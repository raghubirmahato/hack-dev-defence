//! `ux-docs` checks for T-0027 (data visualization and dashboard information design).
//!
//! The task asks for two documents, `docs/UX/DATAVIZ.md` and `docs/UX/metrics-dictionary.md`, and this module is the
//! document linter that holds them to the task text:
//!
//! * T-0027 step 1 and acceptance A1: every analytics screen of the task list (S-040, S-043, S-054, S-065, S-070,
//!   S-071, S-072, S-100, S-127) is a real screen of the spec B12.1 table and has a question, a metric, a dictionary KPI
//!   slug and a widget; the dictionary row for that KPI defines it with a source and a window;
//! * T-0027 step 2: every chart form is one of the forms B11.10 names (line, bar, stacked bar, ranked horizontal bar,
//!   heatmap, choropleth) or one of the text-first B11.8 widgets (StatCard, DataTable), and every row justifies the form;
//! * T-0027 step 3 and A1: the dictionary columns are KPI, definition, unit, aggregation, window, source, type, labels,
//!   refresh cadence and Unknown behaviour; every `MET-` id cited is a metric of the spec B9 catalog and a row that
//!   claims a Prometheus type agrees with the B9 type and does not name a label the metric does not carry;
//! * T-0027 step 4: every table widget has columns, a default sort that names one of its columns, filters and a density;
//! * T-0027 step 5: the time range presets are exactly the six the task names, in order, and the plan-limit paragraph
//!   states the only plan value that bounds a range instead of inventing a limit (Q-008 is OPEN);
//! * T-0027 step 6 and A3: the comparison section defines the previous period, and the annotation list includes mode
//!   changes, rule changes, bans and deployments, each from a real table of the B5 data model and only real `AUD-` events;
//! * T-0027 step 7 and A2: every chart has a text summary and a "View as table" alternative, the chart rules state the
//!   B11.10 global rules (axes with units, zero baseline for bars, user time zone, gaps are gaps, 8 series then "Other",
//!   colour-blind-safe palette with patterns, progressive interaction, server-rendered SVG and print, no animation),
//!   and the colour table has eight patterned series whose hex values are B11.2 tokens when the spec carries B11.2;
//! * T-0027 step 8 and A4: the performance table has numeric thresholds (max points per chart, LTTB downsampling,
//!   render budget, print layout), and a non-numeric value is a finding;
//! * A5: the Unknown table has one row per widget and each display is `Unknown ({reason})` and never zero;
//! * T-0027 notes and R-16: no placeholder or filler value, and no line that mentions interpolation without "never";
//! * F-27 (review round 1): the `## Downsampling` table gives one numeric rule per chart form used in
//!   `Screen questions` - a maximum count, a method and whether the total stays exact. LTTB is the line method only:
//!   bars re-bucket by summing, a ranked bar is top-N plus Other, a heatmap is a fixed 7 x 24 grid, a choropleth keeps
//!   its ranked table, and a stat card or a table aggregates whole rows. A form used without a row, a row whose method
//!   is wrong for its form, or a maximum count without a number is a finding;
//! * F-23 (review round 1): the print row points to `docs/UX/RESPONSIVE.md` for the page margins and states no margin
//!   value of its own; when a value is found in both documents it must be the same value;
//! * F-29 (review round 2): a definition that ranks a key ("the category with ...", "the most ...") returns a label, so
//!   its `Aggregation` must name the argmax or the top list and not `max`. A ranking unit may carry a parenthesised
//!   qualifier such as `category (count in events)`, and `argmax` and `top` are accepted aggregations.
//!
//! Every rule is a separate function whose documentation names the T-0027 step or acceptance item it enforces. The
//! register of the checks lives in [`rules`]. The documents and the specification are plain text, so a malformed or
//! missing input produces a finding, never a panic: the screen, metric and audit readers return empty sets when a
//! specification section is malformed, and the rules then report the missing registry instead of guessing.
//!
//! Limits: the checks are structural. They prove that a question, a metric, a KPI and a widget are present and that the
//! KPI exists in the dictionary; they cannot prove that the chart answers the question well. The justification cell is
//! checked for a citation and a minimum length, not for its reasoning. The colour palette is checked for eight distinct
//! patterns and, when B11.2 is present in the specification, for using only B11.2 hex values.

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

use crate::util::{Finding, read_text};

/// The check name used by every finding.
const CHECK: &str = "ux-docs";

/// The document this module owns.
const DATAVIZ: &str = "docs/UX/DATAVIZ.md";
/// The metrics dictionary this module owns.
const DICTIONARY: &str = "docs/UX/metrics-dictionary.md";

/// The nine analytics screens of T-0027 step 1, in the order the task lists them.
const REQUIRED_SCREENS: [&str; 9] = [
    "S-040", "S-043", "S-054", "S-065", "S-070", "S-071", "S-072", "S-100", "S-127",
];

/// The chart forms B11.10 rule 1 names, plus the two text-first B11.8 forms the task allows.
///
/// `table` is not a chart: it is the DataTable alternative B11.10 rule 5 requires, and a screen may not be answered by
/// the alternative alone (see [`screen_question_findings`]). `stat card` is the B11.8 StatCard.
const ALLOWED_FORMS: [&str; 8] = [
    "line",
    "bar",
    "stacked bar",
    "ranked horizontal bar",
    "heatmap",
    "choropleth",
    "stat card",
    "table",
];

/// The forms that are charts and therefore need a text summary and a "View as table" alternative (A2).
const CHART_FORMS: [&str; 6] = [
    "line",
    "bar",
    "stacked bar",
    "ranked horizontal bar",
    "heatmap",
    "choropleth",
];

/// Forms B11.10 does not select; a form cell naming one of them is a defect rather than a chart.
const DENIED_FORMS: [&str; 9] = [
    "pie", "donut", "area", "radar", "gauge", "scatter", "treemap", "funnel", "bubble",
];

/// The time range presets of T-0027 step 5, in order, with the row name the document must use.
const TIME_PRESETS: [(&str, &str); 6] = [
    ("last 15 minutes", "Last 15 minutes"),
    ("last 1 hour", "Last 1 hour"),
    ("last 24 hours", "Last 24 hours"),
    ("last 7 days", "Last 7 days"),
    ("last 30 days", "Last 30 days"),
    ("custom", "Custom"),
];

/// Aggregations a dictionary row may name. `argmax` and `top` are the label aggregations of a ranking
/// (F-29): a definition that returns "the category with the most ..." must not claim `max`.
const AGGREGATIONS: [&str; 14] = [
    "sum",
    "count",
    "count distinct",
    "average",
    "avg",
    "max",
    "min",
    "percentile",
    "ratio",
    "last",
    "difference",
    "state",
    "argmax",
    "top",
];

/// Value types a dictionary row may name. The first three are the Prometheus types of B9; the rest describe a displayed
/// value that is computed or read from a table.
const VALUE_TYPES: [&str; 7] = [
    "counter",
    "gauge",
    "histogram",
    "derived",
    "rollup",
    "event",
    "state",
];

/// The three Prometheus types, whose meaning must match B9.
const PROM_TYPES: [&str; 3] = ["counter", "gauge", "histogram"];

/// Tables of the spec data model (B5) a metric source may name. Only names that appear in a document are checked
/// against the specification, so a table added later is found by its absence rather than by a missing constant.
const SOURCE_TABLES: [&str; 45] = [
    "rollup_minute",
    "rollup_hour",
    "rollup_day",
    "waf_events",
    "waf_events_ingest",
    "event_aggregates",
    "ip_bans",
    "ban_offences",
    "ban_appeals",
    "campaign_clusters",
    "challenge_stats",
    "certificates",
    "sites",
    "orgs",
    "plans",
    "usage_counters",
    "config_revisions",
    "audit_log",
    "abuse_reports",
    "jobs",
    "job_runs",
    "platform_state",
    "shield_incidents",
    "shield_events",
    "proxy_counter_batches",
    "saved_views",
    "reports",
    "report_runs",
    "access_entries",
    "block_page_settings",
    "alert_rules",
    "integrations",
    "webhooks",
    "webhook_deliveries",
    "mail_outbox",
    "memberships",
    "dns_records",
    "zones",
    "rule_packs",
    "waf_rules",
    "waf_policies",
    "waf_exceptions",
    "auth_endpoints",
    "rate_limit_rules",
    "notifications",
];

/// The annotations T-0027 A3 requires, with the B5 table the marker must come from.
const REQUIRED_ANNOTATIONS: [(&str, &str); 4] = [
    ("mode change", "config_revisions"),
    ("rule change", "config_revisions"),
    ("ban", "ip_bans"),
    ("deployment", "audit_log"),
];

/// The canonical responsive document that defines the print page margins (F-23). T-0024 owns it; this module only
/// points at it and compares a value when both documents happen to state one.
const RESPONSIVE: &str = "docs/UX/RESPONSIVE.md";

/// Sections `docs/UX/DATAVIZ.md` must have. `Downsampling` is the F-27 addition.
const DATAVIZ_SECTIONS: [&str; 12] = [
    "Screen questions",
    "Chart alternatives",
    "Chart rules",
    "Tables",
    "Time range",
    "Comparisons",
    "Annotations",
    "Colour and accessibility",
    "Performance and print",
    "Downsampling",
    "Unknown data",
    "Spec gaps and limits",
];

/// The order a `Chart form` cell is parsed in, longest and most specific first, so `stacked bar` is not read as `bar`
/// and `ranked horizontal bar` is not read as `bar`.
const FORM_PARSE_ORDER: [&str; 8] = [
    "ranked horizontal bar",
    "stacked bar",
    "heatmap",
    "choropleth",
    "stat card",
    "line",
    "bar",
    "table",
];

/// The method words each chart form of `Screen questions` must use in its `## Downsampling` row (F-27). LTTB appears
/// for the line form only; the others aggregate whole rows, so a method that says LTTB for a bar, a heatmap, a
/// choropleth, a stat card, a table or the ranked bar is a finding.
const DOWNSAMPLING_METHODS: [(&str, &[&str]); 8] = [
    ("line", &["lttb"]),
    ("bar", &["re-bucket"]),
    ("stacked bar", &["re-bucket"]),
    ("ranked horizontal bar", &["top-n", "other"]),
    ("heatmap", &["7", "24", "grid"]),
    ("choropleth", &["ranked", "table"]),
    ("stat card", &["whole", "rows"]),
    ("table", &["whole", "rows"]),
];

/// Sections `docs/UX/metrics-dictionary.md` must have.
const DICTIONARY_SECTIONS: [&str; 3] = ["Source legend", "Reading a row", "Metrics"];

/// Placeholder tokens R-01 rejects in either document.
const PLACEHOLDER_TOKENS: [&str; 8] = [
    "TBD",
    "TODO",
    "FIXME",
    "XXX",
    "lorem",
    "dummy",
    "placeholder chart",
    "sample data",
];

/// Build a finding with the check name.
fn finding(location: impl Into<String>, message: impl Into<String>) -> Finding {
    Finding::new(CHECK, location, message)
}

/// True when `needle` occurs in `hay` as a whole token (not preceded or followed by a letter, digit, `_` or `-`).
///
/// Whole-token matching is the rule that keeps `DataTableOfDoom` from satisfying `DataTable` and `MET-x_extra` from
/// satisfying `MET-x` (COLLAB "Lessons from the review rounds" 1).
fn token_in(hay: &str, needle: &str) -> bool {
    if needle.is_empty() {
        return false;
    }
    let hay = hay.to_ascii_lowercase();
    let needle = needle.to_ascii_lowercase();
    let mut start = 0usize;
    while let Some(offset) = hay.get(start..).and_then(|rest| rest.find(&needle)) {
        let at = start.saturating_add(offset);
        let before = hay.get(..at).and_then(|s| s.chars().next_back());
        let end = at.saturating_add(needle.len());
        let after = hay.get(end..).and_then(|s| s.chars().next());
        if !is_token_char(before) && !is_token_char(after) {
            return true;
        }
        start = end.max(at.saturating_add(1));
        if start >= hay.len() {
            break;
        }
    }
    false
}

/// True when a character continues a token for [`token_in`].
fn is_token_char(c: Option<char>) -> bool {
    c.is_some_and(|c| c.is_alphanumeric() || c == '_' || c == '-')
}

/// Case-insensitive substring match, for stems such as `interpolat`.
fn mentions(hay: &str, needle: &str) -> bool {
    hay.to_ascii_lowercase()
        .contains(&needle.to_ascii_lowercase())
}

/// Number of whitespace-separated words in `cell`.
fn word_count(cell: &str) -> usize {
    cell.split_whitespace().count()
}

/// `text` (case-insensitive) split into the cells of a single line, for a keyword group check: true when one line
/// contains every keyword.
fn line_has_all(text: &str, needles: &[&str]) -> bool {
    text.lines()
        .any(|line| needles.iter().all(|needle| mentions(line, needle)))
}

/// The body of the B11.10 section of the specification, or an empty string when the section is absent.
fn b11_10_body(spec: &str) -> String {
    section_text(spec, "B11.10")
}

/// Text of a specification subsection by heading id (`## B9.`, `### B11.10`, ...). The master mixes level-2 and
/// level-3 headings, so this reads the same way [`super::spec_section`] does and joins the lines.
fn section_text(spec: &str, heading: &str) -> String {
    super::spec_section(spec, heading)
        .iter()
        .map(|(_, line)| *line)
        .collect::<Vec<_>>()
        .join("\n")
}

/// The forms of [`ALLOWED_FORMS`] that the specification actually names: B11.10 rule 1 for the chart forms, B11.8 for
/// StatCard and DataTable. Findings for a form the specification lacks are reported here so the rule cannot silently
/// accept a form that came from nowhere.
fn allowed_forms(spec: &str) -> (BTreeSet<String>, Vec<String>) {
    let b11_10 = b11_10_body(spec);
    let b11_8 = section_text(spec, "B11.8");
    let mut allowed = BTreeSet::new();
    let mut missing = Vec::new();
    for form in ALLOWED_FORMS {
        let found = match form {
            "stat card" => token_in(&b11_8, "StatCard"),
            "table" => token_in(&b11_8, "DataTable"),
            _ => token_in(&b11_10, form),
        };
        if found {
            allowed.insert(form.to_owned());
        } else {
            missing.push(form.to_owned());
        }
    }
    (allowed, missing)
}

/// A metric of the spec B9 catalog: its Prometheus type and its bounded labels.
struct Metric {
    kind: String,
    labels: BTreeSet<String>,
}

/// Metrics of the spec B9 catalog, keyed by `MET-` id. Slash shorthand rows (`MET-x_issued_total / solved_total`) are
/// expanded at the last `_` segment; a row whose alternative cannot be placed that way keeps only its first id.
fn b9_metrics(spec: &str) -> BTreeMap<String, Metric> {
    let mut out = BTreeMap::new();
    for (_, line) in super::spec_section(spec, "B9.") {
        let Some(row) = super::cells(line) else {
            continue;
        };
        let Some(first) = row.first() else {
            continue;
        };
        let Some(kind) = row.get(1) else {
            continue;
        };
        let kind = kind.trim().to_ascii_lowercase();
        if !PROM_TYPES.contains(&kind.as_str()) {
            continue;
        }
        let labels: BTreeSet<String> = row
            .get(2)
            .map(|cell| {
                cell.split(',')
                    .map(|label| label.trim().to_ascii_lowercase())
                    .filter(|label| !label.is_empty() && label != "-" && label != "—")
                    .collect()
            })
            .unwrap_or_default();
        let ids = metric_tokens(first);
        for (index, id) in ids.iter().enumerate() {
            out.insert(
                id.clone(),
                Metric {
                    kind: kind.clone(),
                    labels: labels.clone(),
                },
            );
            if index == 0 {
                continue;
            }
            // The alternative is a suffix such as `solved_total`; replace the last segment of the first id.
            let Some(base) = ids.first() else { continue };
            let Some(stem) = base.rfind('_').map(|at| base.get(..at).unwrap_or(base)) else {
                continue;
            };
            out.insert(
                format!("{stem}_{id}"),
                Metric {
                    kind: kind.clone(),
                    labels: labels.clone(),
                },
            );
        }
    }
    out
}

/// `MET-` ids in `text`, in order, matched as whole tokens.
fn metric_tokens(text: &str) -> Vec<String> {
    prefixed_tokens(text, "MET-")
}

/// `AUD-` ids in `text`, in order, matched as whole tokens.
fn audit_tokens(text: &str) -> Vec<String> {
    prefixed_tokens(text, "AUD-")
}

/// Tokens that start with `prefix` and continue with id characters (`[A-Za-z0-9_.]`), whole token on both sides.
fn prefixed_tokens(text: &str, prefix: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut start = 0usize;
    while let Some(offset) = text.get(start..).and_then(|rest| rest.find(prefix)) {
        let at = start.saturating_add(offset);
        let before = text.get(..at).and_then(|s| s.chars().next_back());
        if !is_token_char(before) {
            let tail = text.get(at..).unwrap_or("");
            let token: String = tail
                .chars()
                .take_while(|c| c.is_ascii_alphanumeric() || *c == '_' || *c == '.' || *c == '-')
                .collect();
            let length = token.len();
            if length > prefix.len() {
                out.push(token);
            }
            start = at.saturating_add(length.max(1));
        } else {
            start = at.saturating_add(prefix.len());
        }
        if start >= text.len() {
            break;
        }
    }
    out
}

/// `#rrggbb` values in `text`, lower-cased.
fn hex_values(text: &str) -> Vec<String> {
    let mut out = Vec::new();
    for (index, _) in text.match_indices('#') {
        let tail = text.get(index..).unwrap_or("");
        let candidate: String = tail.chars().take(7).collect();
        let bytes = candidate.as_bytes();
        if bytes.len() == 7 && bytes.iter().skip(1).all(|b| b.is_ascii_hexdigit()) {
            out.push(candidate.to_ascii_lowercase());
        }
    }
    out
}

/// KPI slugs of the dictionary `## Metrics` table, for the screen-to-dictionary cross-check.
fn kpi_names(dictionary: &str) -> BTreeSet<String> {
    let mut out = BTreeSet::new();
    if let Some((header, rows)) = super::section_table(dictionary, "Metrics")
        && let Some(index) = super::column(&header, "KPI")
    {
        for (_, row) in rows {
            if let Some(cell) = row.get(index)
                && !cell.trim().is_empty()
            {
                out.insert(cell.trim().to_owned());
            }
        }
    }
    out
}

/// Skinny cell access: `row.get(index).map(str::trim).unwrap_or("")`.
fn cell(row: &[String], index: usize) -> &str {
    row.get(index).map(|value| value.trim()).unwrap_or("")
}

/// Every rule of the module, so a unit test can run the whole document check without a file system. `responsive` is the
/// text of `docs/UX/RESPONSIVE.md` when it can be read, for the F-23 margin comparison.
fn rules(dataviz: &str, dictionary: &str, spec: &str, responsive: Option<&str>) -> Vec<Finding> {
    let kpis = kpi_names(dictionary);
    let mut out = Vec::new();
    out.extend(document_findings(dataviz, dictionary));
    out.extend(screen_question_findings(dataviz, spec, &kpis));
    out.extend(chart_form_findings(dataviz, spec));
    out.extend(chart_alternative_findings(dataviz));
    out.extend(chart_rule_findings(dataviz));
    out.extend(table_spec_findings(dataviz));
    out.extend(time_range_findings(dataviz));
    out.extend(comparison_findings(dataviz));
    out.extend(annotation_findings(dataviz, spec));
    out.extend(colour_findings(dataviz, spec));
    out.extend(performance_findings(dataviz));
    out.extend(downsampling_findings(dataviz));
    out.extend(print_alignment_findings(dataviz, responsive));
    out.extend(unknown_findings(dataviz));
    out.extend(spec_gap_findings(dataviz));
    out.extend(dictionary_findings(dictionary));
    out.extend(top_aggregation_findings(dictionary));
    out.extend(metric_id_findings(dataviz, dictionary, spec));
    out.extend(metric_type_label_findings(dictionary, spec));
    out.extend(placeholder_findings(dataviz, dictionary));
    out
}

/// Whole T-0027 check on the repository at `root`, reading the checksum-verified master specification.
pub fn check(root: &Path) -> Vec<Finding> {
    match crate::spec::load_master(root) {
        Ok(spec) => check_with_spec(root, &spec),
        Err(e) => vec![super::finding(
            "docs/SPEC.md",
            format!("cannot read the master specification: {}", e.0),
        )],
    }
}

/// Whole T-0027 check on the repository at `root`, with the master specification text.
pub fn check_with_spec(root: &Path, spec: &str) -> Vec<Finding> {
    let mut out = Vec::new();
    let dataviz = read_text(&root.join(DATAVIZ));
    let dictionary = read_text(&root.join(DICTIONARY));
    let responsive = read_text(&root.join(RESPONSIVE)).ok();
    match (&dataviz, &dictionary) {
        (Ok(dataviz), Ok(dictionary)) => {
            out.extend(rules(dataviz, dictionary, spec, responsive.as_deref()))
        }
        _ => {
            if dataviz.is_err() {
                out.push(finding(DATAVIZ, "the document does not exist (T-0027)"));
            }
            if dictionary.is_err() {
                out.push(finding(DICTIONARY, "the document does not exist (T-0027)"));
            }
        }
    }
    out
}

// ------------------------------------------------------------------------------------------------ rules

/// T-0027 steps 1 and 8, A1 and A5: both documents exist, carry their required sections, are UTF-8 without a byte-order
/// mark and contain no mojibake sequence.
pub(crate) fn document_findings(dataviz: &str, dictionary: &str) -> Vec<Finding> {
    let mut out = Vec::new();
    for title in DATAVIZ_SECTIONS {
        if super::section_body(dataviz, title).is_none() {
            out.push(finding(
                DATAVIZ,
                format!("the required `## {title}` section is missing (T-0027)"),
            ));
        }
    }
    for title in DICTIONARY_SECTIONS {
        if super::section_body(dictionary, title).is_none() {
            out.push(finding(
                DICTIONARY,
                format!("the required `## {title}` section is missing (T-0027)"),
            ));
        }
    }
    for (location, text) in [(DATAVIZ, dataviz), (DICTIONARY, dictionary)] {
        if text.trim().is_empty() {
            out.push(finding(location, "the document is empty (T-0027)"));
            continue;
        }
        if text.starts_with('\u{feff}') {
            out.push(finding(
                location,
                "the file starts with a byte-order mark; it must be UTF-8 without a BOM",
            ));
        }
        out.extend(super::mojibake_findings(location, text));
    }
    out
}

/// T-0027 step 1 and A1: every required analytics screen is a real B12.1 screen and has a question, a metric, a
/// dictionary KPI and a widget, and every required screen has at least one visual (a chart or a stat card).
pub(crate) fn screen_question_findings(
    dataviz: &str,
    spec: &str,
    kpis: &BTreeSet<String>,
) -> Vec<Finding> {
    let mut out = Vec::new();
    let screens = super::screen_ids(spec);
    if screens.is_empty() {
        out.push(finding(
            "docs/SPEC.md",
            "the B12.1 screen table has no screen rows, so the analytics screens cannot be checked",
        ));
        return out;
    }
    if kpis.is_empty() {
        out.push(finding(
            DICTIONARY,
            "the metrics dictionary has no KPI rows, so the screen questions cannot be cross-checked",
        ));
        return out;
    }
    let Some((header, rows)) = super::section_table(dataviz, "Screen questions") else {
        out.push(finding(
            DATAVIZ,
            "no `## Screen questions` section with a table",
        ));
        return out;
    };
    let screen_index = super::column(&header, "Screen");
    let question_index = super::column(&header, "Question");
    let metric_index = super::column(&header, "Metric");
    let kpi_index = super::column(&header, "KPI");
    let form_index = super::column(&header, "Chart form");
    let widget_index = super::column(&header, "Widget");
    for (name, index) in [
        ("Screen", &screen_index),
        ("Question", &question_index),
        ("Metric", &metric_index),
        ("KPI", &kpi_index),
        ("Chart form", &form_index),
        ("Widget", &widget_index),
    ] {
        if index.is_none() {
            out.push(finding(
                DATAVIZ,
                format!("the table has no `{name}` column"),
            ));
        }
    }
    let (
        Some(screen_index),
        Some(question_index),
        Some(metric_index),
        Some(kpi_index),
        Some(form_index),
        Some(widget_index),
    ) = (
        screen_index,
        question_index,
        metric_index,
        kpi_index,
        form_index,
        widget_index,
    )
    else {
        return out;
    };
    let mut seen: BTreeSet<String> = BTreeSet::new();
    let mut visual: BTreeSet<String> = BTreeSet::new();
    let mut used_kpis: BTreeSet<String> = BTreeSet::new();
    for (n, row) in &rows {
        let at = format!("{DATAVIZ}:{n}");
        let screen = cell(row, screen_index).to_owned();
        let question = cell(row, question_index);
        let metric = cell(row, metric_index);
        let kpi_cell = cell(row, kpi_index);
        let form = cell(row, form_index);
        let widget = cell(row, widget_index);
        if !REQUIRED_SCREENS.contains(&screen.as_str()) {
            if screens.contains(&screen) {
                out.push(finding(
                    &at,
                    format!("`{screen}` is not one of the nine analytics screens of T-0027 step 1"),
                ));
            } else {
                out.push(finding(
                    &at,
                    format!("`{screen}` is not a screen of the spec B12.1 screen table"),
                ));
            }
            continue;
        }
        seen.insert(screen.clone());
        if CHART_FORMS.iter().any(|chart| token_in(form, chart)) || token_in(form, "stat card") {
            visual.insert(screen.clone());
        }
        if question.is_empty() || !question.ends_with('?') {
            out.push(finding(
                &at,
                format!("the question for {screen} must be a question and end with `?`"),
            ));
        }
        if word_count(metric) < 3 {
            out.push(finding(
                &at,
                format!("the Metric cell for {screen} is empty or too short to name a metric"),
            ));
        }
        if widget.is_empty() {
            out.push(finding(
                &at,
                format!("the Widget cell for {screen} is empty"),
            ));
        }
        for kpi in kpi_cell.split(',').map(str::trim).filter(|k| !k.is_empty()) {
            used_kpis.insert(kpi.to_owned());
            if !kpis.contains(kpi) {
                out.push(finding(
                    &at,
                    format!("`{kpi}` is not a KPI row of docs/UX/metrics-dictionary.md (A1)"),
                ));
            }
        }
    }
    for screen in REQUIRED_SCREENS {
        if !seen.contains(screen) {
            out.push(finding(
                DATAVIZ,
                format!("{screen} does not appear in the screen questions table (T-0027 step 1)"),
            ));
        } else if !visual.contains(screen) {
            out.push(finding(
                DATAVIZ,
                format!("{screen} has no visual question: every screen needs a chart or stat card, not only the table alternative"),
            ));
        }
    }
    for kpi in kpis {
        if !used_kpis.contains(kpi) {
            out.push(finding(
                DICTIONARY,
                format!(
                    "the dictionary row `{kpi}` is used by no screen question row (T-0027 step 1)"
                ),
            ));
        }
    }
    out
}

/// T-0027 step 2: every chart form is one of the B11.10 forms (or the two B11.8 text-first forms), no form is one
/// B11.10 does not select, and every row justifies its form with a citation.
pub(crate) fn chart_form_findings(dataviz: &str, spec: &str) -> Vec<Finding> {
    let mut out = Vec::new();
    let (allowed, missing) = allowed_forms(spec);
    for form in &missing {
        out.push(finding(
            "docs/SPEC.md",
            format!("the specification does not name the chart form `{form}`, so it cannot be allowed (B11.10, B11.8)"),
        ));
    }
    if allowed.is_empty() {
        return out;
    }
    let Some((header, rows)) = super::section_table(dataviz, "Screen questions") else {
        out.push(finding(
            DATAVIZ,
            "no `## Screen questions` section with a table",
        ));
        return out;
    };
    let Some(form_index) = super::column(&header, "Chart form") else {
        out.push(finding(
            DATAVIZ,
            "the screen questions table has no `Chart form` column",
        ));
        return out;
    };
    let Some(justify_index) = super::column(&header, "Justification") else {
        out.push(finding(
            DATAVIZ,
            "the screen questions table has no `Justification` column",
        ));
        return out;
    };
    for (n, row) in &rows {
        let at = format!("{DATAVIZ}:{n}");
        let form = cell(row, form_index);
        let justification = cell(row, justify_index);
        if form.is_empty() {
            out.push(finding(&at, "the Chart form cell is empty (T-0027 step 2)"));
            continue;
        }
        let denied: Vec<&str> = DENIED_FORMS
            .iter()
            .copied()
            .filter(|denied| token_in(form, denied))
            .collect();
        for denied in denied {
            out.push(finding(
                &at,
                format!("`{denied}` is not a form B11.10 selects; the allowed forms are line, bar, stacked bar, ranked horizontal bar, heatmap, choropleth, stat card and table"),
            ));
        }
        if !allowed.iter().any(|form_name| token_in(form, form_name)) {
            out.push(finding(
                &at,
                format!(
                    "`{form}` is not a chart form of B11.10 or one of the B11.8 text-first forms"
                ),
            ));
        }
        let is_chart = CHART_FORMS.iter().any(|chart| token_in(form, chart));
        let rule = if is_chart { "B11.10" } else { "B11.8" };
        if word_count(justification) < 6 || !mentions(justification, rule) {
            out.push(finding(
                &at,
                format!("the Justification cell for `{form}` must explain the choice in at least six words and cite {rule} (T-0027 step 2)"),
            ));
        }
    }
    out
}

/// T-0027 step 7 and A2: every chart widget has a text summary, a "View as table" alternative and a CSV export, and no
/// alternative row is orphaned.
pub(crate) fn chart_alternative_findings(dataviz: &str) -> Vec<Finding> {
    let mut out = Vec::new();
    let chart_widgets = chart_widgets(dataviz);
    let Some((header, rows)) = super::section_table(dataviz, "Chart alternatives") else {
        out.push(finding(
            DATAVIZ,
            "no `## Chart alternatives` section with a table (A2)",
        ));
        return out;
    };
    let widget_index = super::column(&header, "Widget");
    let summary_index = super::column(&header, "Text summary");
    let table_index = super::column(&header, "View as table");
    let csv_index = super::column(&header, "CSV export");
    for (name, index) in [
        ("Widget", &widget_index),
        ("Text summary", &summary_index),
        ("View as table", &table_index),
        ("CSV export", &csv_index),
    ] {
        if index.is_none() {
            out.push(finding(
                DATAVIZ,
                format!("the table has no `{name}` column"),
            ));
        }
    }
    let (Some(widget_index), Some(summary_index), Some(table_index), Some(csv_index)) =
        (widget_index, summary_index, table_index, csv_index)
    else {
        return out;
    };
    let mut found: BTreeSet<String> = BTreeSet::new();
    for (n, row) in &rows {
        let at = format!("{DATAVIZ}:{n}");
        let widget = cell(row, widget_index).to_owned();
        let summary = cell(row, summary_index);
        let table = cell(row, table_index);
        let csv = cell(row, csv_index);
        if widget.is_empty() {
            out.push(finding(&at, "a chart alternatives row has no Widget"));
            continue;
        }
        found.insert(widget.clone());
        if word_count(summary) < 6 || !summary.contains('{') || !summary.contains('}') {
            out.push(finding(
                &at,
                format!("the chart `{widget}` has no text summary template: it needs at least six words and a {{placeholder}} (A2)"),
            ));
        }
        if !mentions(table, "view as table") {
            out.push(finding(
                &at,
                format!("the chart `{widget}` has no `View as table` alternative (A2)"),
            ));
        }
        if !mentions(csv, "csv") {
            out.push(finding(
                &at,
                format!("the chart `{widget}` has no CSV export (T-0442 step 6)"),
            ));
        }
    }
    for widget in &chart_widgets {
        if !found.contains(widget) {
            out.push(finding(
                DATAVIZ,
                format!("the chart `{widget}` has no row in `## Chart alternatives` (A2)"),
            ));
        }
    }
    for widget in &found {
        if !chart_widgets.contains(widget) {
            out.push(finding(
                DATAVIZ,
                format!("the chart alternatives row `{widget}` is not used by any screen question"),
            ));
        }
    }
    out
}

/// Widgets whose `Chart form` cell is one of [`CHART_FORMS`], in document order.
fn chart_widgets(dataviz: &str) -> BTreeSet<String> {
    let mut out = BTreeSet::new();
    let Some((header, rows)) = super::section_table(dataviz, "Screen questions") else {
        return out;
    };
    let (Some(form_index), Some(widget_index)) = (
        super::column(&header, "Chart form"),
        super::column(&header, "Widget"),
    ) else {
        return out;
    };
    for (_, row) in &rows {
        let form = cell(row, form_index);
        if CHART_FORMS.iter().any(|chart| token_in(form, chart)) {
            let widget = cell(row, widget_index);
            if !widget.is_empty() {
                out.insert(widget.to_owned());
            }
        }
    }
    out
}

/// Every widget named by a screen question row (charts, stat cards and tables).
fn all_widgets(dataviz: &str) -> BTreeSet<String> {
    let mut out = BTreeSet::new();
    let Some((header, rows)) = super::section_table(dataviz, "Screen questions") else {
        return out;
    };
    let Some(widget_index) = super::column(&header, "Widget") else {
        return out;
    };
    for (_, row) in &rows {
        let widget = cell(row, widget_index);
        if !widget.is_empty() {
            out.insert(widget.to_owned());
        }
    }
    out
}

/// Widgets whose `Chart form` is `table`.
fn table_widgets(dataviz: &str) -> BTreeSet<String> {
    let mut out = BTreeSet::new();
    let Some((header, rows)) = super::section_table(dataviz, "Screen questions") else {
        return out;
    };
    let (Some(form_index), Some(widget_index)) = (
        super::column(&header, "Chart form"),
        super::column(&header, "Widget"),
    ) else {
        return out;
    };
    for (_, row) in &rows {
        if token_in(cell(row, form_index), "table") {
            let widget = cell(row, widget_index);
            if !widget.is_empty() {
                out.insert(widget.to_owned());
            }
        }
    }
    out
}

/// T-0027 step 7 and the B11.10 global rules: axes and units, zero baseline, user time zone, gaps are gaps, at most 8
/// series then "Other", colour-blind-safe palette with patterns, progressive interaction, server-rendered SVG and print,
/// no animation, no fabricated or interpolated data, and forced-colors support.
pub(crate) fn chart_rule_findings(dataviz: &str) -> Vec<Finding> {
    let mut out = Vec::new();
    let Some(body) = super::section_body(dataviz, "Chart rules") else {
        out.push(finding(
            DATAVIZ,
            "no `## Chart rules` section (T-0027 step 7)",
        ));
        return out;
    };
    let text = body
        .iter()
        .map(|(_, line)| line.as_str())
        .collect::<Vec<_>>()
        .join("\n");
    let groups: [(&str, &[&str]); 11] = [
        (
            "axes with units, a zero baseline for bars and the user time zone",
            &["axes", "units", "zero baseline", "time zone"],
        ),
        (
            "that a gap is drawn as a gap and never interpolated as zero",
            &["gap", "never", "interpolat"],
        ),
        (
            "direct labels, the 8-series cap and Other",
            &["direct label", "8 series", "other"],
        ),
        (
            "the colour-blind-safe palette with a pattern per series",
            &["colour-blind", "b11.2", "pattern"],
        ),
        (
            "a text summary and a View as table toggle for every chart",
            &["text summary", "view as table"],
        ),
        (
            "progressive interaction: tooltips enhance and nothing depends on them",
            &["progressive", "tooltip", "without"],
        ),
        (
            "server-rendered SVG, JavaScript-free rendering and clean print",
            &["server-rendered", "javascript", "print"],
        ),
        ("no animation by default", &["animation", "default"]),
        (
            "that fabricated or interpolated data is never charted",
            &["never", "fabricated", "interpolat"],
        ),
        (
            "the forced-colors rule",
            &["forced-colors", "system colours"],
        ),
        (
            "that no encoding is colour alone",
            &["colour alone", "no encoding"],
        ),
    ];
    for (label, needles) in groups {
        if !line_has_all(&text, needles) {
            out.push(finding(
                DATAVIZ,
                format!("the chart rules do not state {label} (B11.10)"),
            ));
        }
    }
    for (n, line) in dataviz.lines().enumerate() {
        if mentions(line, "interpolat") && !mentions(line, "never") {
            out.push(finding(
                format!("{DATAVIZ}:{}", n + 1),
                "the line mentions interpolation without `never`: a chart never interpolates data (T-0027 notes, R-16)",
            ));
        }
    }
    out
}

/// T-0027 step 4: every table widget has columns, a default sort naming a column, filters and a density.
pub(crate) fn table_spec_findings(dataviz: &str) -> Vec<Finding> {
    let mut out = Vec::new();
    let required = table_widgets(dataviz);
    let Some((header, rows)) = super::section_table(dataviz, "Tables") else {
        out.push(finding(
            DATAVIZ,
            "no `## Tables` section with a table (T-0027 step 4)",
        ));
        return out;
    };
    let (
        Some(screen_index),
        Some(table_index),
        Some(columns_index),
        Some(sort_index),
        Some(filters_index),
        Some(density_index),
    ) = (
        super::column(&header, "Screen"),
        super::column(&header, "Table"),
        super::column(&header, "Columns"),
        super::column(&header, "Default sort"),
        super::column(&header, "Filters"),
        super::column(&header, "Density"),
    )
    else {
        out.push(finding(
            DATAVIZ,
            "the tables section needs the Screen, Table, Columns, Default sort, Filters and Density columns (T-0027 step 4)",
        ));
        return out;
    };
    let mut seen: BTreeSet<String> = BTreeSet::new();
    for (n, row) in &rows {
        let at = format!("{DATAVIZ}:{n}");
        let screen = cell(row, screen_index).to_owned();
        let table = cell(row, table_index).to_owned();
        let columns_cell = cell(row, columns_index);
        let sort = cell(row, sort_index);
        let filters = cell(row, filters_index);
        let density = cell(row, density_index).to_ascii_lowercase();
        if !REQUIRED_SCREENS.contains(&screen.as_str()) {
            out.push(finding(
                &at,
                format!("`{screen}` is not one of the nine analytics screens of T-0027 step 1"),
            ));
        }
        if table.is_empty() {
            out.push(finding(&at, "a tables row has no Table name"));
            continue;
        }
        seen.insert(table.clone());
        let columns: Vec<&str> = columns_cell
            .split(',')
            .map(str::trim)
            .filter(|column| !column.is_empty())
            .collect();
        if columns.len() < 3 {
            out.push(finding(
                &at,
                format!("the table `{table}` lists fewer than three columns (T-0027 step 4)"),
            ));
        }
        if !columns.iter().any(|column| token_in(sort, column)) {
            out.push(finding(
                &at,
                format!("the default sort `{sort}` of `{table}` does not name one of its columns"),
            ));
        }
        if word_count(filters) < 1 {
            out.push(finding(&at, format!("the table `{table}` has no filters")));
        }
        if density != "comfortable" && density != "compact" {
            out.push(finding(
                &at,
                format!(
                    "the density of `{table}` must be `comfortable` or `compact` (B11.8 DataTable)"
                ),
            ));
        }
    }
    for widget in &required {
        if !seen.contains(widget) {
            out.push(finding(
                DATAVIZ,
                format!("no `## Tables` row for the table widget `{widget}` (T-0027 step 4)"),
            ));
        }
    }
    for table in &seen {
        if !required.contains(table) {
            out.push(finding(
                DATAVIZ,
                format!("the tables row `{table}` is not a table widget of any screen question"),
            ));
        }
    }
    out
}

/// T-0027 step 5: the six presets exactly, in order, and the plan-limit paragraph names the real plan value and the
/// open question instead of inventing a limit.
pub(crate) fn time_range_findings(dataviz: &str) -> Vec<Finding> {
    let mut out = Vec::new();
    let Some((header, rows)) = super::section_table(dataviz, "Time range") else {
        out.push(finding(
            DATAVIZ,
            "no `## Time range` section with a table (T-0027 step 5)",
        ));
        return out;
    };
    let Some(preset_index) = super::column(&header, "Preset") else {
        out.push(finding(
            DATAVIZ,
            "the time range table has no `Preset` column",
        ));
        return out;
    };
    let Some(granularity_index) = super::column(&header, "Granularity") else {
        out.push(finding(
            DATAVIZ,
            "the time range table has no `Granularity` column",
        ));
        return out;
    };
    if rows.len() != TIME_PRESETS.len() {
        out.push(finding(
            DATAVIZ,
            format!(
                "the time range presets must be exactly the six of T-0027 step 5 (found {} rows)",
                rows.len()
            ),
        ));
    }
    for (index, (_, expected)) in TIME_PRESETS.iter().enumerate() {
        match rows.get(index) {
            Some((_, row)) => {
                let preset = cell(row, preset_index);
                if !preset.eq_ignore_ascii_case(expected) {
                    out.push(finding(
                        DATAVIZ,
                        format!(
                            "the preset at position {} must be `{expected}`, not `{preset}`",
                            index + 1
                        ),
                    ));
                }
                let granularity = cell(row, granularity_index).to_ascii_lowercase();
                if !["minute", "hour", "day", "auto"]
                    .iter()
                    .any(|value| token_in(&granularity, value))
                {
                    out.push(finding(
                        DATAVIZ,
                        format!("the preset `{preset}` has no valid granularity (minute, hour, day or auto)"),
                    ));
                }
            }
            None => out.push(finding(
                DATAVIZ,
                format!("the preset `{expected}` is missing (T-0027 step 5)"),
            )),
        }
    }
    let Some(body) = super::section_body(dataviz, "Time range") else {
        return out;
    };
    let text = body
        .iter()
        .map(|(_, line)| line.as_str())
        .collect::<Vec<_>>()
        .join("\n");
    if !line_has_all(&text, &["events_retention_days", "q-008", "per-plan"]) {
        out.push(finding(
            DATAVIZ,
            "the time range section must name `plans.limits.events_retention_days`, the open question Q-008 and the per-plan limit rule instead of inventing a limit",
        ));
    }
    out
}

/// T-0027 step 6: the previous period is defined with the same buckets in the same time zone, the comparison toggle is
/// named, and an unknown previous window produces Unknown rather than a number.
pub(crate) fn comparison_findings(dataviz: &str) -> Vec<Finding> {
    let mut out = Vec::new();
    let Some(body) = super::section_body(dataviz, "Comparisons") else {
        out.push(finding(
            DATAVIZ,
            "no `## Comparisons` section (T-0027 step 6)",
        ));
        return out;
    };
    let text = body
        .iter()
        .map(|(_, line)| line.as_str())
        .collect::<Vec<_>>()
        .join("\n");
    if !line_has_all(&text, &["previous period", "same", "bucket", "time zone"]) {
        out.push(finding(
            DATAVIZ,
            "the comparison section does not define the previous period as the same buckets in the same time zone (T-0027 step 6)",
        ));
    }
    if !token_in(&text, "toggle") {
        out.push(finding(
            DATAVIZ,
            "the comparison section does not name the comparison toggle",
        ));
    }
    if !line_has_all(&text, &["unknown", "previous"]) {
        out.push(finding(
            DATAVIZ,
            "the comparison section does not define what is shown when the previous window is unknown or has a gap",
        ));
    }
    out
}

/// T-0027 step 6 and A3: mode changes, rule changes, bans and deployments are annotated from the real data model and
/// only real B8 audit events are cited.
pub(crate) fn annotation_findings(dataviz: &str, spec: &str) -> Vec<Finding> {
    let mut out = Vec::new();
    let audits = super::audit_ids(spec);
    if audits.is_empty() {
        out.push(finding(
            "docs/SPEC.md",
            "the B8 audit event taxonomy has no rows, so annotation sources cannot be checked",
        ));
    }
    for (n, line) in dataviz.lines().enumerate() {
        for id in audit_tokens(line) {
            if !audits.is_empty() && !audits.contains(&id) {
                out.push(finding(
                    format!("{DATAVIZ}:{}", n + 1),
                    format!("`{id}` is not an event of the spec B8 audit taxonomy"),
                ));
            }
        }
    }
    let Some((header, rows)) = super::section_table(dataviz, "Annotations") else {
        out.push(finding(
            DATAVIZ,
            "no `## Annotations` section with a table (A3)",
        ));
        return out;
    };
    let (Some(annotation_index), Some(source_index), Some(marker_index), Some(text_index)) = (
        super::column(&header, "Annotation"),
        super::column(&header, "Source"),
        super::column(&header, "Marker"),
        super::column(&header, "Text alternative"),
    ) else {
        out.push(finding(
            DATAVIZ,
            "the annotations table needs the Annotation, Source, Marker and Text alternative columns (A3)",
        ));
        return out;
    };
    for (kind, source) in REQUIRED_ANNOTATIONS {
        let mut found = false;
        for (n, row) in &rows {
            let annotation = cell(row, annotation_index);
            if !token_in(annotation, kind) {
                continue;
            }
            found = true;
            let at = format!("{DATAVIZ}:{n}");
            let source_cell = cell(row, source_index);
            if !token_in(source_cell, source) {
                out.push(finding(
                    &at,
                    format!("the {kind} annotation must come from `{source}` (T-0027 step 6)"),
                ));
            }
            if cell(row, marker_index).is_empty() {
                out.push(finding(&at, format!("the {kind} annotation has no marker")));
            }
            let text = cell(row, text_index);
            if !text.contains('{') || !text.contains('}') {
                out.push(finding(
                    &at,
                    format!("the {kind} annotation has no text alternative template"),
                ));
            }
        }
        if !found {
            out.push(finding(
                DATAVIZ,
                format!("the annotation list is missing `{kind}` (T-0027 A3)"),
            ));
        }
    }
    out
}

/// T-0027 step 7: eight patterned chart series, a colour-blind-safe B11.2 palette, the forced-colors rule and no
/// colour-only encoding.
pub(crate) fn colour_findings(dataviz: &str, spec: &str) -> Vec<Finding> {
    let mut out = Vec::new();
    let Some((header, rows)) = super::section_table(dataviz, "Colour and accessibility") else {
        out.push(finding(
            DATAVIZ,
            "no `## Colour and accessibility` section with a palette table (T-0027 step 7)",
        ));
        return out;
    };
    let (Some(series_index), Some(dark_index), Some(light_index), Some(pattern_index)) = (
        super::column(&header, "Series"),
        super::column(&header, "Dark"),
        super::column(&header, "Light"),
        super::column(&header, "Pattern"),
    ) else {
        out.push(finding(
            DATAVIZ,
            "the palette table needs the Series, Dark, Light and Pattern columns (T-0027 step 7)",
        ));
        return out;
    };
    let b11_2 = section_text(spec, "B11.2");
    let palette = hex_values(&b11_2);
    let mut patterns: BTreeSet<String> = BTreeSet::new();
    if rows.len() != 8 {
        out.push(finding(
            DATAVIZ,
            format!(
                "the palette must have eight chart series (found {})",
                rows.len()
            ),
        ));
    }
    for (n, row) in &rows {
        let at = format!("{DATAVIZ}:{n}");
        let series = cell(row, series_index);
        if !series.is_empty() && !(1..=8).any(|number| series == number.to_string()) {
            out.push(finding(
                &at,
                format!("`{series}` is not a series number from 1 to 8"),
            ));
        }
        let pattern = cell(row, pattern_index);
        if pattern.is_empty() {
            out.push(finding(&at, format!("series {series} has no pattern")));
        } else {
            patterns.insert(pattern.to_ascii_lowercase());
        }
        for index in [dark_index, light_index] {
            for hex in hex_values(cell(row, index)) {
                if !palette.is_empty() && !palette.contains(&hex) {
                    out.push(finding(
                        &at,
                        format!("`{hex}` is not a colour token of B11.2"),
                    ));
                }
            }
        }
    }
    if patterns.len() < 8 {
        out.push(finding(
            DATAVIZ,
            "the eight chart series must have eight distinct patterns (B11.10 rule 4)",
        ));
    }
    let Some(body) = super::section_body(dataviz, "Colour and accessibility") else {
        return out;
    };
    let text = body
        .iter()
        .map(|(_, line)| line.as_str())
        .collect::<Vec<_>>()
        .join("\n");
    for (label, needles) in [
        (
            "the colour-blind-safe B11.2 palette",
            &["colour-blind", "b11.2"][..],
        ),
        (
            "the forced-colors rule with system colours",
            &["forced-colors", "system colours"][..],
        ),
        (
            "that no encoding is colour alone",
            &["colour alone", "no encoding"][..],
        ),
        (
            "the text summary and View as table alternatives",
            &["text summary", "view as table"][..],
        ),
    ] {
        if !line_has_all(&text, needles) {
            out.push(finding(
                DATAVIZ,
                format!("the colour section does not state {label} (T-0027 step 7)"),
            ));
        }
    }
    out
}

/// T-0027 step 8 and A4: numeric thresholds for points per chart, LTTB downsampling, the render budget and the print
/// layout, and the LTTB rule.
pub(crate) fn performance_findings(dataviz: &str) -> Vec<Finding> {
    let mut out = Vec::new();
    let Some((header, rows)) = super::section_table(dataviz, "Performance and print") else {
        out.push(finding(
            DATAVIZ,
            "no `## Performance and print` section with a table (T-0027 step 8)",
        ));
        return out;
    };
    let (Some(constraint_index), Some(value_index), Some(rule_index)) = (
        super::column(&header, "Constraint"),
        super::column(&header, "Value"),
        super::column(&header, "Rule"),
    ) else {
        out.push(finding(
            DATAVIZ,
            "the performance table needs the Constraint, Value and Rule columns (T-0027 step 8)",
        ));
        return out;
    };
    if rows.len() < 5 {
        out.push(finding(
            DATAVIZ,
            "the performance table has fewer than five numeric constraints (T-0027 A4)",
        ));
    }
    let forbidden = ["many", "some", "varies", "tbd", "todo", "depending"];
    let mut constraints: BTreeSet<String> = BTreeSet::new();
    for (n, row) in &rows {
        let at = format!("{DATAVIZ}:{n}");
        let constraint = cell(row, constraint_index).to_ascii_lowercase();
        let value = cell(row, value_index);
        let rule = cell(row, rule_index);
        constraints.insert(constraint.clone());
        if value.is_empty()
            || !value.chars().any(|c| c.is_ascii_digit())
            || forbidden.iter().any(|word| token_in(value, word))
        {
            out.push(finding(
                &at,
                format!("the value `{value}` is not numeric (T-0027 A4)"),
            ));
        }
        if word_count(rule) < 5 {
            out.push(finding(
                &at,
                format!("the constraint `{constraint}` has no rule"),
            ));
        }
    }
    for required in ["points per chart", "downsampling", "render", "print"] {
        if !constraints
            .iter()
            .any(|constraint| mentions(constraint, required))
        {
            out.push(finding(
                DATAVIZ,
                format!("the performance table has no `{required}` constraint (T-0027 A4)"),
            ));
        }
    }
    let Some(body) = super::section_body(dataviz, "Performance and print") else {
        return out;
    };
    let text = body
        .iter()
        .map(|(_, line)| line.as_str())
        .collect::<Vec<_>>()
        .join("\n");
    if !mentions(&text, "lttb") {
        out.push(finding(
            DATAVIZ,
            "the performance section does not name the LTTB downsampling rule (T-0088 step 6)",
        ));
    }
    if !line_has_all(&text, &["lttb", "never", "gap"]) {
        out.push(finding(
            DATAVIZ,
            "the performance section does not state that LTTB never bridges a gap",
        ));
    }
    out
}

/// The chart form a `Chart form` cell names, as spelled in [`FORM_PARSE_ORDER`]; `None` when it names no form.
///
/// The order matters: `ranked horizontal bar` and `stacked bar` are matched before `bar`, and `table` is matched last, so
/// a cell is read as one form instead of as every form whose name it contains.
fn form_of(text: &str) -> Option<&'static str> {
    FORM_PARSE_ORDER
        .iter()
        .copied()
        .find(|form| token_in(text, form))
}

/// The chart forms the `Screen questions` table uses, deduplicated.
fn forms_used(dataviz: &str) -> BTreeSet<String> {
    let mut out = BTreeSet::new();
    let Some((header, rows)) = super::section_table(dataviz, "Screen questions") else {
        return out;
    };
    let Some(form_index) = super::column(&header, "Chart form") else {
        return out;
    };
    for (_, row) in &rows {
        if let Some(form) = form_of(cell(row, form_index)) {
            out.insert(form.to_owned());
        }
    }
    out
}

/// F-27: one numeric downsampling rule per chart form used in `Screen questions`, with a method that fits the form and a
/// statement that the total stays exact.
///
/// LTTB is the line-series method only (T-0088 step 6); a bar, a heatmap, a choropleth, a stat card or a table reduced
/// by LTTB is a finding. Bars re-bucket by summing, the ranked bar is top-N plus Other, the heatmap is a fixed 7 x 24
/// grid, the choropleth keeps its ranked table and the two text-first forms use whole rows, which is why their totals
/// stay exact. A form used in `Screen questions` without a row here is a finding, so a new chart form cannot ship
/// without a downsampling rule (T-0027 step 8 and A4).
pub(crate) fn downsampling_findings(dataviz: &str) -> Vec<Finding> {
    let mut out = Vec::new();
    let used = forms_used(dataviz);
    if used.is_empty() {
        out.push(finding(
            DATAVIZ,
            "the screen questions table names no chart form, so no downsampling rule can be checked (F-27)",
        ));
        return out;
    }
    let Some((header, rows)) = super::section_table(dataviz, "Downsampling") else {
        out.push(finding(
            DATAVIZ,
            "no `## Downsampling` section with a table (T-0027 A4, F-27)",
        ));
        return out;
    };
    let (Some(form_index), Some(count_index), Some(method_index), Some(exact_index)) = (
        super::column(&header, "Chart form"),
        super::column(&header, "Maximum count"),
        super::column(&header, "Method"),
        super::column(&header, "Totals exact"),
    ) else {
        out.push(finding(
            DATAVIZ,
            "the downsampling table needs the Chart form, Maximum count, Method and Totals exact columns (F-27)",
        ));
        return out;
    };
    let vague = [
        "many",
        "some",
        "varies",
        "several",
        "tbd",
        "todo",
        "depending",
        "unlimited",
    ];
    let mut seen: BTreeSet<String> = BTreeSet::new();
    for (n, row) in &rows {
        let at = format!("{DATAVIZ}:{n}");
        let form_cell = cell(row, form_index);
        let Some(form) = form_of(form_cell) else {
            out.push(finding(
                &at,
                format!("`{form_cell}` is not a chart form of B11.10 or one of the two B11.8 text-first forms"),
            ));
            continue;
        };
        if !seen.insert(form.to_owned()) {
            out.push(finding(
                &at,
                format!("the chart form `{form}` has more than one downsampling row (F-27)"),
            ));
        }
        let maximum = cell(row, count_index);
        if !maximum.chars().any(|c| c.is_ascii_digit())
            || vague.iter().any(|word| token_in(maximum, word))
        {
            out.push(finding(
                &at,
                format!(
                    "the maximum count `{maximum}` of `{form}` is not a number (T-0027 A4, F-27)"
                ),
            ));
        }
        let method = cell(row, method_index);
        if word_count(method) < 4 {
            out.push(finding(
                &at,
                format!("the method of `{form}` is empty or too short to name a downsampling method (F-27)"),
            ));
        }
        if form != "line" && token_in(method, "lttb") {
            out.push(finding(
                &at,
                format!("`{form}` names LTTB, but LTTB is the line-series method only; the other forms aggregate whole rows (F-27)"),
            ));
        }
        if let Some((_, needles)) = DOWNSAMPLING_METHODS.iter().find(|(name, _)| *name == form) {
            for needle in *needles {
                if !token_in(method, needle) {
                    out.push(finding(
                        &at,
                        format!("the method of `{form}` does not state `{needle}` (F-27)"),
                    ));
                }
            }
        }
        let exact = cell(row, exact_index).to_ascii_lowercase();
        if !token_in(&exact, "yes") && !token_in(&exact, "exact") {
            out.push(finding(
                &at,
                format!("the `Totals exact` cell of `{form}` must say `Yes` or `exact` (F-27)"),
            ));
        }
        if ["no", "changes", "approximate"]
            .iter()
            .any(|word| token_in(&exact, word))
        {
            out.push(finding(
                &at,
                format!("the `Totals exact` cell of `{form}` says the total changes; downsampling never changes a total (T-0442 A1, F-27)"),
            ));
        }
    }
    for form in &used {
        if !seen.contains(form) {
            out.push(finding(
                DATAVIZ,
                format!("the chart form `{form}` is used in `Screen questions` but has no downsampling row (T-0027 A4, F-27)"),
            ));
        }
    }
    for form in &seen {
        if !used.contains(form) {
            out.push(finding(
                DATAVIZ,
                format!("the downsampling row `{form}` is for a form that no screen question uses"),
            ));
        }
    }
    out
}

/// The print-margin values in `text`: each `<number> mm` written immediately before the word `margin` or `margins`, so a
/// page dimension or a header band in the same sentence is not read as a margin.
fn margin_values(text: &str) -> Vec<String> {
    let mut out = Vec::new();
    let lower = text.to_ascii_lowercase();
    let mut start = 0usize;
    while let Some(offset) = lower.get(start..).and_then(|rest| rest.find("margin")) {
        let at = start.saturating_add(offset);
        let before = lower.get(..at).and_then(|s| s.chars().next_back());
        let after = lower
            .get(at.saturating_add(6)..)
            .and_then(|s| s.chars().next());
        let after_ok = match after {
            None => true,
            Some('s') => lower
                .get(at.saturating_add(7)..)
                .and_then(|s| s.chars().next())
                .is_none_or(|c| !is_token_char(Some(c))),
            Some(c) => !is_token_char(Some(c)),
        };
        if !is_token_char(before) && after_ok {
            let prefix = lower.get(..at).unwrap_or("").trim_end();
            if let Some(number) = prefix.strip_suffix("mm") {
                let number = number.trim_end();
                let mut tail = String::new();
                for c in number.chars().rev() {
                    if c.is_ascii_digit() || c == '.' || c == ',' {
                        tail.push(c);
                    } else {
                        break;
                    }
                }
                let digits: String = tail.chars().rev().collect();
                let boundary = number
                    .get(..number.len().saturating_sub(digits.len()))
                    .and_then(|s| s.chars().next_back())
                    .is_none_or(|c| !is_token_char(Some(c)));
                if !digits.is_empty() && boundary {
                    out.push(format!("{digits} mm"));
                }
            }
        }
        start = at.saturating_add(6);
    }
    out
}

/// F-23: the print row points to `docs/UX/RESPONSIVE.md` for the page margins and states no margin value of its own;
/// when both documents state one, the values must be equal (one rule, stated in one document).
pub(crate) fn print_alignment_findings(dataviz: &str, responsive: Option<&str>) -> Vec<Finding> {
    let mut out = Vec::new();
    let Some(body) = super::section_body(dataviz, "Performance and print") else {
        return out;
    };
    let text = body
        .iter()
        .map(|(_, line)| line.as_str())
        .collect::<Vec<_>>()
        .join("\n");
    if !mentions(&text, "RESPONSIVE.md") {
        out.push(finding(
            DATAVIZ,
            "the print layout does not point to docs/UX/RESPONSIVE.md for the page margins (F-23)",
        ));
    }
    let own = margin_values(&text);
    for value in &own {
        out.push(finding(
            DATAVIZ,
            format!(
                "the print layout states its own margin `{value}`; the value belongs to docs/UX/RESPONSIVE.md (F-23)"
            ),
        ));
    }
    if own.is_empty() {
        return out;
    }
    let Some(responsive) = responsive else {
        return out;
    };
    let canonical = margin_values(responsive);
    let Some(canonical) = canonical.first() else {
        out.push(finding(
            DATAVIZ,
            "docs/UX/RESPONSIVE.md states no print margin value, so the print layout has no canonical value to point to (F-23)",
        ));
        return out;
    };
    for value in &own {
        if value.replace(' ', "") != canonical.replace(' ', "") {
            out.push(finding(
                DATAVIZ,
                format!(
                    "the print margin `{value}` differs from `{canonical}` in docs/UX/RESPONSIVE.md; one value, stated in one document (F-23)"
                ),
            ));
        }
    }
    out
}

/// T-0027 A5: one Unknown row per widget, each display `Unknown ({reason})` and never zero, and the gap rule.
pub(crate) fn unknown_findings(dataviz: &str) -> Vec<Finding> {
    let mut out = Vec::new();
    let widgets = all_widgets(dataviz);
    let Some((header, rows)) = super::section_table(dataviz, "Unknown data") else {
        out.push(finding(
            DATAVIZ,
            "no `## Unknown data` section with a table (A5)",
        ));
        return out;
    };
    let (Some(widget_index), Some(when_index), Some(display_index), Some(never_index)) = (
        super::column(&header, "Widget"),
        super::column(&header, "When it is unknown"),
        super::column(&header, "Display"),
        super::column(&header, "Never"),
    ) else {
        out.push(finding(
            DATAVIZ,
            "the Unknown table needs the Widget, When it is unknown, Display and Never columns (A5)",
        ));
        return out;
    };
    let mut found: BTreeSet<String> = BTreeSet::new();
    for (n, row) in &rows {
        let at = format!("{DATAVIZ}:{n}");
        let widget = cell(row, widget_index).to_owned();
        if widget.is_empty() {
            out.push(finding(&at, "an Unknown row has no Widget"));
            continue;
        }
        found.insert(widget.clone());
        if word_count(cell(row, when_index)) < 4 {
            out.push(finding(
                &at,
                format!("the widget `{widget}` does not say when it is unknown (A5)"),
            ));
        }
        let display = cell(row, display_index);
        if !mentions(display, "unknown (") || !mentions(display, "{reason}") {
            out.push(finding(
                &at,
                format!("the display of `{widget}` must be `Unknown ({{reason}})` (A5)"),
            ));
        }
        if !token_in(cell(row, never_index), "zero") {
            out.push(finding(
                &at,
                format!(
                    "the widget `{widget}` does not state that the missing value is never zero (A5)"
                ),
            ));
        }
    }
    for widget in &widgets {
        if !found.contains(widget) {
            out.push(finding(
                DATAVIZ,
                format!("no Unknown row for the widget `{widget}` (A5)"),
            ));
        }
    }
    for widget in &found {
        if !widgets.contains(widget) {
            out.push(finding(
                DATAVIZ,
                format!("the Unknown row `{widget}` is not used by any screen question"),
            ));
        }
    }
    let Some(body) = super::section_body(dataviz, "Unknown data") else {
        return out;
    };
    let text = body
        .iter()
        .map(|(_, line)| line.as_str())
        .collect::<Vec<_>>()
        .join("\n");
    if !line_has_all(&text, &["gap", "never", "fabricated"]) {
        out.push(finding(
            DATAVIZ,
            "the Unknown section does not state that a gap is never filled with a fabricated value (R-16)",
        ));
    }
    out
}

/// T-0027 notes and R-16: the document states its known specification gaps and limits with real references.
pub(crate) fn spec_gap_findings(dataviz: &str) -> Vec<Finding> {
    let mut out = Vec::new();
    let Some((header, rows)) = super::section_table(dataviz, "Spec gaps and limits") else {
        out.push(finding(
            DATAVIZ,
            "no `## Spec gaps and limits` section with a table (T-0027 notes)",
        ));
        return out;
    };
    let (Some(gap_index), Some(effect_index), Some(handling_index)) = (
        super::column(&header, "Gap"),
        super::column(&header, "Effect"),
        super::column(&header, "Handling"),
    ) else {
        out.push(finding(
            DATAVIZ,
            "the spec gaps table needs the Gap, Effect and Handling columns (T-0027 notes)",
        ));
        return out;
    };
    if rows.len() < 4 {
        out.push(finding(
            DATAVIZ,
            format!(
                "the spec gaps table has fewer than four rows (found {})",
                rows.len()
            ),
        ));
    }
    let references = [
        "b5.", "b6.", "b8", "b9", "b11.", "b12.", "t-0", "q-0", "met-", "s-0", "c11.",
    ];
    for (n, row) in &rows {
        let at = format!("{DATAVIZ}:{n}");
        let gap = cell(row, gap_index);
        if !references.iter().any(|reference| mentions(gap, reference)) {
            out.push(finding(
                &at,
                format!("`{gap}` cites no specification section or id, so it is not a known gap"),
            ));
        }
        for (index, name) in [(effect_index, "Effect"), (handling_index, "Handling")] {
            if word_count(cell(row, index)) < 2 {
                out.push(finding(&at, format!("the {name} cell is empty")));
            }
        }
    }
    out
}

/// T-0027 step 3 and A1: the dictionary columns exist and every row has a definition, unit, aggregation, window, source,
/// Prometheus-or-derived type, refresh cadence and Unknown behaviour.
pub(crate) fn dictionary_findings(dictionary: &str) -> Vec<Finding> {
    let mut out = Vec::new();
    let Some((header, rows)) = super::section_table(dictionary, "Metrics") else {
        out.push(finding(
            DICTIONARY,
            "no `## Metrics` section with a table (T-0027 step 3)",
        ));
        return out;
    };
    let mut indexes = BTreeMap::new();
    for name in [
        "KPI",
        "Definition",
        "Unit",
        "Aggregation",
        "Window",
        "Source",
        "Type",
        "Labels",
        "Refresh",
        "Unknown",
    ] {
        match super::column(&header, name) {
            Some(index) => {
                indexes.insert(name, index);
            }
            None => out.push(finding(
                DICTIONARY,
                format!("the metrics table has no `{name}` column (T-0027 step 3)"),
            )),
        }
    }
    if indexes.len() != 10 {
        return out;
    }
    let mut names: BTreeSet<String> = BTreeSet::new();
    for (n, row) in &rows {
        let get = |name: &str| -> &str {
            indexes
                .get(name)
                .map(|index| cell(row, *index))
                .unwrap_or("")
        };
        let kpi = get("KPI");
        if kpi.is_empty() {
            out.push(finding(
                format!("{DICTIONARY}:{n}"),
                "a metrics row has no KPI name",
            ));
            continue;
        }
        let at = format!("{DICTIONARY}:{n}");
        if !names.insert(kpi.to_owned()) {
            out.push(finding(
                &at,
                format!("the KPI `{kpi}` appears more than once"),
            ));
        }
        let definition = get("Definition");
        let kind = get("Type").to_ascii_lowercase();
        if word_count(definition) < 8 {
            out.push(finding(
                &at,
                format!("{kpi}: the Definition is shorter than eight words (A1)"),
            ));
        }
        if kind == "derived"
            && !["/", "divided", "minus", "difference", "ratio"]
                .iter()
                .any(|marker| mentions(definition, marker))
        {
            out.push(finding(
                &at,
                format!("{kpi}: the derived KPI does not state its formula in the Definition (A1)"),
            ));
        }
        // A unit may carry a parenthesised qualifier (F-29: `category (count in events)`); only an
        // unqualified unit longer than three words is rejected.
        let unit = get("Unit");
        let unit_words = word_count(unit);
        let parenthetical = unit.contains('(') && unit.contains(')');
        if unit.is_empty() || (unit_words > 3 && !(parenthetical && unit_words <= 6)) {
            out.push(finding(
                &at,
                format!("{kpi}: the Unit is empty or not a unit"),
            ));
        }
        let aggregation = get("Aggregation").to_ascii_lowercase();
        if !AGGREGATIONS
            .iter()
            .any(|allowed| token_in(&aggregation, allowed))
        {
            out.push(finding(
                &at,
                format!("{kpi}: the Aggregation `{}` is not one of sum, count, count distinct, average, max, min, percentile, ratio, last, difference, state, argmax or top", get("Aggregation")),
            ));
        }
        let window = get("Window");
        if window.is_empty()
            || (!window.chars().any(|c| c.is_ascii_digit())
                && ![
                    "current",
                    "live",
                    "picker",
                    "build",
                    "release",
                    "contract",
                    "probe",
                    "run",
                    "last",
                    "retention",
                ]
                .iter()
                .any(|token| token_in(window, token)))
        {
            out.push(finding(
                &at,
                format!("{kpi}: the Window is empty or names no time range (A1)"),
            ));
        }
        if word_count(get("Source")) < 2 && metric_tokens(get("Source")).is_empty() {
            out.push(finding(
                &at,
                format!("{kpi}: the Source is empty or too short to name a source (A1)"),
            ));
        }
        if !VALUE_TYPES.contains(&kind.as_str()) {
            out.push(finding(
                &at,
                format!("{kpi}: the Type `{}` is not one of counter, gauge, histogram, derived, rollup, event or state", get("Type")),
            ));
        }
        if get("Labels").is_empty() {
            out.push(finding(
                &at,
                format!("{kpi}: the Labels cell is empty (use - for none)"),
            ));
        }
        let refresh = get("Refresh");
        if refresh.is_empty()
            || (!refresh.chars().any(|c| c.is_ascii_digit())
                && ![
                    "live",
                    "scrape",
                    "write",
                    "change",
                    "run",
                    "poll",
                    "job",
                    "request",
                    "reload",
                    "watermark",
                    "input",
                    "refresh",
                ]
                .iter()
                .any(|token| mentions(refresh, token)))
        {
            out.push(finding(
                &at,
                format!("{kpi}: the Refresh cadence is empty or not a cadence (T-0027 step 3)"),
            ));
        }
        let unknown = get("Unknown");
        if word_count(unknown) < 3 || !mentions(unknown, "unknown (") {
            out.push(finding(
                &at,
                format!("{kpi}: the Unknown behaviour must start with `Unknown (reason)` (A5)"),
            ));
        }
    }
    out
}

/// F-29 (review round 2): a dictionary row whose definition ranks a key ("the category with ...",
/// "the most ...") returns a label, so its `Aggregation` must name the argmax or the top list. `max`
/// names one extreme value, not the winning category or key.
pub(crate) fn top_aggregation_findings(dictionary: &str) -> Vec<Finding> {
    let mut out = Vec::new();
    // A missing Metrics table, Definition column or Aggregation column is reported by
    // `dictionary_findings`; this rule only reads a table that is complete enough to read.
    let Some((header, rows)) = super::section_table(dictionary, "Metrics") else {
        return out;
    };
    let (Some(definition_index), Some(aggregation_index)) = (
        super::column(&header, "Definition"),
        super::column(&header, "Aggregation"),
    ) else {
        return out;
    };
    for (n, row) in &rows {
        let definition = cell(row, definition_index);
        let ranks = token_in(definition, "the category with") || token_in(definition, "the most");
        if !ranks {
            continue;
        }
        let aggregation = cell(row, aggregation_index);
        let label_aggregation = token_in(aggregation, "argmax")
            || token_in(aggregation, "top")
            || token_in(aggregation, "top-n");
        if label_aggregation {
            continue;
        }
        out.push(finding(
            format!("{DICTIONARY}:{n}"),
            format!(
                "the definition ranks a key (`the category with ...` or `the most ...`) but the Aggregation `{aggregation}` is not an argmax or a top list (F-29)"
            ),
        ));
    }
    out
}

/// T-0027 step 3: every `MET-` id cited exists in B9, every `AUD-` id exists in B8, every source table exists in the
/// data model, and every `docs/....md` source path is named by the specification.
pub(crate) fn metric_id_findings(dataviz: &str, dictionary: &str, spec: &str) -> Vec<Finding> {
    let mut out = Vec::new();
    let metrics = b9_metrics(spec);
    if metrics.is_empty() {
        out.push(finding(
            "docs/SPEC.md",
            "the B9 metrics catalog has no rows, so `MET-` ids cannot be checked",
        ));
    }
    let audits = super::audit_ids(spec);
    if audits.is_empty() {
        out.push(finding(
            "docs/SPEC.md",
            "the B8 audit event taxonomy has no rows, so `AUD-` ids cannot be checked",
        ));
    }
    for (location, text) in [(DATAVIZ, dataviz), (DICTIONARY, dictionary)] {
        let mut reported: BTreeSet<String> = BTreeSet::new();
        for id in metric_tokens(text) {
            if !metrics.is_empty() && !metrics.contains_key(&id) && reported.insert(id.clone()) {
                out.push(finding(
                    location,
                    format!("`{id}` is not a metric of the spec B9 metrics catalog"),
                ));
            }
        }
        let mut reported: BTreeSet<String> = BTreeSet::new();
        for id in audit_tokens(text) {
            if !audits.is_empty() && !audits.contains(&id) && reported.insert(id.clone()) {
                out.push(finding(
                    location,
                    format!("`{id}` is not an event of the spec B8 audit taxonomy"),
                ));
            }
        }
    }
    if let Some((header, rows)) = super::section_table(dictionary, "Metrics") {
        let (Some(definition_index), Some(source_index)) = (
            super::column(&header, "Definition"),
            super::column(&header, "Source"),
        ) else {
            return out;
        };
        let kpi_index = super::column(&header, "KPI").unwrap_or(0);
        for (n, row) in &rows {
            let at = format!("{DICTIONARY}:{n}");
            let kpi = cell(row, kpi_index);
            for index in [definition_index, source_index] {
                let value = cell(row, index);
                for table in SOURCE_TABLES {
                    if token_in(value, table) && !token_in(spec, table) {
                        out.push(finding(
                            &at,
                            format!("{kpi}: the source table `{table}` is not in the specification data model (T-0027 step 3)"),
                        ));
                    }
                }
                let mut seen: BTreeSet<String> = BTreeSet::new();
                for path in doc_paths(value) {
                    if seen.insert(path.clone()) && !token_in(spec, &path) {
                        out.push(finding(
                            &at,
                            format!(
                                "{kpi}: the source path `{path}` is not named by the specification"
                            ),
                        ));
                    }
                }
            }
        }
    }
    out
}

/// `docs/...md` paths in a cell.
fn doc_paths(text: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut start = 0usize;
    while let Some(offset) = text.get(start..).and_then(|rest| rest.find("docs/")) {
        let at = start.saturating_add(offset);
        let tail = text.get(at..).unwrap_or("");
        let path: String = tail
            .chars()
            .take_while(|c| !c.is_whitespace() && *c != ')' && *c != '`' && *c != ',')
            .collect();
        let length = path.len();
        if path.ends_with(".md") {
            out.push(path);
        }
        start = at.saturating_add(length.max(1));
        if start >= text.len() {
            break;
        }
    }
    out
}

/// T-0027 step 3: a row that claims a Prometheus type agrees with the B9 type and does not name a label the metric does
/// not carry.
pub(crate) fn metric_type_label_findings(dictionary: &str, spec: &str) -> Vec<Finding> {
    let mut out = Vec::new();
    let metrics = b9_metrics(spec);
    if metrics.is_empty() {
        return out;
    }
    let Some((header, rows)) = super::section_table(dictionary, "Metrics") else {
        return out;
    };
    let (Some(kpi_index), Some(source_index), Some(type_index), Some(labels_index)) = (
        super::column(&header, "KPI"),
        super::column(&header, "Source"),
        super::column(&header, "Type"),
        super::column(&header, "Labels"),
    ) else {
        return out;
    };
    for (n, row) in &rows {
        let at = format!("{DICTIONARY}:{n}");
        let kpi = cell(row, kpi_index);
        let ids = metric_tokens(cell(row, source_index));
        let kind = cell(row, type_index).to_ascii_lowercase();
        if ids.len() != 1 || !PROM_TYPES.contains(&kind.as_str()) {
            continue;
        }
        let Some(id) = ids.first() else { continue };
        let Some(metric) = metrics.get(id) else {
            continue;
        };
        if kind != metric.kind {
            out.push(finding(
                &at,
                format!(
                    "{kpi}: `{id}` is a {} in B9 but the row says {kind}",
                    metric.kind
                ),
            ));
        }
        for label in cell(row, labels_index)
            .split(',')
            .map(str::trim)
            .filter(|label| !label.is_empty() && *label != "-" && *label != "—")
        {
            let label = label.to_ascii_lowercase();
            if !metric.labels.contains(&label) {
                out.push(finding(
                    &at,
                    format!("{kpi}: `{label}` is not a label of `{id}` in B9"),
                ));
            }
        }
    }
    out
}

/// R-01 and R-16: no placeholder token and no row made only of filler cells.
pub(crate) fn placeholder_findings(dataviz: &str, dictionary: &str) -> Vec<Finding> {
    let mut out = Vec::new();
    for (location, text) in [(DATAVIZ, dataviz), (DICTIONARY, dictionary)] {
        for token in PLACEHOLDER_TOKENS {
            if token_in(text, token) {
                out.push(finding(
                    location,
                    format!("`{token}` is a placeholder token (R-01)"),
                ));
            }
        }
        for (n, line) in text.lines().enumerate() {
            let Some(row) = super::cells(line) else {
                continue;
            };
            let separator = row
                .iter()
                .all(|cell| !cell.is_empty() && cell.chars().all(|c| c == '-' || c == ':'))
                && row.iter().any(|cell| cell.len() >= 3);
            if separator || row.len() < 2 {
                continue;
            }
            let filler = |value: &str| {
                let value = value.trim();
                value.is_empty() || value == "-" || value == "—"
            };
            let first = row.first().map(|value| value.as_str()).unwrap_or("");
            let rest = row.iter().skip(1);
            let non_filler = rest.filter(|value| !filler(value)).count();
            if !first.is_empty() && !filler(first) && non_filler == 0 {
                out.push(finding(
                    format!("{location}:{}", n + 1),
                    format!("the row `{first}` is made only of filler cells (R-01)"),
                ));
            }
        }
    }
    out
}

#[cfg(test)]
pub(crate) mod fixtures {
    //! Fixture tree for the Lead's `ux_docs/tests.rs`: two documents that satisfy every rule against a minimal
    //! specification, and the specification rows the fixture spec does not already carry.

    /// The fixture data visualization document path.
    pub(crate) const DATAVIZ: &str = "docs/UX/DATAVIZ.md";
    /// The fixture metrics dictionary path.
    pub(crate) const DICTIONARY: &str = "docs/UX/metrics-dictionary.md";

    /// The two fixture documents as `(repository-relative path, text)`, for the fixture tree.
    pub(crate) fn documents() -> Vec<(String, String)> {
        vec![
            (DATAVIZ.to_owned(), dataviz()),
            (DICTIONARY.to_owned(), dictionary()),
        ]
    }

    /// The fixture responsive document, for the F-23 print-margin comparison. The shipped `docs/UX/RESPONSIVE.md` is
    /// owned by T-0024; this string only stands in for it in the unit tests, and it is never written to the repository.
    pub(crate) fn responsive_fixture() -> String {
        String::from(
            "# Responsive and device strategy (fixture)\n\n\
             ## Printing and PDF\n\n\
             Page setup: A4 portrait at 210 x 297 mm, with 12 mm margins on every edge, a 10 mm header band and a\n\
             10 mm footer band. Navigation is hidden in print.\n",
        )
    }

    /// The specification rows the fixture spec lacks: a B9 metrics table, the B11.10 numbered rules in the master's
    /// shape, and the B5 data-model rows the source check reads. Append it to the fixture specification.
    pub(crate) fn spec_section() -> String {
        String::from(
            r#"## B9. Metrics catalog (fixture rows)

| Metric | Type | Labels | Meaning |
| --- | --- | --- | --- |
| MET-hdd_proxy_requests_total | counter | surface, site, status_class, mode | Requests handled |
| MET-hdd_waf_blocks_total | counter | category, vector | Blocked requests |
| MET-hdd_waf_would_block_total | counter | category | Would-block requests in monitor and log modes |
| MET-hdd_bans_active | gauge | scope | Active bans |
| MET-hdd_shield_state | gauge | | 0 normal, 1 elevated, 2 attack, 3 saturated |
| MET-hdd_origin_health | gauge | site | 1 healthy, 0 unhealthy |
| MET-hdd_mail_sent_total | counter | template | Mail sent (shared fixture row for the T-0026 measures rule) |

### B11.10 Data visualization rules

1. Choose the simplest form that answers the question: line for time series, bar for category comparison, stacked bar for composition over time, ranked horizontal bar for top-N, heatmap for hour-by-day, choropleth only with a ranked table alongside.
2. Axes labeled with units; zero baseline for bars; time axis in user time zone; gaps shown as gaps, not interpolated zeros.
3. Direct labels over legends where feasible; legend order matches visual order; limit to 8 series (then "Other").
4. Color-blind-safe palette (B11.2) plus patterns for fills; severity uses icon + label.
5. Every chart has a text summary ("Blocked requests peaked at 14:10 with 412") and a "View as table" toggle.
6. Interaction is progressive: tooltips and crosshair enhance; all information is available without them.
7. Charts are server-rendered SVG so they render without JavaScript and print cleanly; no animation by default.
8. Never chart fabricated or interpolated data; sparse data shows the sparse state.

### B5.8 Analytics and reporting (fixture rows)

| Table | Key columns |
| --- | --- |
| `rollup_minute`, `rollup_hour`, `rollup_day` | org_id, site_id, bucket, dimension, key, requests, blocked, bytes_out, p50_ms, p95_ms, p99_ms |
| `waf_events` | ray_id, ts, site_id, category, action, rule_id, country, asn |
| `ip_bans` | id, site_id, ip_key, reason, created_at, expires_at, released_at |
| `ban_appeals` | id, site_id, ray_id, status |
| `campaign_clusters` | id, site_id, distinct_ips, status |
| `certificates` | id, site_id, not_after, status |
| `sites` | id, org_id, waf_mode, readiness_cache |
| `config_revisions` | id, site_id, revision, status |
| `audit_log` | id, ts, event, target_id |
| `webhook_deliveries` | id, webhook_id, status, created_at |
| `shield_incidents`, `shield_events` | id, state, ts |
| `abuse_reports` | id, status |
| `jobs`, `job_runs` | id, kind, status, started_at |
| `platform_state` | key, value |
"#,
        )
    }

    /// The screen questions of the fixture: screen, question, metric, KPI slugs, form, widget, justification.
    const QUESTIONS: [(&str, &str, &str, &str, &str, &str, &str); 14] = [
        (
            "S-040",
            "How much traffic did the organisation receive?",
            "Requests and blocked requests over 24 hours",
            "requests, blocked",
            "line",
            "traffic-24h",
            "Time series: line is the simplest form for a change over time (B11.10 rule 1).",
        ),
        (
            "S-040",
            "Which items need attention now?",
            "Open attention items",
            "attention-open",
            "table",
            "attention-list",
            "A heterogeneous list with actions: the DataTable is the text-first form (B11.8).",
        ),
        (
            "S-043",
            "Is this domain's traffic normal?",
            "Requests and blocked over 24 hours",
            "requests, blocked",
            "line",
            "traffic-24h",
            "Time series: the line shows a trend over time (B11.10 rule 1).",
        ),
        (
            "S-043",
            "What share of the traffic was blocked?",
            "Block rate over the range",
            "block-rate",
            "stat card",
            "stat-card",
            "One ratio with a delta: StatCard (B11.8).",
        ),
        (
            "S-054",
            "Which categories are attacked?",
            "Blocked requests by category",
            "blocked-by-category",
            "ranked horizontal bar",
            "top-categories",
            "A top-N ranking reads its labels directly (B11.10 rule 1).",
        ),
        (
            "S-054",
            "When during the week do attacks cluster?",
            "Blocked requests by local hour and weekday",
            "attack-heatmap",
            "heatmap",
            "attack-heatmap",
            "An hour-by-day pattern is the heatmap of B11.10 rule 1.",
        ),
        (
            "S-065",
            "What is happening right now?",
            "Events and blocked events per minute",
            "live-events-per-min, live-blocked-per-min",
            "stat card",
            "stat-card",
            "Two current rates with units: StatCard (B11.8).",
        ),
        (
            "S-065",
            "Which events should I inspect?",
            "The newest notable events",
            "live-rows",
            "table",
            "live-table",
            "Row detail and actions: a DataTable, not a chart (B11.8).",
        ),
        (
            "S-065",
            "Which attack category is busiest right now?",
            "The category with the most events in the last five minutes",
            "live-top-category",
            "stat card",
            "stat-card",
            "One ranked label and its count: StatCard (B11.8).",
        ),
        (
            "S-070",
            "Which status classes dominate?",
            "Requests by status class over the range",
            "status-classes",
            "stacked bar",
            "status-stacked",
            "Composition over time is the stacked bar (B11.10 rule 1).",
        ),
        (
            "S-071",
            "Where does traffic come from?",
            "Requests by country",
            "geo-requests",
            "choropleth",
            "geo-choropleth",
            "A map with a ranked table alongside (B11.10 rule 1).",
        ),
        (
            "S-072",
            "How did the attack evolve by category?",
            "Blocked requests by category over the range",
            "blocked-by-category",
            "line",
            "attack-timeline",
            "Time series grouped by category (B11.10 rule 1).",
        ),
        (
            "S-100",
            "What is the current attack summary?",
            "Top categories and ASNs in the last hour",
            "admin-attack-summary",
            "ranked horizontal bar",
            "admin-attack-summary",
            "A top-N ranking of two dimensions (B11.10 rule 1).",
        ),
        (
            "S-127",
            "What state is the shield in?",
            "The shield state",
            "shield-state",
            "stat card",
            "stat-card",
            "One current state with a text label: StatCard (B11.8).",
        ),
    ];

    /// The chart alternatives of the fixture: widget, text summary, table alternative.
    const ALTERNATIVES: [(&str, &str); 7] = [
        (
            "traffic-24h",
            "Requests peaked at {peak_time} with {peak_value}; {blocked} were blocked.",
        ),
        (
            "top-categories",
            "The largest category was {category} with {blocked} blocked requests.",
        ),
        (
            "status-stacked",
            "Status class {class} held {share} of the requests in the range.",
        ),
        (
            "geo-choropleth",
            "The highest country was {country} with {requests} requests.",
        ),
        (
            "attack-timeline",
            "Blocked requests peaked at {peak_time} with {blocked} in category {category}.",
        ),
        (
            "attack-heatmap",
            "The busiest cell was {weekday} at {hour} with {blocked} blocked requests.",
        ),
        (
            "admin-attack-summary",
            "The top category was {category} with {blocked} blocked requests from {asn}.",
        ),
    ];

    /// Every widget of the fixture, with its form, for the Unknown table.
    const WIDGETS: [(&str, &str); 10] = [
        ("traffic-24h", "line"),
        ("attention-list", "table"),
        ("stat-card", "stat card"),
        ("top-categories", "ranked horizontal bar"),
        ("attack-heatmap", "heatmap"),
        ("live-table", "table"),
        ("status-stacked", "stacked bar"),
        ("geo-choropleth", "choropleth"),
        ("attack-timeline", "line"),
        ("admin-attack-summary", "ranked horizontal bar"),
    ];

    /// The fixture data visualization document.
    fn dataviz() -> String {
        let mut text = String::from(
            "# Data visualization (fixture)\n\n\
             A fixture document for the T-0027 unit tests; it is not shipped and describes no real deployment.\n\n\
             ## Screen questions\n\n\
             | Screen | Question | Metric | KPI | Chart form | Widget | Justification |\n\
             | --- | --- | --- | --- | --- | --- | --- |\n",
        );
        for (screen, question, metric, kpi, form, widget, justification) in QUESTIONS {
            text.push_str(&format!(
                "| {screen} | {question} | {metric} | {kpi} | {form} | {widget} | {justification} |\n"
            ));
        }
        text.push_str(
            "\n## Chart alternatives\n\n\
             | Widget | Text summary | View as table | CSV export |\n| --- | --- | --- | --- |\n",
        );
        for (widget, summary) in ALTERNATIVES {
            text.push_str(&format!(
                "| {widget} | {summary} | View as table (bucket ascending, compact density) | CSV export of the displayed series |\n"
            ));
        }
        text.push_str(
            "\n## Chart rules\n\n\
             1. Line, bar, stacked bar, ranked horizontal bar, heatmap and choropleth are the forms of B11.10 rule 1.\n\
             2. Axes are labeled with units; bars start at a zero baseline; the time axis is in the user's time zone (B11.10 rule 2).\n\
             3. A gap is drawn as a gap and never interpolated as a zero (B11.10 rules 2 and 8).\n\
             4. Direct labels are preferred over legends; a chart carries at most 8 series and the ninth becomes Other (B11.10 rule 3).\n\
             5. Series use the colour-blind-safe palette of B11.2 and each fill also carries a pattern (B11.10 rule 4).\n\
             6. Every chart has a text summary and a View as table toggle (B11.10 rule 5).\n\
             7. Interaction is progressive: tooltips enhance the chart and all information is available without them (B11.10 rule 6).\n\
             8. Charts are server-rendered SVG, render without JavaScript, print cleanly and have no animation by default (B11.10 rule 7).\n\
             9. Never chart fabricated or interpolated data (B11.10 rule 8; R-16).\n\
             10. Forced-colors mode uses the system colours and no encoding is colour alone (B11.2).\n\n\
             ## Tables\n\n\
             | Screen | Table | Columns | Default sort | Filters | Density |\n\
             | --- | --- | --- | --- | --- | --- |\n\
             | S-040 | attention-list | Item, Severity, Since, Action | Severity | Item kind | comfortable |\n\
             | S-065 | live-table | Time, Ray ID, IP key, Category, Action | Time | Category, Action | compact |\n\n\
             ## Time range\n\n\
             | Preset | Range | Granularity | Notes |\n| --- | --- | --- | --- |\n\
             | Last 15 minutes | 15 minutes before now | minute | The smallest preset. |\n\
             | Last 1 hour | 60 minutes before now | minute | One point per minute. |\n\
             | Last 24 hours | 24 hours before now | minute | The overview default. |\n\
             | Last 7 days | 7 days before now | hour | One point per hour. |\n\
             | Last 30 days | 30 days before now | hour | Bounded by the plan retention. |\n\
             | Custom | From and to, at most 400 days apart | auto | Validated; the granularity follows the guards. |\n\n\
             Plan limits: the only plan value that bounds a range is `plans.limits.events_retention_days` (B5.2, default 30 days in B6); Q-008 is OPEN and the specification states no per-plan analytics time-range limit, so this document invents none.\n\n\
             ## Comparisons\n\n\
             The previous period is the window of the same length immediately before the current one, compared bucket by bucket at the same granularity and in the same time zone (T-0442 step 1).\n\
             A comparison toggle turns the deltas on and off and keeps its state in the URL.\n\
             When the previous window contains a gap, the comparison is Unknown ({reason}) instead of a number.\n\n\
             ## Annotations\n\n\
             | Annotation | Source | Marker | Text alternative |\n| --- | --- | --- | --- |\n\
             | Mode change | config_revisions and `AUD-waf.mode_changed` | Vertical line | Mode changed to {mode} at {time} |\n\
             | Rule change | config_revisions and `AUD-waf.rule_created` | Dashed vertical line | Rule {rule} created at {time} |\n\
             | Ban | ip_bans and `AUD-ban.created` | Dot on the series | Ban created at {time} |\n\
             | Deployment | audit_log | Shaded band | Release {version} at {time} |\n\n\
             ## Colour and accessibility\n\n\
             | Series | Dark | Light | Pattern |\n| --- | --- | --- | --- |\n",
        );
        let patterns = [
            "solid",
            "dashes 6 3",
            "dots",
            "dash-dot",
            "wide dashes",
            "cross-hatch",
            "diagonal hatch",
            "vertical lines",
        ];
        for (index, pattern) in patterns.iter().enumerate() {
            let series = index + 1;
            text.push_str(&format!(
                "| {series} | B11.2 dark series {series} | B11.2 light series {series} | {pattern} |\n"
            ));
        }
        text.push_str(
            "\nThe chart series use the colour-blind-safe palette of B11.2 and every series also carries a pattern (B11.10 rule 4).\n\
             Forced-colors mode uses the system colours CanvasText, Canvas, LinkText and Highlight, and icons use currentColor (B11.2).\n\
             No encoding is colour alone: each series has a direct label, and the text summary and the View as table alternative carry the numbers.\n\
             Stat cards and tables are text-first: label, value, unit and delta are read directly (B11.8).\n\n\
             ## Performance and print\n\n\
             | Constraint | Value | Rule |\n| --- | --- | --- |\n\
             | Line points per chart | 16,000 points | 8 series times 2,000 points (T-0088 step 6). |\n\
             | Line points per series | 2,000 points | LTTB reduces a longer line series to this count (T-0088 step 6). |\n\
             | Line downsampling threshold | 2,000 points per series | LTTB is deterministic and split at every gap. |\n\
             | Render budget | 5 ms p95 for 2,000 points | Criterion benchmark on the builder (T-0088 A5). |\n\
             | API latency | 150 ms p95 | T-0442 A5; a 2 s query timeout returns ERR-ANALYTICS-002. |\n\
             | Print | A4 portrait, ISO 216, page margins in RESPONSIVE.md | One chart per page; patterns keep the series readable in greyscale. |\n\n\
             LTTB keeps 2,000 points per series and never crosses a gap: each gap-free segment is downsampled on its own.\n\n\
             ## Downsampling\n\n\
             LTTB is the line method only; every other form below aggregates whole rows, so a total never changes (F-27).\n\n\
             | Chart form | Maximum count | Method | Totals exact |\n| --- | --- | --- | --- |\n\
             | line | 2,000 points per series | LTTB with a three-point window, split at every gap (T-0088 step 6). | Yes: totals come from the rollup rows. |\n\
             | stacked bar | 400 buckets per chart | Re-bucket by summing adjacent buckets; nothing is sampled. | Yes: each bar is a sum of buckets. |\n\
             | ranked horizontal bar | 10 ranked keys plus Other (11 bars) | Top-N plus Other: Other is the exact sum of the remaining keys. | Yes: Other closes the ranking. |\n\
             | heatmap | 168 cells | Sum every hourly bucket into its local weekday and hour of a fixed 7 x 24 grid; the grid does not grow. | Yes: the cells partition the window. |\n\
             | choropleth | 200 countries plus Other and Unknown | One fill per country; the ranked table lists the same keys. | Yes: every fill is a sum over whole rows. |\n\
             | stat card | 1 value per card, at most 6 in a row | Whole rows: the card shows the aggregate of its window. | Yes: the value is the aggregate of every row. |\n\
             | table | 10,000 rows per table view | Whole rows: pagination reaches every row and nothing is sampled. | Yes: counts and totals come from the same query. |\n\n\
             ## Unknown data\n\n\
             | Widget | When it is unknown | Display | Never |\n| --- | --- | --- | --- |\n",
        );
        let reasons = [
            "the rollup has no row for the window",
            "a source query failed",
            "the counter has no sample in the window",
            "the category dimension has no row",
            "no hourly bucket in the week",
            "the stream is reconnecting",
            "the status class dimension has no row",
            "no GeoIP database is loaded",
            "the event store is unavailable",
            "no platform traffic was recorded",
        ];
        for (index, (widget, _form)) in WIDGETS.iter().enumerate() {
            let reason = reasons
                .get(index)
                .copied()
                .unwrap_or("the source is unavailable");
            text.push_str(&format!(
                "| {widget} | {reason} | Unknown ({{reason}}) | zero |\n"
            ));
        }
        text.push_str(
            "\nA gap in the data is a gap: it is never filled with an estimate or a fabricated value (R-16).\n\n\
             ## Spec gaps and limits\n\n\
             | Gap | Effect | Handling |\n| --- | --- | --- |\n\
             | B5.8 has no would-block or bans column | Monitor-mode counts and ban counts are not rollup columns | Would-block counts come from waf_events and ban counts from ip_bans |\n\
             | B9 has no bytes counter | Bandwidth exists only in the rollups | The dictionary marks bandwidth as rollup-only |\n\
             | T-0442 and B6.3 use different analytics route names | The endpoint name is ambiguous | The dictionary cites the B6.3 route names |\n\
             | Q-008 is OPEN | No per-plan time-range limit is specified | The six presets are the same for every plan |\n",
        );
        text
    }

    /// The fixture metrics dictionary.
    fn dictionary() -> String {
        String::from(
            "# Metrics dictionary (fixture)\n\n\
             A fixture dictionary for the T-0027 unit tests; it describes the fixture rows only.\n\n\
             ## Source legend\n\n\
             - `rollup_hour` and `rollup_day` are the aggregates of B5.8.\n\
             - `waf_events` is the event store of B5.7.\n\
             - `MET-` ids are the Prometheus metrics of B9.\n\n\
             ## Reading a row\n\n\
             Each row gives the KPI, its definition, unit, aggregation, time window, source, type, B9 labels, refresh cadence and Unknown behaviour.\n\n\
             ## Metrics\n\n\
             | KPI | Definition | Unit | Aggregation | Window | Source | Type | Labels | Refresh | Unknown |\n\
             | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |\n\
             | requests | Requests recorded by the proxy counters for the selected scope and window. | requests | sum | Last 24 hours and the picker range | rollup_hour and rollup_day, dimension all; instrumented by `MET-hdd_proxy_requests_total` | counter | surface, site, status_class, mode | rollup watermark, at most 30 s widget cache | Unknown (no rollup row yet); never zero |\n\
             | blocked | Requests whose verdict was block, summed over the selected scope and window. | requests | sum | Last 24 hours and the picker range | rollup_hour, column blocked; instrumented by `MET-hdd_waf_blocks_total` | counter | category, vector | rollup watermark, at most 30 s widget cache | Unknown (no rollup row yet); never zero |\n\
             | attention-open | Attention items whose deterministic rule currently fires for this organisation. | items | count | Current state | sites, certificates, ban_appeals and webhook_deliveries (T-0139 step 3) | state | - | on request, 30 s widget cache | Unknown (a source query failed); never zero |\n\
             | block-rate | Blocked requests divided by all requests over the same scope and window; `MET-hdd_waf_blocks_total` / `MET-hdd_proxy_requests_total`. | percent | ratio | The picker range | derived from `MET-hdd_waf_blocks_total` and `MET-hdd_proxy_requests_total` | derived | - | same as its inputs | Unknown (either counter has no sample); never 0 percent |\n\
             | blocked-by-category | Blocked requests grouped by attack category, summed over the window. | requests | sum | The picker range | rollup_hour, dimension category; instrumented by `MET-hdd_waf_blocks_total` | rollup | - | rollup watermark, at most 30 s widget cache | Unknown (the category dimension has no row); never zero |\n\
             | attack-heatmap | Blocked requests grouped by local weekday and hour, summed into a fixed seven by twenty-four grid. | requests | sum | The picker range | rollup_hour buckets converted to the user's time zone (B5.8) | rollup | - | rollup watermark, at most 30 s widget cache | Unknown (no hourly bucket in the week); never zero |\n\
             | live-events-per-min | Notable events per minute read from the live event stream. | events/min | count | Last 60 seconds, sliding every 5 s | waf_events and the SSE stream `GET D/events/stream` | event | - | live SSE push, 15 s heartbeat | Unknown (the stream is reconnecting); never zero |\n\
             | live-blocked-per-min | Events with the action block per minute from the live stream. | events/min | count | Last 60 seconds, sliding every 5 s | waf_events and `GET D/events/stream` | event | - | live SSE push, 15 s heartbeat | Unknown (the stream is reconnecting); never zero |\n\
             | live-top-category | The category with the most events in the last five minutes of the live stream. | category (count in events) | argmax over the count | Last 5 minutes | waf_events and the live stream (B5.7) | event | - | live SSE push, recomputed every 5 s | Unknown (too few events to rank); never shown as zero |\n\
             | live-rows | The newest notable events shown as table rows. | rows | count | Last 60 seconds | waf_events and the SSE stream | event | - | live SSE push, sampled above 20 events/s | Unknown (no event can be shown); never zero |\n\
             | status-classes | Requests grouped by response status class over the range. | requests | sum | The picker range | rollup_hour, dimension status_class | rollup | - | rollup watermark, at most 30 s widget cache | Unknown (the status class dimension has no row); never zero |\n\
             | geo-requests | Requests grouped by the enrichment country of the event. | requests | sum | The picker range | rollup_hour, dimension country | rollup | - | rollup watermark, at most 30 s widget cache | Unknown (no GeoIP database); never zero |\n\
             | admin-attack-summary | Blocked requests by category and ASN during the last hour of platform traffic. | requests | sum | Last 1 hour | rollup_hour and waf_events | rollup | - | rollup watermark, at most 30 s widget cache | Unknown (no platform traffic recorded); never zero |\n\
             | shield-state | The shield state 0 normal, 1 elevated, 2 attack, 3 saturated. | state | last | Current state | `MET-hdd_shield_state` | gauge | - | each Prometheus scrape | Unknown (the shield is not deployed); never zero |\n",
        )
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used, clippy::unwrap_used, reason = "tests")]

    use std::fs;
    use std::path::PathBuf;

    use super::*;

    /// A minimal specification with the sections the rules read (B12.1, B11.8, B8) plus the fixture rows the Lead
    /// appends. It stands in for the master and keeps the tests independent of the repository.
    fn test_spec() -> String {
        let mut spec = String::from(
            "## B12.1 Screen table\n\n| ID | Name | Purpose and key content |\n| --- | --- | --- |\n\
             | S-040 | Org overview | Organisation summary. |\n\
             | S-043 | Domain overview | One domain summary. |\n\
             | S-054 | Security overview | Protection state. |\n\
             | S-065 | Live threat monitor | The live event feed. |\n\
             | S-070 | Analytics overview | Traffic charts. |\n\
             | S-071 | Geo and ASN | Map with ranked table. |\n\
             | S-072 | Top attackers and paths | Top lists. |\n\
             | S-100 | Admin overview | Platform KPIs. |\n\
             | S-127 | DDoS readiness and shield | Shield state. |\n\
             \n### B11.8 Component inventory\n\n| Component | Contract (summary) |\n| --- | --- |\n\
             | Card / StatCard | A label and a value. |\n\
             | DataTable | A semantic table with sortable headers. |\n\
             | ChartKit | Server-rendered SVG with a data table alternative. |\n\
             | WorldMap | A map with a ranked list alternative. |\n\
             \n### B8. Audit event taxonomy\n\n| Event | Trigger | Detail |\n| --- | --- | --- |\n\
             | AUD-waf.mode_changed | Mode | from, to |\n\
             | AUD-waf.rule_created | Rule | rule id |\n\
             | AUD-ban.created | Ban | ip_key |\n\n",
        );
        spec.push_str(&fixtures::spec_section());
        spec
    }

    /// The fixture data visualization document.
    fn dataviz() -> String {
        let documents = fixtures::documents();
        documents
            .first()
            .map(|(_, text)| text.clone())
            .unwrap_or_default()
    }

    /// The fixture metrics dictionary.
    fn dictionary() -> String {
        let documents = fixtures::documents();
        documents
            .get(1)
            .map(|(_, text)| text.clone())
            .unwrap_or_default()
    }

    /// The fixture responsive document for the F-23 comparison.
    fn responsive() -> String {
        fixtures::responsive_fixture()
    }

    /// Findings of one rule, as one string.
    fn messages(findings: Vec<Finding>) -> String {
        findings
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>()
            .join("\n")
    }

    #[test]
    fn t27_the_fixture_documents_pass_every_rule() {
        let spec = test_spec();
        let findings = rules(&dataviz(), &dictionary(), &spec, Some(&responsive()));
        assert!(findings.is_empty(), "{}", messages(findings));
    }

    #[test]
    fn t27_missing_documents_and_sections_are_findings() {
        let spec = test_spec();
        let missing = check_with_spec(Path::new("a-directory-that-does-not-exist"), &spec);
        let text = messages(missing);
        assert!(text.contains(DATAVIZ), "{text}");
        assert!(text.contains(DICTIONARY), "{text}");

        let no_unknown = dataviz().replace("## Unknown data", "## Missing behaviour");
        let text = messages(document_findings(&no_unknown, &dictionary()));
        assert!(text.contains("Unknown data"), "{text}");

        let no_metrics = dictionary().replace("## Metrics", "## Numbers");
        let text = messages(document_findings(&dataviz(), &no_metrics));
        assert!(text.contains("Metrics"), "{text}");
    }

    #[test]
    fn t27_a_byte_order_mark_or_mojibake_fails_the_document_rule() {
        let with_bom = format!("\u{feff}{}", dataviz());
        let text = messages(document_findings(&with_bom, &dictionary()));
        assert!(text.contains("byte-order mark"), "{text}");

        let mojibake = dataviz().replace("A fixture document", "A fiÃ¢â‚¬â„¢xture document");
        let text = messages(document_findings(&mojibake, &dictionary()));
        assert!(
            text.contains("mojibake") || text.contains("encoding"),
            "{text}"
        );
    }

    #[test]
    fn t27_every_required_screen_has_a_question_and_a_metric() {
        let spec = test_spec();
        let kpis = kpi_names(&dictionary());
        let without_s100: String = dataviz()
            .lines()
            .filter(|line| !line.starts_with("| S-100 |"))
            .collect::<Vec<_>>()
            .join("\n");
        let text = messages(screen_question_findings(&without_s100, &spec, &kpis));
        assert!(text.contains("S-100"), "{text}");

        let unknown_screen = dataviz().replace("| S-127 |", "| S-999 |");
        let text = messages(screen_question_findings(&unknown_screen, &spec, &kpis));
        assert!(text.contains("S-999"), "{text}");

        let no_question_mark = dataviz().replacen(
            "How much traffic did the organisation receive?",
            "Traffic received",
            1,
        );
        let text = messages(screen_question_findings(&no_question_mark, &spec, &kpis));
        assert!(text.contains("?"), "{text}");

        let empty_metric =
            dataviz().replacen("| Requests and blocked requests over 24 hours |", "| |", 1);
        let text = messages(screen_question_findings(&empty_metric, &spec, &kpis));
        assert!(text.contains("Metric"), "{text}");
    }

    #[test]
    fn t27_every_screen_has_a_visual_not_only_the_table_alternative() {
        let spec = test_spec();
        let kpis = kpi_names(&dictionary());
        let only_table: String = dataviz()
            .lines()
            .map(|line| {
                if line.starts_with("| S-054 |") {
                    "| S-054 | Which categories are attacked? | Blocked requests by category | blocked-by-category | table | attention-list | A list of categories with actions: the DataTable is the text-first form (B11.8). |"
                } else {
                    line
                }
            })
            .collect::<Vec<_>>()
            .join("\n");
        let text = messages(screen_question_findings(&only_table, &spec, &kpis));
        assert!(text.contains("visual"), "{text}");
    }

    #[test]
    fn t27_kpi_must_be_a_dictionary_row() {
        let spec = test_spec();
        let kpis = kpi_names(&dictionary());
        let wrong_kpi = dataviz().replacen("| requests, blocked |", "| not-a-kpi |", 1);
        let text = messages(screen_question_findings(&wrong_kpi, &spec, &kpis));
        assert!(text.contains("not-a-kpi"), "{text}");
    }

    #[test]
    fn t27_chart_forms_are_the_b11_10_forms_and_whole_tokens() {
        let spec = test_spec();
        let pie = dataviz().replacen("| line | traffic-24h |", "| pie | traffic-24h |", 1);
        let text = messages(chart_form_findings(&pie, &spec));
        assert!(text.contains("pie"), "{text}");

        let deadline =
            dataviz().replacen("| line | traffic-24h |", "| deadline | traffic-24h |", 1);
        let text = messages(chart_form_findings(&deadline, &spec));
        assert!(text.contains("deadline"), "{text}");

        let no_forms = spec.replace("line for time series", "curves for time series");
        let text = messages(chart_form_findings(&dataviz(), &no_forms));
        assert!(text.to_lowercase().contains("b11.10"), "{text}");
    }

    #[test]
    fn t27_every_chart_form_is_justified() {
        let spec = test_spec();
        let weak = dataviz().replacen(
            "Time series: line is the simplest form for a change over time (B11.10 rule 1).",
            "It looks nice.",
            1,
        );
        let text = messages(chart_form_findings(&weak, &spec));
        assert!(
            text.contains("Justification") || text.contains("B11.10"),
            "{text}"
        );
    }

    #[test]
    fn t27_every_chart_has_a_text_summary_and_a_view_as_table_toggle() {
        let without = dataviz()
            .lines()
            .filter(|line| !line.starts_with("| top-categories |"))
            .collect::<Vec<_>>()
            .join("\n");
        let text = messages(chart_alternative_findings(&without));
        assert!(text.contains("top-categories"), "{text}");

        let no_toggle = dataviz().replacen(
            "| View as table (bucket ascending, compact density) |",
            "| The numbers in a table |",
            1,
        );
        let text = messages(chart_alternative_findings(&no_toggle));
        assert!(text.contains("View as table"), "{text}");

        let no_summary = dataviz().replacen(
            "| Requests peaked at {peak_time} with {peak_value}; {blocked} were blocked. |",
            "| |",
            1,
        );
        let text = messages(chart_alternative_findings(&no_summary));
        assert!(text.contains("summary"), "{text}");
    }

    #[test]
    fn t27_the_chart_rules_state_the_global_rules() {
        let no_gap = dataviz().replace(
            "A gap is drawn as a gap and never interpolated as a zero (B11.10 rules 2 and 8).\n",
            "",
        );
        let text = messages(chart_rule_findings(&no_gap));
        assert!(text.contains("gap"), "{text}");

        let interpolated = dataviz().replace(
            "A gap is drawn as a gap and never interpolated as a zero (B11.10 rules 2 and 8).",
            "A gap is interpolated as a zero (B11.10 rules 2 and 8).",
        );
        let text = messages(chart_rule_findings(&interpolated));
        assert!(text.contains("never"), "{text}");

        let no_svg = dataviz().replace(
            "Charts are server-rendered SVG, render without JavaScript, print cleanly and have no animation by default (B11.10 rule 7).\n",
            "",
        );
        let text = messages(chart_rule_findings(&no_svg));
        assert!(
            text.contains("SVG") || text.contains("server-rendered"),
            "{text}"
        );

        let no_series = dataviz().replace(
            "Direct labels are preferred over legends; a chart carries at most 8 series and the ninth becomes Other (B11.10 rule 3).\n",
            "",
        );
        let text = messages(chart_rule_findings(&no_series));
        assert!(text.contains("8") || text.contains("series"), "{text}");
    }

    #[test]
    fn t27_table_specs_need_columns_sort_filters_and_density() {
        let no_row = dataviz()
            .lines()
            .filter(|line| !line.starts_with("| S-065 | live-table |"))
            .collect::<Vec<_>>()
            .join("\n");
        let text = messages(table_spec_findings(&no_row));
        assert!(text.contains("live-table"), "{text}");

        let bad_density = dataviz().replace("| compact |", "| dense |");
        let text = messages(table_spec_findings(&bad_density));
        assert!(text.contains("density"), "{text}");

        let bad_sort = dataviz().replace(
            "| Time | Category, Action |",
            "| Whatever | Category, Action |",
        );
        let text = messages(table_spec_findings(&bad_sort));
        assert!(
            text.contains("default sort") || text.contains("column"),
            "{text}"
        );
    }

    #[test]
    fn t27_time_presets_are_exactly_the_six_named() {
        let swapped = dataviz().replace("| Last 7 days |", "| Last 12 hours |");
        let text = messages(time_range_findings(&swapped));
        assert!(
            text.contains("Last 7 days") || text.contains("presets"),
            "{text}"
        );

        let no_plan = dataviz().replace(
            "Plan limits: the only plan value that bounds a range is `plans.limits.events_retention_days` (B5.2, default 30 days in B6); Q-008 is OPEN and the specification states no per-plan analytics time-range limit, so this document invents none.\n",
            "",
        );
        let text = messages(time_range_findings(&no_plan));
        assert!(
            text.contains("events_retention_days") || text.contains("plan"),
            "{text}"
        );
    }

    #[test]
    fn t27_comparison_defines_the_previous_period_and_the_unknown_case() {
        let no_unknown = dataviz().replace(
            "When the previous window contains a gap, the comparison is Unknown ({reason}) instead of a number.\n",
            "",
        );
        let text = messages(comparison_findings(&no_unknown));
        assert!(
            text.contains("Unknown") || text.contains("previous"),
            "{text}"
        );

        let no_toggle = dataviz().replace(
            "A comparison toggle turns the deltas on and off and keeps its state in the URL.\n",
            "",
        );
        let text = messages(comparison_findings(&no_toggle));
        assert!(text.contains("toggle"), "{text}");
    }

    #[test]
    fn t27_annotations_include_mode_rule_ban_and_deployment() {
        let spec = test_spec();
        let no_ban = dataviz().replace(
            "| Ban | ip_bans and `AUD-ban.created` | Dot on the series | Ban created at {time} |\n",
            "",
        );
        let text = messages(annotation_findings(&no_ban, &spec));
        assert!(text.contains("ban"), "{text}");

        let wrong_source = dataviz().replace(
            "| Mode change | config_revisions and `AUD-waf.mode_changed` |",
            "| Mode change | a deploy log and `AUD-waf.mode_changed` |",
        );
        let text = messages(annotation_findings(&wrong_source, &spec));
        assert!(text.contains("config_revisions"), "{text}");

        let fake_audit =
            dataviz().replace("`AUD-waf.mode_changed`", "`AUD-waf.mode_changed_extra`");
        let text = messages(annotation_findings(&fake_audit, &spec));
        assert!(text.contains("AUD-waf.mode_changed_extra"), "{text}");
    }

    #[test]
    fn t27_colour_has_eight_patterned_b11_2_series() {
        let spec = test_spec();
        let duplicate = dataviz().replace("| dots |", "| solid |");
        let text = messages(colour_findings(&duplicate, &spec));
        assert!(text.contains("pattern"), "{text}");

        let mut with_b11_2 = spec.clone();
        with_b11_2.push_str("\n### B11.2 Color tokens\n\n| Token | Value |\n| --- | --- |\n| `--chart-1` | `#E69F00` |\n");
        let invented = dataviz().replace("B11.2 dark series 1", "#123456");
        let text = messages(colour_findings(&invented, &with_b11_2));
        assert!(text.contains("#123456"), "{text}");

        let no_forced = dataviz().replace(
            "Forced-colors mode uses the system colours CanvasText, Canvas, LinkText and Highlight, and icons use currentColor (B11.2).",
            "High contrast is handled.",
        );
        let text = messages(colour_findings(&no_forced, &spec));
        assert!(text.contains("forced-colors"), "{text}");
    }

    #[test]
    fn t27_downsampling_thresholds_are_numeric() {
        let non_numeric = dataviz().replace("| 2,000 points per series |", "| many points |");
        let text = messages(performance_findings(&non_numeric));
        assert!(
            text.contains("numeric") || text.contains("points per series"),
            "{text}"
        );

        let no_lttb = dataviz().replace("LTTB keeps 2,000 points per series and never crosses a gap: each gap-free segment is downsampled on its own.", "");
        let text = messages(performance_findings(&no_lttb));
        assert!(text.contains("LTTB"), "{text}");
    }

    #[test]
    fn t27_every_chart_form_used_has_a_numeric_downsampling_rule() {
        let text = messages(downsampling_findings(&dataviz()));
        assert!(text.is_empty(), "{text}");

        let no_heatmap: String = dataviz()
            .lines()
            .filter(|line| !line.starts_with("| heatmap |"))
            .collect::<Vec<_>>()
            .join("\n");
        let text = messages(downsampling_findings(&no_heatmap));
        assert!(text.contains("heatmap"), "{text}");

        let with_bar = dataviz().replacen("| line | traffic-24h |", "| bar | traffic-24h |", 1);
        let text = messages(downsampling_findings(&with_bar));
        assert!(text.contains("bar"), "{text}");

        let no_number = dataviz().replace("| 168 cells |", "| many cells |");
        let text = messages(downsampling_findings(&no_number));
        assert!(
            text.contains("numeric") || text.contains("heatmap"),
            "{text}"
        );
    }

    #[test]
    fn t27_downsampling_methods_match_their_form_and_lttb_stays_on_the_line() {
        let wrong = dataviz().replace(
            "| stacked bar | 400 buckets per chart | Re-bucket by summing adjacent buckets; nothing is sampled. |",
            "| stacked bar | 400 buckets per chart | LTTB with a three-point window, same as the line. |",
        );
        let text = messages(downsampling_findings(&wrong));
        assert!(
            text.contains("stacked bar") && text.contains("LTTB"),
            "{text}"
        );

        let not_exact = dataviz().replace(
            "| Yes: each bar is a sum of buckets. |",
            "| No: the bars are approximate. |",
        );
        let text = messages(downsampling_findings(&not_exact));
        assert!(text.contains("exact") || text.contains("total"), "{text}");

        let line_without_lttb = dataviz().replace(
            "| line | 2,000 points per series | LTTB with a three-point window, split at every gap (T-0088 step 6). |",
            "| line | 2,000 points per series | every other point, split at every gap (T-0088 step 6). |",
        );
        let text = messages(downsampling_findings(&line_without_lttb));
        assert!(text.to_lowercase().contains("lttb"), "{text}");
    }

    #[test]
    fn t27_print_layout_points_to_responsive_without_its_own_margin() {
        let responsive = responsive();
        let text = messages(print_alignment_findings(&dataviz(), Some(&responsive)));
        assert!(text.is_empty(), "{text}");

        let own = dataviz().replace(
            "| Print | A4 portrait, ISO 216, page margins in RESPONSIVE.md |",
            "| Print | A4 portrait, 12 mm margins |",
        );
        let text = messages(print_alignment_findings(&own, Some(&responsive)));
        assert!(text.contains("12"), "{text}");
        assert!(text.contains("RESPONSIVE.md"), "{text}");

        let no_pointer = dataviz().replace(
            "| Print | A4 portrait, ISO 216, page margins in RESPONSIVE.md |",
            "| Print | A4 portrait, ISO 216, page margins as elsewhere |",
        );
        let text = messages(print_alignment_findings(&no_pointer, Some(&responsive)));
        assert!(text.contains("RESPONSIVE.md"), "{text}");

        let different = dataviz().replace(
            "| Print | A4 portrait, ISO 216, page margins in RESPONSIVE.md |",
            "| Print | A4 portrait, 15 mm margins |",
        );
        let text = messages(print_alignment_findings(&different, Some(&responsive)));
        assert!(text.contains("15") && text.contains("12"), "{text}");
    }

    #[test]
    fn t27_unknown_behaviour_is_defined_for_every_widget() {
        let without = dataviz()
            .lines()
            .filter(|line| !line.starts_with("| live-table |"))
            .collect::<Vec<_>>()
            .join("\n");
        let text = messages(unknown_findings(&without));
        assert!(text.contains("live-table"), "{text}");

        let zero = dataviz().replace("| Unknown ({reason}) | zero |", "| 0 | zero |");
        let text = messages(unknown_findings(&zero));
        assert!(text.contains("Unknown"), "{text}");
    }

    #[test]
    fn t27_spec_gaps_are_stated_with_real_references() {
        let no_reference = dataviz().replace(
            "| B9 has no bytes counter | Bandwidth exists only in the rollups | The dictionary marks bandwidth as rollup-only |",
            "| A missing metric | Bandwidth is unclear | The dictionary says so |",
        );
        let text = messages(spec_gap_findings(&no_reference));
        assert!(
            text.contains("cites no specification") || text.contains("B9"),
            "{text}"
        );

        let too_few: String = dataviz()
            .lines()
            .filter(|line| !line.starts_with("| Q-008 is OPEN |"))
            .collect::<Vec<_>>()
            .join("\n");
        let text = messages(spec_gap_findings(&too_few));
        assert!(text.contains("four") || text.contains("gap"), "{text}");
    }

    #[test]
    fn t27_dictionary_columns_and_rows_are_complete() {
        let no_unknown = dictionary().replace("| Unknown |", "| Note |");
        let text = messages(dictionary_findings(&no_unknown));
        assert!(text.contains("Unknown"), "{text}");

        let short_definition = dictionary().replace(
            "Requests recorded by the proxy counters for the selected scope and window.",
            "Requests.",
        );
        let text = messages(dictionary_findings(&short_definition));
        assert!(text.contains("Definition"), "{text}");

        let bad_aggregation = dictionary().replace("| requests | sum |", "| requests | guess |");
        let text = messages(dictionary_findings(&bad_aggregation));
        assert!(text.contains("Aggregation"), "{text}");

        let bad_type = dictionary().replace("| gauge | - |", "| average | - |");
        let text = messages(dictionary_findings(&bad_type));
        assert!(text.contains("Type"), "{text}");

        let no_unknown_text = dictionary().replace(
            "Unknown (no rollup row yet); never zero",
            "Not available; never zero",
        );
        let text = messages(dictionary_findings(&no_unknown_text));
        assert!(text.contains("Unknown"), "{text}");
    }

    #[test]
    fn t27_derived_kpis_state_their_formula() {
        let no_formula = dictionary().replace(
            "Blocked requests divided by all requests over the same scope and window; `MET-hdd_waf_blocks_total` / `MET-hdd_proxy_requests_total`.",
            "The share of the traffic that was blocked.",
        );
        let text = messages(dictionary_findings(&no_formula));
        assert!(
            text.contains("formula") || text.contains("derived"),
            "{text}"
        );
    }

    #[test]
    fn t27_metric_ids_exist_in_b9_and_audit_ids_in_b8() {
        let spec = test_spec();
        let fake = dictionary().replace("MET-hdd_proxy_requests_total", "MET-hdd_not_a_metric");
        let text = messages(metric_id_findings(&dataviz(), &fake, &spec));
        assert!(text.contains("MET-hdd_not_a_metric"), "{text}");

        let suffixed = dictionary().replace(
            "`MET-hdd_waf_blocks_total`",
            "`MET-hdd_waf_blocks_total_extra`",
        );
        let text = messages(metric_id_findings(&dataviz(), &suffixed, &spec));
        assert!(text.contains("MET-hdd_waf_blocks_total_extra"), "{text}");

        let fake_audit = dataviz().replace("AUD-ban.created", "AUD-ban.created_now");
        let text = messages(metric_id_findings(&fake_audit, &dictionary(), &spec));
        assert!(text.contains("AUD-ban.created_now"), "{text}");
    }

    #[test]
    fn t27_metric_type_and_labels_agree_with_b9() {
        let spec = test_spec();
        let wrong_type = dictionary().replace(
            "| rollup_hour and rollup_day, dimension all; instrumented by `MET-hdd_proxy_requests_total` | counter |",
            "| `MET-hdd_bans_active` | counter |",
        );
        let text = messages(metric_type_label_findings(&wrong_type, &spec));
        assert!(text.contains("counter") && text.contains("gauge"), "{text}");

        let wrong_label =
            dictionary().replace("| surface, site, status_class, mode |", "| country |");
        let text = messages(metric_type_label_findings(&wrong_label, &spec));
        assert!(text.contains("country"), "{text}");
    }

    #[test]
    fn t27_placeholder_values_are_rejected() {
        let placeholder = dataviz().replace("| 16,000 points |", "| TBD |");
        let text = messages(placeholder_findings(&placeholder, &dictionary()));
        assert!(text.contains("TBD"), "{text}");

        let filler_row = dictionary().replace(
            "| shield-state | The shield state 0 normal, 1 elevated, 2 attack, 3 saturated. | state | last | Current state | `MET-hdd_shield_state` | gauge | - | each Prometheus scrape | Unknown (the shield is not deployed); never zero |",
            "| shield-state | - | - | - | - | - | - | - | - | - |",
        );
        let text = messages(placeholder_findings(&dataviz(), &filler_row));
        assert!(text.contains("filler"), "{text}");
    }

    #[test]
    fn t27_a_spec_without_b9_or_b11_10_is_a_finding_not_a_panic() {
        let spec =
            "### B12.1 Screen table\n\n| ID | Name |\n| --- | --- |\n| S-040 | Org overview |\n";
        let findings = rules(&dataviz(), &dictionary(), spec, Some(&responsive()));
        let text = messages(findings);
        assert!(text.contains("B9") || text.contains("B11.10"), "{text}");

        let empty = rules("", "", "", None);
        assert!(!empty.is_empty());
    }

    #[test]
    fn t27_the_check_reads_the_fixture_tree() {
        let dir = std::env::temp_dir().join(format!("hdd-xtask-dataviz-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(dir.join("docs").join("UX")).expect("mkdir");
        for (path, text) in fixtures::documents() {
            let target = dir.join(PathBuf::from(path));
            fs::write(target, text).expect("write");
        }
        fs::write(
            dir.join("docs").join("UX").join("RESPONSIVE.md"),
            fixtures::responsive_fixture(),
        )
        .expect("write");
        let findings = check_with_spec(&dir, &test_spec());
        assert!(findings.is_empty(), "{}", messages(findings));
        let _ = fs::remove_dir_all(&dir);
    }

    /// A minimal metrics dictionary with one ranking row, for the F-29 rule.
    fn ranking_dictionary(definition: &str, aggregation: &str) -> String {
        format!(
            "# Metrics dictionary (fixture)\n\n\
             ## Metrics\n\n\
             | KPI | Definition | Unit | Aggregation | Window | Source | Type | Labels | Refresh | Unknown |\n\
             | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |\n\
             | live-top-category | {definition} | category (count in events) | {aggregation} | Last 5 minutes | waf_events and the live stream (B5.7) | event | - | live SSE push, recomputed every 5 s | Unknown (too few events to rank); never shown as zero |\n"
        )
    }

    #[test]
    fn t27_a_ranking_definition_needs_an_argmax_aggregation() {
        let category =
            "The category with the most events in the last five minutes of the live stream.";
        let passing = ranking_dictionary(category, "argmax over the count");
        assert!(top_aggregation_findings(&passing).is_empty());

        // A label aggregation that only keeps the maximum count loses the category name.
        let max = ranking_dictionary(category, "max");
        let text = messages(top_aggregation_findings(&max));
        assert!(
            text.contains("argmax") && text.contains("top"),
            "a ranking definition with the aggregation `max` must be a finding: {text}"
        );

        // `the category with` alone, without `the most`, is a ranking too.
        let labelled = ranking_dictionary(
            "The category with the largest share of blocked events over the window.",
            "max",
        );
        let text = messages(top_aggregation_findings(&labelled));
        assert!(
            text.contains("argmax") || text.contains("top"),
            "`the category with` without `the most` must be a finding: {text}"
        );

        // `the most` alone, without `the category with`, is a ranking too.
        let ranked = ranking_dictionary(
            "The path with the most requests over the selected window.",
            "sum",
        );
        let text = messages(top_aggregation_findings(&ranked));
        assert!(
            text.contains("argmax") || text.contains("top"),
            "`the most` without `the category with` must be a finding: {text}"
        );

        // The shared fixture dictionary carries a passing ranking row.
        assert!(top_aggregation_findings(&dictionary()).is_empty());
    }
}
