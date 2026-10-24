//! `ux-docs` checks for T-0022 (accessibility strategy and test plan).
//!
//! Rules, all stated here because this module is the only place that enforces them:
//!
//! * `docs/UX/ACCESSIBILITY.md` has the eight sections of T-0022 steps 1 to 8 (`Criterion mapping`,
//!   `Assistive technology and browser matrix`, `Automated checks`, `Manual checks`, `Severity and gate rule`,
//!   `Accessibility statement`, `Human steps`, `Regression strategy`), each with a body;
//! * `docs/UX/wcag22-criteria.toml` parses, cites the W3C WCAG 2.2 source and access date, and lists unique
//!   success criteria ids with a title and a level of `A` or `AA`;
//! * every stored criterion id appears exactly once in the mapping table with the stored level and title and
//!   an owner that is either a B11.8 component named as a whole token, a declared page pattern, or
//!   `not applicable: <reason>` (at least three words); a mapped id that is not in the stored list, a
//!   duplicate row, a level or title that differs from the stored list, and an owner that names no real
//!   component are findings (T-0022 A1);
//! * every page pattern an owner names is declared in the `### Page patterns` table, and each declared
//!   pattern names at least one real B11.8 component;
//! * the assistive technology and browser matrix covers every modality T-0022 step 2 names, and the JAWS
//!   row says `if available`;
//! * the automated checks name the axe-core oracle in the CDP tests with zero serious or critical
//!   violations, the colour-contrast token check and the heading, landmark, form-label and focus-order
//!   checks (T-0022 step 3, T-0091);
//! * the manual checks name keyboard walkthroughs, the 12 screen-reader checklists and zoom and reflow
//!   checks (T-0022 step 4);
//! * the severity section has the four severities and states that serious issues block the gate under
//!   AC-40 (T-0022 step 5); the scheme is a function of four inputs (criterion failed, critical flow
//!   blocked, security control unreachable, axe impact) whose precedence the section states, the four
//!   definitions and gate effects cannot overlap, and every row of the `### Severity examples` table is
//!   recomputed by the classifier so a row that disagrees with the precedence is a defect (F-25);
//! * the accessibility statement section claims no more than was tested (no absolute conformance wording,
//!   an explicit "does not claim" sentence) and lists the known gaps in a table (T-0022 step 6, A5);
//! * the human-step section carries `human_step_pending` with an owner line and exact numbered
//!   instructions, including where the record is stored (T-0022 step 7, A4);
//! * the regression strategy names `acceptance-ui/`, stable per-screen names and the baselines that arrive
//!   with T-0052 and T-0090 (T-0022 step 8);
//! * `## Critical flows` names exactly 12 journeys of spec B3 by id and exact title, each with a unique
//!   slug, and `docs/UX/a11y-checklists/` holds exactly those 12 files; each checklist has a keyboard path,
//!   a screen-reader script, failure criteria and a `human_step_pending` owner line (T-0022 A2);
//! * every checklist screen id is a whole token (an `ERR-SYS-001` error code is never the screen S-001)
//!   and every `S-nnn` and `J-nn` cited in the strategy or a checklist exists in the master
//!   specification, so an invented screen or journey id is a finding;
//! * each checklist agrees with its journey map (F-26): its `Screens:` line equals the screens of the
//!   journey's `## Steps` table, every journey screen is exercised by the keyboard path or the
//!   screen-reader script or is declared on a reasoned `Screens not covered:` line, every screen the
//!   checklist names is a journey screen or is declared on a reasoned `Outside the journey:` line, and
//!   the strategy documents those three forms in `### Checklist screen coverage`.
//!
//! The module receives the checksum-verified master specification from the caller. Missing files, missing
//! sections and malformed tables are findings, never panics.

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

use regex::Regex;
use serde::Deserialize;

use crate::util::{Finding, read_text, rel, walk_files};

use super::{cells, column, section_body, section_table, subsection_body, table_rows, tokens_in};

/// The accessibility strategy document.
pub const ACCESSIBILITY: &str = "docs/UX/ACCESSIBILITY.md";
/// The stored WCAG 2.2 A/AA criterion list the mapping is checked against.
pub const CRITERIA_FILE: &str = "docs/UX/wcag22-criteria.toml";
/// The directory of one checklist per critical flow.
pub const CHECKLIST_DIR: &str = "docs/UX/a11y-checklists";
/// The journey maps whose `## Steps` tables the checklists must agree with (F-26).
pub const JOURNEY_DIR: &str = "docs/UX/journeys";

/// The eight level-2 sections T-0022 steps 1 to 8 name.
pub const SECTIONS: [&str; 8] = [
    "Criterion mapping",
    "Assistive technology and browser matrix",
    "Automated checks",
    "Manual checks",
    "Severity and gate rule",
    "Accessibility statement",
    "Human steps",
    "Regression strategy",
];

/// The section that names the 12 critical flows (T-0022 A2).
pub const FLOWS: &str = "Critical flows";
/// Exactly this many critical flows and checklist files (T-0022 A2).
pub const FLOW_COUNT: usize = 12;

/// The assistive technology and browser modalities T-0022 step 2 names.
pub const MATRIX_MODALITIES: [&str; 13] = [
    "Chromium-based",
    "Firefox",
    "Safari",
    "NVDA",
    "JAWS",
    "VoiceOver",
    "TalkBack",
    "Keyboard only",
    "200% zoom",
    "400% zoom",
    "High contrast",
    "Forced colors",
    "Reduced motion",
];

/// Severities of the scheme in T-0022 step 5.
pub const SEVERITIES: [&str; 4] = ["Critical", "Serious", "Moderate", "Minor"];

/// Absolute conformance wording the statement must not carry (T-0022 A5).
pub const ABSOLUTE_CLAIMS: [&str; 9] = [
    "fully conforms",
    "fully conform",
    "fully compliant",
    "100%",
    "meets all",
    "meets every",
    "complete conformance",
    "no known accessibility issues",
    "wcag 2.2 aa compliant",
];

/// One stored success criterion.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Criterion {
    /// WCAG success criterion title as the standard writes it.
    title: String,
    /// Conformance level, `A` or `AA`.
    level: String,
}

/// One named critical flow (T-0022 A2).
#[derive(Debug, Clone, PartialEq, Eq)]
struct Flow {
    /// Journey id from spec B3 (`J-nn`).
    id: String,
    /// Exact journey title from spec B3.
    name: String,
    /// Checklist file stem.
    slug: String,
}

/// The raw shape of `docs/UX/wcag22-criteria.toml`.
#[derive(Debug, Deserialize)]
struct CriteriaFile {
    /// The W3C URL the list was transcribed from.
    source: String,
    /// Access date in `YYYY-MM-DD`.
    accessed: String,
    /// The criteria rows.
    criteria: Vec<CriterionRow>,
}

/// One `[[criteria]]` row of the stored list.
#[derive(Debug, Deserialize)]
struct CriterionRow {
    /// Success criterion id such as `1.4.3`.
    id: String,
    /// Success criterion title.
    title: String,
    /// Conformance level.
    level: String,
}

/// A `ux-docs` finding at `location`.
fn at(location: impl Into<String>, message: impl Into<String>) -> Finding {
    Finding::new("ux-docs", location, message)
}

/// Collapsed whitespace, so a multi-word token matches across table cell padding.
fn normalized(text: &str) -> String {
    text.split_whitespace().collect::<Vec<_>>().join(" ")
}

/// Whether `token` occurs in `text` as a whole token (case-insensitive).
///
/// A token is not matched inside a longer word: `DataTableOfDoom` does not name `DataTable`, `IconButton`
/// does not name `Button`, `1.1.10` does not name `1.1.1` and `J-021` does not name `J-02`.
fn has_token(text: &str, token: &str) -> bool {
    let needle = normalized(token);
    if needle.is_empty() {
        return false;
    }
    let hay = normalized(text);
    let pattern = format!(
        r"(?i)(?:^|[^0-9A-Za-z_]){}(?:$|[^0-9A-Za-z_])",
        regex::escape(&needle)
    );
    Regex::new(&pattern).is_ok_and(|re| re.is_match(&hay))
}

/// Whether any of `tokens` occurs in `text` as a whole token.
fn has_any(text: &str, tokens: &[&str]) -> bool {
    tokens.iter().any(|token| has_token(text, token))
}

/// Trimmed table cell with backticks removed.
fn plain(cell: &str) -> String {
    cell.trim().trim_matches('`').trim().to_owned()
}

/// Body of a list of section lines as one string.
fn body_text(lines: &[(usize, String)]) -> String {
    let mut out = String::new();
    for (_, line) in lines {
        out.push_str(line);
        out.push('\n');
    }
    out
}

/// Whether a line is a numbered list item (`1. `).
fn is_numbered(line: &str) -> bool {
    let t = line.trim_start();
    let digits: String = t.chars().take_while(char::is_ascii_digit).collect();
    !digits.is_empty()
        && t.get(digits.len()..)
            .is_some_and(|rest| rest.starts_with(". "))
}

/// Number of numbered list items among `lines`.
fn numbered_items(lines: &[(usize, String)]) -> usize {
    lines.iter().filter(|(_, line)| is_numbered(line)).count()
}

/// Whether a line is a bullet list item (`- `).
fn is_bullet(line: &str) -> bool {
    line.trim_start().starts_with("- ")
}

/// Number of bullet list items among `lines`.
fn bullets(lines: &[(usize, String)]) -> usize {
    lines.iter().filter(|(_, line)| is_bullet(line)).count()
}

/// Shape of a criterion id: two numeric parts and a numeric third part, no `x`.
fn criterion_id(cell: &str) -> Option<String> {
    let id = plain(cell);
    let mut parts = id.split('.');
    let first = parts.next()?;
    let second = parts.next()?;
    let third = parts.next()?;
    if parts.next().is_some() {
        return None;
    }
    let valid =
        |part: &str| (1..=2).contains(&part.len()) && part.chars().all(|c| c.is_ascii_digit());
    (valid(first) && valid(second) && valid(third)).then_some(id)
}

/// Shape of a checklist slug: lowercase words and digits joined by single hyphens.
fn slug_shape(slug: &str) -> bool {
    Regex::new(r"^[a-z0-9]+(-[a-z0-9]+)*$").is_ok_and(|re| re.is_match(slug))
}

/// The reason of an owner cell of the form `not applicable: <reason>`.
fn not_applicable_reason(cell: &str) -> Option<String> {
    let (prefix, rest) = cell.split_once(':')?;
    prefix
        .trim()
        .eq_ignore_ascii_case("not applicable")
        .then(|| rest.trim().to_owned())
}

/// The pattern name of an owner cell of the form `page pattern: <name>`.
fn page_pattern_name(cell: &str) -> Option<String> {
    let (prefix, rest) = cell.split_once(':')?;
    prefix
        .trim()
        .eq_ignore_ascii_case("page pattern")
        .then(|| rest.trim().to_owned())
}

/// Parse and validate `docs/UX/wcag22-criteria.toml`.
///
/// The stored list is the reference the mapping is checked against, so this parser is strict: a source
/// URL on `w3.org/TR/WCAG22`, an access date, unique ids of the standard shape, a title, and a level of
/// `A` or `AA`.
fn parse_criteria(text: &str) -> Result<BTreeMap<String, Criterion>, String> {
    let raw: CriteriaFile = toml::from_str(text)
        .map_err(|e| format!("the stored criterion list is not valid TOML: {e}"))?;
    if !raw
        .source
        .trim()
        .starts_with("https://www.w3.org/TR/WCAG22")
    {
        return Err(format!(
            "the stored criterion list must cite https://www.w3.org/TR/WCAG22/ as its source, not `{}`",
            raw.source.trim()
        ));
    }
    let date = Regex::new(r"^\d{4}-\d{2}-\d{2}$").map_err(|e| e.to_string())?;
    if !date.is_match(raw.accessed.trim()) {
        return Err(format!(
            "the stored criterion list needs an access date in YYYY-MM-DD form, not `{}`",
            raw.accessed.trim()
        ));
    }
    if raw.criteria.is_empty() {
        return Err("the stored criterion list has no [[criteria]] rows".to_owned());
    }
    if !text.contains("UNVERIFIED(") {
        return Err(
            "the stored criterion list must carry an `UNVERIFIED(...)` provenance marker in its header, because the transcription has not been independently reviewed (T-0022 A1)"
                .to_owned(),
        );
    }
    let mut out = BTreeMap::new();
    for row in raw.criteria {
        let Some(id) = criterion_id(&row.id) else {
            return Err(format!(
                "`{}` is not a WCAG success criterion id of the form 1.4.3",
                row.id.trim()
            ));
        };
        let title = row.title.trim();
        if title.is_empty() || title.eq_ignore_ascii_case(&id) {
            return Err(format!("the criterion {id} has no title"));
        }
        let level = row.level.trim();
        if level != "A" && level != "AA" {
            return Err(format!(
                "the criterion {id} has level `{level}`; the stored list holds level A and AA only"
            ));
        }
        if out.contains_key(&id) {
            return Err(format!(
                "the criterion {id} appears more than once in the stored list"
            ));
        }
        out.insert(
            id,
            Criterion {
                title: title.to_owned(),
                level: level.to_owned(),
            },
        );
    }
    Ok(out)
}

/// The `## Critical flows` table as flows, with its findings.
fn flows_findings(doc: &str, journeys: &BTreeMap<String, String>) -> (Vec<Flow>, Vec<Finding>) {
    let mut out = Vec::new();
    if section_body(doc, FLOWS).is_none() {
        return (Vec::new(), out);
    }
    let Some((header, rows)) = section_table(doc, FLOWS) else {
        out.push(at(
            ACCESSIBILITY,
            "the `## Critical flows` section has no table (T-0022 A2)",
        ));
        return (Vec::new(), out);
    };
    let (Some(id_column), Some(name_column), Some(slug_column), Some(why_column)) = (
        column(&header, "Flow id"),
        column(&header, "Flow name"),
        column(&header, "Checklist slug"),
        column(&header, "Why critical"),
    ) else {
        out.push(at(
            ACCESSIBILITY,
            "the `## Critical flows` table needs the columns `Flow id`, `Flow name`, `Checklist slug` and `Why critical` (T-0022 A2)",
        ));
        return (Vec::new(), out);
    };
    let id_shape = Regex::new(r"^J-\d{2}$").ok();
    let mut flows = Vec::new();
    let mut ids = BTreeSet::new();
    let mut slugs = BTreeSet::new();
    for (line, row) in rows {
        let id = row
            .get(id_column)
            .map(|cell| plain(cell))
            .unwrap_or_default();
        let name = row
            .get(name_column)
            .map(|cell| plain(cell))
            .unwrap_or_default();
        let slug = row
            .get(slug_column)
            .map(|cell| plain(cell))
            .unwrap_or_default();
        let why = row
            .get(why_column)
            .map(|cell| plain(cell))
            .unwrap_or_default();
        let loc = format!("{ACCESSIBILITY}:{line}");
        let Some(expected) = journeys.get(&id) else {
            out.push(at(
                loc.as_str(),
                format!("`{id}` is not a journey of spec B3 (T-0022 A2)"),
            ));
            continue;
        };
        let id_ok = id_shape.as_ref().is_some_and(|re| re.is_match(&id));
        if !id_ok {
            out.push(at(
                loc.as_str(),
                format!("`{id}` is not a journey id of the form J-02 (T-0022 A2)"),
            ));
            continue;
        }
        if name != *expected {
            out.push(at(
                loc.as_str(),
                format!(
                    "the flow name `{name}` does not match the title of {id} in spec B3, which is `{expected}` (T-0022 A2)"
                ),
            ));
        }
        if !slug_shape(&slug) {
            out.push(at(
                loc.as_str(),
                format!("`{slug}` is not a checklist slug of lowercase words joined by hyphens"),
            ));
        }
        if !slugs.insert(slug.clone()) {
            out.push(at(
                loc.as_str(),
                format!("the checklist slug `{slug}` is used more than once (T-0022 A2)"),
            ));
        }
        if why.is_empty() {
            out.push(at(
                loc.as_str(),
                format!("the flow {id} has an empty `Why critical` cell (T-0022 A2)"),
            ));
        }
        if !ids.insert(id.clone()) {
            out.push(at(
                loc.as_str(),
                format!("the flow {id} is named more than once (T-0022 A2)"),
            ));
        }
        if id_ok && !slug.is_empty() {
            flows.push(Flow { id, name, slug });
        }
    }
    if flows.len() != FLOW_COUNT {
        out.push(at(
            ACCESSIBILITY,
            format!(
                "the `## Critical flows` table names {} flows; T-0022 A2 requires exactly {FLOW_COUNT}",
                flows.len()
            ),
        ));
    }
    (flows, out)
}

/// The declared page patterns and the findings of the `### Page patterns` table.
fn page_patterns_findings(
    doc: &str,
    components: &BTreeSet<String>,
) -> (BTreeSet<String>, Vec<Finding>) {
    let mut declared = BTreeSet::new();
    let mut out = Vec::new();
    let Some(body) = subsection_body(doc, "Criterion mapping", "Page patterns") else {
        return (declared, out);
    };
    let mut header = None;
    for (_, line) in &body {
        let Some(row) = cells(line) else { continue };
        let separator = row
            .iter()
            .all(|cell| !cell.is_empty() && cell.chars().all(|ch| ch == '-' || ch == ':'));
        if separator {
            continue;
        }
        header = Some(row);
        break;
    }
    let Some(header) = header else {
        out.push(at(
            format!("{ACCESSIBILITY}: page patterns"),
            "the `### Page patterns` subsection has no table (T-0022 A1)",
        ));
        return (declared, out);
    };
    let (Some(_pattern_column), Some(_encodes_column), Some(components_column)) = (
        column(&header, "Pattern"),
        column(&header, "What it encodes"),
        column(&header, "Components"),
    ) else {
        out.push(at(
            format!("{ACCESSIBILITY}: page patterns"),
            "the `### Page patterns` table needs the columns `Pattern`, `What it encodes` and `Components` (T-0022 A1)",
        ));
        return (declared, out);
    };
    let rows = table_rows(&body);
    if rows.is_empty() {
        out.push(at(
            format!("{ACCESSIBILITY}: page patterns"),
            "the `### Page patterns` table has no rows (T-0022 A1)",
        ));
    }
    for (line, row) in rows {
        let loc = format!("{ACCESSIBILITY}:{line}");
        let name = row.first().map(|cell| plain(cell)).unwrap_or_default();
        if name.is_empty() {
            out.push(at(
                loc.as_str(),
                "a page-pattern row has an empty `Pattern` cell",
            ));
            continue;
        }
        let components_cell = row.get(components_column).map(String::as_str).unwrap_or("");
        if !components
            .iter()
            .any(|component| has_token(components_cell, component))
        {
            out.push(at(
                loc.as_str(),
                format!(
                    "the page pattern \"{name}\" names no B11.8 component in its `Components` cell `{components_cell}` (T-0022 A1)"
                ),
            ));
        }
        if !declared.insert(name.clone()) {
            out.push(at(
                loc.as_str(),
                format!("the page pattern \"{name}\" is declared more than once (T-0022 A1)"),
            ));
        }
    }
    (declared, out)
}

/// Rule T-0022 steps 1 to 8: the eight sections exist and each has a body.
fn sections_findings(doc: &str) -> Vec<Finding> {
    let mut out = Vec::new();
    for title in SECTIONS {
        match section_body(doc, title) {
            None => out.push(at(
                ACCESSIBILITY,
                format!("no `## {title}` section exists (T-0022 step 1 to 8)"),
            )),
            Some(body) if body.iter().all(|(_, line)| line.trim().is_empty()) => out.push(at(
                ACCESSIBILITY,
                format!("the `## {title}` section has an empty body (T-0022 step 1 to 8)"),
            )),
            Some(_) => {}
        }
    }
    out
}

/// Rule T-0022 step 1 and A1: the mapping covers every stored criterion exactly once.
fn mapping_findings(
    doc: &str,
    criteria: &BTreeMap<String, Criterion>,
    components: &BTreeSet<String>,
    patterns: &BTreeSet<String>,
) -> Vec<Finding> {
    let mut out = Vec::new();
    let Some(body) = section_body(doc, "Criterion mapping") else {
        return out;
    };
    if !has_token(&body_text(&body), "B11.11") {
        out.push(at(
            ACCESSIBILITY,
            "the `## Criterion mapping` section does not say that it extends the B11.11 accessibility contract (T-0022 step 1)",
        ));
    }
    let Some((header, rows)) = section_table(doc, "Criterion mapping") else {
        out.push(at(
            ACCESSIBILITY,
            "the `## Criterion mapping` section has no table (T-0022 step 1, A1)",
        ));
        return out;
    };
    let (Some(criterion_column), Some(level_column), Some(title_column), Some(owner_column)) = (
        column(&header, "Criterion"),
        column(&header, "Level"),
        column(&header, "Title"),
        column(&header, "Owner"),
    ) else {
        out.push(at(
            ACCESSIBILITY,
            "the `## Criterion mapping` table needs the columns `Criterion`, `Level`, `Title` and `Owner` (T-0022 A1)",
        ));
        return out;
    };
    let mut seen = BTreeMap::new();
    for (line, row) in rows {
        let loc = format!("{ACCESSIBILITY}:{line}");
        let cell = row.get(criterion_column).map(String::as_str).unwrap_or("");
        let Some(id) = criterion_id(cell) else {
            out.push(at(
                loc.as_str(),
                format!(
                    "`{}` is not a WCAG success criterion id of the form 1.4.3 (T-0022 A1)",
                    plain(cell)
                ),
            ));
            continue;
        };
        if let Some(previous) = seen.insert(id.clone(), line) {
            out.push(at(
                loc.as_str(),
                format!(
                    "the criterion {id} appears more than once in the mapping (lines {previous} and {line}); every criterion needs exactly one row (T-0022 A1)"
                ),
            ));
            continue;
        }
        let Some(criterion) = criteria.get(&id) else {
            out.push(at(
                loc.as_str(),
                format!(
                    "the criterion {id} is not in docs/UX/wcag22-criteria.toml, so the stored list is not the authority for this row (T-0022 A1)"
                ),
            ));
            continue;
        };
        let level = row
            .get(level_column)
            .map(|value| plain(value))
            .unwrap_or_default();
        if !level.eq_ignore_ascii_case(&criterion.level) {
            out.push(at(
                loc.as_str(),
                format!(
                    "the level `{level}` of {id} does not match the stored level `{}` (T-0022 A1)",
                    criterion.level
                ),
            ));
        }
        let title = row
            .get(title_column)
            .map(|value| plain(value))
            .unwrap_or_default();
        if title != criterion.title {
            out.push(at(
                loc.as_str(),
                format!(
                    "the title `{title}` of {id} does not match the stored title `{}` (T-0022 A1)",
                    criterion.title
                ),
            ));
        }
        let owner = row.get(owner_column).map(String::as_str).unwrap_or("");
        if let Some(reason) = not_applicable_reason(owner) {
            if reason.split_whitespace().count() < 3 {
                out.push(at(
                    loc.as_str(),
                    format!(
                        "the `not applicable` owner of {id} needs a real reason of at least three words, not `{reason}` (T-0022 A1)"
                    ),
                ));
            }
        } else if let Some(pattern) = page_pattern_name(owner) {
            if pattern.is_empty() || !patterns.contains(&pattern) {
                out.push(at(
                    loc.as_str(),
                    format!(
                        "the page pattern `{pattern}` named by {id} is not declared in the `### Page patterns` table (T-0022 A1)"
                    ),
                ));
            }
        } else if !components
            .iter()
            .any(|component| has_token(owner, component))
        {
            out.push(at(
                loc.as_str(),
                format!(
                    "the owner `{}` of {id} names no B11.8 component, no declared page pattern and no `not applicable: <reason>` (T-0022 A1)",
                    plain(owner)
                ),
            ));
        }
    }
    for (id, criterion) in criteria {
        if !seen.contains_key(id) {
            out.push(at(
                ACCESSIBILITY,
                format!(
                    "the criterion {id} ({}) is missing from the `## Criterion mapping` table (T-0022 A1)",
                    criterion.title
                ),
            ));
        }
    }
    out
}

/// Rule T-0022 A2: cited screen and journey ids exist in the master specification.
fn identifier_findings(
    doc: &str,
    screens: &BTreeSet<String>,
    journeys: &BTreeMap<String, String>,
) -> Vec<Finding> {
    let mut out = Vec::new();
    for token in screen_ids_in(doc) {
        if !screens.contains(&token) {
            out.push(at(
                ACCESSIBILITY,
                format!(
                    "`{token}` is not a screen of the spec B12.1 screen table (T-0022 A2: no invented screen ids)"
                ),
            ));
        }
    }
    for token in tokens_in(doc, r"J-\d+") {
        if !journeys.contains_key(&token) {
            out.push(at(
                ACCESSIBILITY,
                format!(
                    "`{token}` is not a journey of spec B3 (T-0022 A2: the 12 flows must be real journeys)"
                ),
            ));
        }
    }
    out
}

/// Rule T-0022 step 2: the AT and browser matrix covers every named modality.
fn matrix_findings(doc: &str) -> Vec<Finding> {
    let mut out = Vec::new();
    if section_body(doc, "Assistive technology and browser matrix").is_none() {
        return out;
    }
    let Some((_header, rows)) = section_table(doc, "Assistive technology and browser matrix")
    else {
        out.push(at(
            ACCESSIBILITY,
            "the `## Assistive technology and browser matrix` section has no table (T-0022 step 2)",
        ));
        return out;
    };
    for modality in MATRIX_MODALITIES {
        let found = rows
            .iter()
            .any(|(_, row)| row.first().is_some_and(|cell| has_token(cell, modality)));
        if !found {
            out.push(at(
                ACCESSIBILITY,
                format!(
                    "the `## Assistive technology and browser matrix` has no `{modality}` row (T-0022 step 2)"
                ),
            ));
        }
    }
    for (line, row) in &rows {
        let first = row.first().map(String::as_str).unwrap_or("");
        if has_token(first, "JAWS") {
            let coverage = row.get(1).map(String::as_str).unwrap_or("");
            if !has_token(coverage, "if available") {
                out.push(at(
                    format!("{ACCESSIBILITY}:{line}"),
                    "the JAWS row must say `if available` in its `Coverage` cell (T-0022 step 2)",
                ));
            }
        }
    }
    out
}

/// Rule T-0022 step 3: the automated checks are the ones the task names.
fn automated_findings(doc: &str) -> Vec<Finding> {
    let Some(body) = section_body(doc, "Automated checks") else {
        return Vec::new();
    };
    let text = body_text(&body);
    let mut out = Vec::new();
    let required: [(&str, &str); 9] = [
        ("axe-core", "the axe-core oracle"),
        ("CDP", "the CDP test run"),
        ("zero", "the zero-violation rule"),
        ("serious", "the serious impact level"),
        ("critical", "the critical impact level"),
        ("contrast", "the colour-contrast token check"),
        ("heading", "the heading-structure check"),
        ("landmark", "the landmark check"),
        ("label", "the form-label check"),
    ];
    for (token, what) in required {
        if !has_token(&text, token) {
            out.push(at(
                ACCESSIBILITY,
                format!(
                    "the `## Automated checks` section does not name {what} (`{token}`) (T-0022 step 3)"
                ),
            ));
        }
    }
    if !has_any(&text, &["focus order", "focus-order"]) {
        out.push(at(
            ACCESSIBILITY,
            "the `## Automated checks` section does not name the focus-order recording (T-0022 step 3)",
        ));
    }
    out
}

/// Rule T-0022 step 4: the manual checks are the ones the task names.
fn manual_findings(doc: &str) -> Vec<Finding> {
    let Some(body) = section_body(doc, "Manual checks") else {
        return Vec::new();
    };
    let text = body_text(&body);
    let mut out = Vec::new();
    let required: [(&[&str], &str); 5] = [
        (
            &["keyboard walkthrough", "keyboard walkthroughs"],
            "the keyboard walkthrough scripts",
        ),
        (
            &["screen reader", "screen-reader"],
            "the screen-reader checklists",
        ),
        (&["checklist", "checklists"], "the checklist files"),
        (&["zoom"], "the zoom checks"),
        (&["reflow"], "the reflow checks"),
    ];
    for (tokens, what) in required {
        if !has_any(&text, tokens) {
            out.push(at(
                ACCESSIBILITY,
                format!("the `## Manual checks` section does not name {what} (T-0022 step 4)"),
            ));
        }
    }
    if !has_token(&text, "12") {
        out.push(at(
            ACCESSIBILITY,
            "the `## Manual checks` section does not name the 12 screen-reader checklists (T-0022 step 4, A2)",
        ));
    }
    out
}

/// Rule T-0022 step 5 and A3: the severity scheme and the AC-40 gate rule are explicit.
fn severity_findings(doc: &str) -> Vec<Finding> {
    let Some(body) = section_body(doc, "Severity and gate rule") else {
        return Vec::new();
    };
    let text = body_text(&body);
    let mut out = Vec::new();
    if !has_token(&text, "AC-40") {
        out.push(at(
            ACCESSIBILITY,
            "the `## Severity and gate rule` section does not name AC-40 (T-0022 step 5)",
        ));
    }
    if !(has_token(&text, "serious")
        && has_any(&text, &["block", "blocks", "blocking", "blocked"])
        && has_token(&text, "gate"))
    {
        out.push(at(
            ACCESSIBILITY,
            "the `## Severity and gate rule` section must state that a serious issue blocks a gate (T-0022 step 5, A3)",
        ));
    }
    let Some((header, rows)) = section_table(doc, "Severity and gate rule") else {
        out.push(at(
            ACCESSIBILITY,
            "the `## Severity and gate rule` section has no severity table (T-0022 step 5, A3)",
        ));
        return out;
    };
    let (Some(severity_column), Some(definition_column), Some(gate_column)) = (
        column(&header, "Severity"),
        column(&header, "Definition"),
        column(&header, "Gate effect"),
    ) else {
        out.push(at(
            ACCESSIBILITY,
            "the severity table needs the columns `Severity`, `Definition` and `Gate effect` (T-0022 step 5, A3)",
        ));
        return out;
    };
    if !normalized(&text)
        .to_lowercase()
        .contains("evaluated in this order")
    {
        out.push(at(
            ACCESSIBILITY,
            "the `## Severity and gate rule` section does not state the precedence: the four inputs are evaluated in this order (T-0022 step 5, F-25)",
        ));
    }
    if !has_token(&text, "always Serious") {
        out.push(at(
            ACCESSIBILITY,
            "the `## Severity and gate rule` section must state that a WCAG 2.2 A or AA criterion failure is always Serious (T-0022 step 5, F-25)",
        ));
    }
    if numbered_items(&body) < 4 {
        out.push(at(
            ACCESSIBILITY,
            "the `## Severity and gate rule` section needs the precedence as at least four numbered rules (T-0022 step 5, F-25)",
        ));
    }
    for severity in SEVERITIES {
        let Some((line, row)) = rows.iter().find(|(_, row)| {
            row.get(severity_column)
                .is_some_and(|cell| cell.trim().eq_ignore_ascii_case(severity))
        }) else {
            out.push(at(
                ACCESSIBILITY,
                format!("the severity scheme has no `{severity}` row (T-0022 step 5, A3)"),
            ));
            continue;
        };
        let loc = format!("{ACCESSIBILITY}:{line}");
        let gate = row.get(gate_column).map(|cell| cell.trim()).unwrap_or("");
        if gate.is_empty() {
            out.push(at(
                loc.as_str(),
                format!("the `{severity}` row has an empty `Gate effect` cell (T-0022 step 5, A3)"),
            ));
        }
        let definition = row
            .get(definition_column)
            .map(|cell| normalized(cell).to_lowercase())
            .unwrap_or_default();
        let gate_lower = normalized(gate).to_lowercase();
        let blocking = gate_lower.contains("block") && !gate_lower.contains("does not block");
        match severity {
            "Critical" | "Serious" => {
                if gate.is_empty() || !blocking {
                    out.push(at(
                        loc.as_str(),
                        format!(
                            "the `{severity}` row must state that it blocks the gate; the two grading rows cannot point in opposite directions (T-0022 step 5, F-25)"
                        ),
                    ));
                }
            }
            _ => {
                if !gate_lower.contains("does not block") {
                    out.push(at(
                        loc.as_str(),
                        format!(
                            "the `{severity}` row must state that it does not block the gate, because a criterion failure is always Serious (T-0022 step 5, F-25)"
                        ),
                    ));
                }
                if !definition.contains("no criterion failure") {
                    out.push(at(
                        loc.as_str(),
                        format!(
                            "the `{severity}` definition must say `no criterion failure`; a definition that allows a criterion failure overlaps Serious (T-0022 step 5, F-25)"
                        ),
                    ));
                }
            }
        }
        if severity == "Serious" && !definition.contains("criterion") {
            out.push(at(
                loc.as_str(),
                "the `Serious` definition does not name the WCAG criterion failure it grades (T-0022 step 5, F-25)",
            ));
        }
    }
    out
}

/// Rule T-0022 step 6 and A5: the statement claims no more than was tested and lists the known gaps.
fn statement_findings(doc: &str) -> Vec<Finding> {
    let Some(body) = section_body(doc, "Accessibility statement") else {
        return Vec::new();
    };
    let text = body_text(&body);
    let mut out = Vec::new();
    for claim in ABSOLUTE_CLAIMS {
        if has_token(&text, claim) {
            out.push(at(
                ACCESSIBILITY,
                format!(
                    "the accessibility statement makes the untested conformance claim \"{claim}\" (T-0022 step 6, A5)"
                ),
            ));
        }
    }
    if !has_any(
        &text,
        &[
            "does not claim",
            "no conformance claim",
            "not a conformance claim",
        ],
    ) {
        out.push(at(
            ACCESSIBILITY,
            "the `## Accessibility statement` section must state what it does not claim (T-0022 step 6, A5)",
        ));
    }
    let Some(gaps) = subsection_body(doc, "Accessibility statement", "Known gaps") else {
        out.push(at(
            ACCESSIBILITY,
            "the `## Accessibility statement` section has no `### Known gaps` subsection (T-0022 step 6, A5)",
        ));
        return out;
    };
    let rows = table_rows(&gaps);
    if rows.len() < 3 {
        out.push(at(
            ACCESSIBILITY,
            "the `### Known gaps` table must list at least three gaps (T-0022 step 6, A5)",
        ));
    }
    for (line, row) in rows {
        let cells = row.iter().take(2).collect::<Vec<_>>();
        if cells.len() < 2 || cells.iter().any(|cell| cell.trim().is_empty()) {
            out.push(at(
                format!("{ACCESSIBILITY}:{line}"),
                "a `### Known gaps` row has an empty gap or impact cell (T-0022 step 6, A5)",
            ));
        }
    }
    out
}

/// Rule T-0022 step 7 and A4: `human_step_pending` carries an owner and exact instructions.
fn human_steps_findings(doc: &str) -> Vec<Finding> {
    let Some(body) = section_body(doc, "Human steps") else {
        return Vec::new();
    };
    let text = body_text(&body);
    let mut out = Vec::new();
    if !has_token(&text, "human_step_pending") {
        out.push(at(
            ACCESSIBILITY,
            "the `## Human steps` section does not record the work as `human_step_pending` (T-0022 step 7, A4)",
        ));
    }
    if !body
        .iter()
        .any(|(_, line)| line.trim_start().starts_with("Owner:"))
    {
        out.push(at(
            ACCESSIBILITY,
            "the `## Human steps` section needs an `Owner:` line naming who runs the check (T-0022 step 7, A4)",
        ));
    }
    if numbered_items(&body) < 3 {
        out.push(at(
            ACCESSIBILITY,
            "the `## Human steps` section needs at least three numbered instructions (T-0022 step 7, A4)",
        ));
    }
    if !has_token(&text, "acceptance-ui") {
        out.push(at(
            ACCESSIBILITY,
            "the `## Human steps` section must say where the record is stored in `acceptance-ui/` (T-0022 step 7, A4)",
        ));
    }
    out
}

/// Rule T-0022 step 8: the regression strategy names `acceptance-ui/` and the baseline tasks.
fn regression_findings(doc: &str) -> Vec<Finding> {
    let Some(body) = section_body(doc, "Regression strategy") else {
        return Vec::new();
    };
    let text = body_text(&body);
    let mut out = Vec::new();
    for (token, what) in [
        ("acceptance-ui", "the `acceptance-ui/` artifact directory"),
        ("T-0052", "the T-0052 component baselines"),
        ("T-0090", "the T-0090 visual baselines"),
    ] {
        if !has_token(&text, token) {
            out.push(at(
                ACCESSIBILITY,
                format!(
                    "the `## Regression strategy` section does not name {what} (`{token}`) (T-0022 step 8)"
                ),
            ));
        }
    }
    if !has_any(&text, &["per screen", "per-screen"]) {
        out.push(at(
            ACCESSIBILITY,
            "the `## Regression strategy` section does not say that results are stored per screen (T-0022 step 8)",
        ));
    }
    if !has_token(&text, "stable") {
        out.push(at(
            ACCESSIBILITY,
            "the `## Regression strategy` section does not name the stable result naming (T-0022 step 8)",
        ));
    }
    out
}

/// The measured severity of a defect under the precedence scheme of T-0022 step 5 (F-25).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum Severity {
    /// A security control is unreachable or a critical flow cannot be finished.
    Critical,
    /// A WCAG 2.2 A or AA criterion fails, or axe reports a serious or critical violation.
    Serious,
    /// No criterion failure, but a best-practice issue blocks a non-critical task.
    Moderate,
    /// A best-practice issue with no criterion failure and no blocked task.
    Minor,
}

impl Severity {
    /// The severity name as the documents write it.
    fn name(self) -> &'static str {
        match self {
            Severity::Critical => "Critical",
            Severity::Serious => "Serious",
            Severity::Moderate => "Moderate",
            Severity::Minor => "Minor",
        }
    }

    /// The severity named by a table cell.
    fn parse(text: &str) -> Option<Severity> {
        match normalized(text).to_lowercase().as_str() {
            "critical" => Some(Severity::Critical),
            "serious" => Some(Severity::Serious),
            "moderate" => Some(Severity::Moderate),
            "minor" => Some(Severity::Minor),
            _ => None,
        }
    }
}

/// One axe-core impact level, as axe reports it, plus `None` for no violation (F-25).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum AxeImpact {
    /// No axe violation.
    None,
    /// axe impact `minor`.
    Minor,
    /// axe impact `moderate`.
    Moderate,
    /// axe impact `serious`.
    Serious,
    /// axe impact `critical`.
    Critical,
}

impl AxeImpact {
    /// The impact named by a table cell.
    fn parse(text: &str) -> Option<AxeImpact> {
        match normalized(text).to_lowercase().as_str() {
            "none" | "no violation" | "no" => Some(AxeImpact::None),
            "minor" => Some(AxeImpact::Minor),
            "moderate" => Some(AxeImpact::Moderate),
            "serious" => Some(AxeImpact::Serious),
            "critical" => Some(AxeImpact::Critical),
            _ => None,
        }
    }
}

/// The severity of a defect: the first matching rule of the precedence wins (F-25).
///
/// A criterion failure is always Serious; Moderate is reachable only when no criterion failed and axe reports a
/// moderate best-practice issue, so Serious and Moderate cannot both apply to one defect.
fn classify(
    criterion_failed: bool,
    critical_flow_blocked: bool,
    security_control_unreachable: bool,
    axe: AxeImpact,
) -> Severity {
    if security_control_unreachable || critical_flow_blocked {
        Severity::Critical
    } else if criterion_failed || axe >= AxeImpact::Serious {
        Severity::Serious
    } else if axe == AxeImpact::Moderate {
        Severity::Moderate
    } else {
        Severity::Minor
    }
}

/// Whole-token screen ids in `text`: `S-001` is not matched inside `ERR-SYS-001` (F-26).
///
/// A screen id is not preceded or followed by a letter, a digit, `_` or `-`, so an error code such as
/// `ERR-DNS-002` never yields `S-002`. That substring reading produced the failed review's screen counts.
fn screen_ids_in(text: &str) -> BTreeSet<String> {
    fn token_byte(byte: u8) -> bool {
        byte.is_ascii_alphanumeric() || byte == b'_' || byte == b'-'
    }
    let mut out = BTreeSet::new();
    let bytes = text.as_bytes();
    let mut index = 0;
    while index + 2 <= bytes.len() {
        let starts = matches!(bytes.get(index), Some(b'S') | Some(b's'))
            && bytes.get(index + 1) == Some(&b'-');
        if starts {
            let before_ok = match index
                .checked_sub(1)
                .and_then(|previous| bytes.get(previous))
            {
                Some(byte) => !token_byte(*byte),
                None => true,
            };
            let mut end = index + 2;
            while bytes.get(end).is_some_and(u8::is_ascii_digit) {
                end += 1;
            }
            let after_ok = match bytes.get(end) {
                Some(byte) => !token_byte(*byte),
                None => true,
            };
            if before_ok
                && after_ok
                && end > index + 2
                && let Some(digits) = text.get(index + 2..end)
            {
                out.insert(format!("S-{digits}"));
                index = end;
                continue;
            }
        }
        index += 1;
    }
    out
}

/// The screens of a journey: the unique ids in the `Screen` column of its `## Steps` table (F-26).
fn journey_screen_ids(text: &str) -> Result<BTreeSet<String>, String> {
    let Some((header, rows)) = section_table(text, "Steps") else {
        return Err("the journey has no `## Steps` table".to_owned());
    };
    let Some(screen_column) = column(&header, "Screen") else {
        return Err("the journey `## Steps` table has no `Screen` column".to_owned());
    };
    let mut out = BTreeSet::new();
    for (_, row) in rows {
        if let Some(cell) = row.get(screen_column) {
            out.extend(screen_ids_in(cell));
        }
    }
    if out.is_empty() {
        return Err(
            "the journey `## Steps` table names no screen in its `Screen` column".to_owned(),
        );
    }
    Ok(out)
}

/// Whether a cell is a `yes` or a `no` classifier input.
fn yes_no(cell: &str) -> Option<bool> {
    match normalized(cell).to_lowercase().as_str() {
        "yes" => Some(true),
        "no" => Some(false),
        _ => None,
    }
}

/// Whether every cell of a table row is a header separator (`---` or `:--`).
fn separator_row(row: &[String]) -> bool {
    !row.is_empty()
        && row
            .iter()
            .all(|cell| !cell.is_empty() && cell.chars().all(|ch| ch == '-' || ch == ':'))
}

/// A table: header cells and body rows with line numbers.
type TableRows = (Vec<String>, Vec<(usize, Vec<String>)>);

/// The first table in a subsection body: header cells and body rows with line numbers.
fn subsection_table(body: &[(usize, String)]) -> Option<TableRows> {
    let mut header: Option<Vec<String>> = None;
    let mut rows = Vec::new();
    for (line, text) in body {
        let Some(row) = cells(text) else { continue };
        if separator_row(&row) {
            continue;
        }
        match header {
            None => header = Some(row),
            Some(_) => rows.push((*line, row)),
        }
    }
    header.map(|header| (header, rows))
}

/// F-25: every row of the `### Severity examples` table is recomputed by [`classify`].
fn severity_example_findings(doc: &str) -> Vec<Finding> {
    let mut out = Vec::new();
    let Some(body) = subsection_body(doc, "Severity and gate rule", "Severity examples") else {
        out.push(at(
            ACCESSIBILITY,
            "the `## Severity and gate rule` section has no `### Severity examples` table of example defects (T-0022 step 5, F-25)",
        ));
        return out;
    };
    let Some((header, rows)) = subsection_table(&body) else {
        out.push(at(
            ACCESSIBILITY,
            "the `### Severity examples` subsection has no table (T-0022 step 5, F-25)",
        ));
        return out;
    };
    let (
        Some(defect_column),
        Some(criterion_column),
        Some(critical_column),
        Some(security_column),
        Some(impact_column),
        Some(severity_column),
    ) = (
        column(&header, "Defect"),
        column(&header, "Criterion failed"),
        column(&header, "Critical flow blocked"),
        column(&header, "Security control unreachable"),
        column(&header, "axe impact"),
        column(&header, "Severity"),
    )
    else {
        out.push(at(
            ACCESSIBILITY,
            "the `### Severity examples` table needs the columns `Defect`, `Criterion failed`, `Critical flow blocked`, `Security control unreachable`, `axe impact` and `Severity` (T-0022 step 5, F-25)",
        ));
        return out;
    };
    let mut seen = BTreeSet::new();
    for (line, row) in &rows {
        let loc = format!("{ACCESSIBILITY}:{line}");
        let defect = row
            .get(defect_column)
            .map(|cell| plain(cell))
            .unwrap_or_default();
        if defect.is_empty() {
            out.push(at(
                loc.as_str(),
                "an example defect has an empty `Defect` cell (T-0022 step 5, F-25)",
            ));
            continue;
        }
        let input = |column: usize, name: &str, out: &mut Vec<Finding>| -> Option<bool> {
            let cell = row.get(column).map(String::as_str).unwrap_or("");
            let value = yes_no(cell);
            if value.is_none() {
                out.push(at(
                    loc.as_str(),
                    format!(
                        "the `{name}` input of \"{defect}\" must be `yes` or `no`, not `{cell}` (T-0022 step 5, F-25)"
                    ),
                ));
            }
            value
        };
        let Some(criterion_failed) = input(criterion_column, "Criterion failed", &mut out) else {
            continue;
        };
        let Some(critical_blocked) = input(critical_column, "Critical flow blocked", &mut out)
        else {
            continue;
        };
        let Some(security_unreachable) =
            input(security_column, "Security control unreachable", &mut out)
        else {
            continue;
        };
        let impact_cell = row.get(impact_column).map(String::as_str).unwrap_or("");
        let Some(impact) = AxeImpact::parse(impact_cell) else {
            out.push(at(
                loc.as_str(),
                format!(
                    "the `axe impact` input of \"{defect}\" must be one of `critical`, `serious`, `moderate`, `minor` or `none`, not `{impact_cell}` (T-0022 step 5, F-25)"
                ),
            ));
            continue;
        };
        let severity_cell = row.get(severity_column).map(String::as_str).unwrap_or("");
        let Some(stated) = Severity::parse(severity_cell) else {
            out.push(at(
                loc.as_str(),
                format!(
                    "the `Severity` of \"{defect}\" must be one of the four severities, not `{severity_cell}` (T-0022 step 5, F-25)"
                ),
            ));
            continue;
        };
        seen.insert(stated);
        let computed = classify(
            criterion_failed,
            critical_blocked,
            security_unreachable,
            impact,
        );
        if computed != stated {
            out.push(at(
                loc.as_str(),
                format!(
                    "the example defect \"{defect}\" is graded `{}` but the precedence scheme returns `{}` from its four inputs (T-0022 step 5, F-25)",
                    stated.name(),
                    computed.name()
                ),
            ));
        }
    }
    if rows.len() < 6 {
        out.push(at(
            ACCESSIBILITY,
            format!(
                "the `### Severity examples` table has {} rows; at least six example defects are needed to show the precedence (T-0022 step 5, F-25)",
                rows.len()
            ),
        ));
    }
    for severity in [
        Severity::Critical,
        Severity::Serious,
        Severity::Moderate,
        Severity::Minor,
    ] {
        if !seen.contains(&severity) {
            out.push(at(
                ACCESSIBILITY,
                format!(
                    "the `### Severity examples` table has no `{}` example, so the scheme is not exercised for that grade (T-0022 step 5, F-25)",
                    severity.name()
                ),
            ));
        }
    }
    out
}

/// One `Outside the journey:` or `Screens not covered:` declaration line (F-26).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Declaration {
    /// A screen the checklist exercises that the journey does not list.
    Outside,
    /// A journey screen the checklist does not exercise.
    NotCovered,
}

/// One parsed declaration line of a checklist (F-26).
#[derive(Debug, Clone)]
struct DeclarationLine {
    /// 1-based line number.
    line: usize,
    /// Which declaration the line makes.
    kind: Declaration,
    /// The screen ids the line names.
    screens: BTreeSet<String>,
    /// The reason text after the screens.
    reason: String,
}

/// The marker of an `Outside the journey:` line (F-26).
const OUTSIDE_MARKER: &str = "outside the journey:";
/// The marker of a `Screens not covered:` line (F-26).
const NOT_COVERED_MARKER: &str = "screens not covered:";

/// The screens and the reason of a declaration line: `S-nnn, S-nnn - <reason>` (F-26).
///
/// Only the part before the first ` - `, ` — `, ` – ` or `: ` is read as screens, so a screen id that the
/// reason mentions is not mistaken for a declaration.
fn declaration_parts(rest: &str) -> (String, String) {
    for separator in [" - ", " — ", " – ", ": "] {
        if let Some((screens, reason)) = rest.split_once(separator) {
            return (screens.trim().to_owned(), reason.trim().to_owned());
        }
    }
    (rest.trim().to_owned(), String::new())
}

/// The declaration lines of a checklist (F-26).
fn declaration_lines(text: &str) -> Vec<DeclarationLine> {
    let mut out = Vec::new();
    for (index, line) in text.lines().enumerate() {
        let trimmed = line.trim_start();
        let lower = trimmed.to_lowercase();
        let (kind, rest) = if lower.starts_with(OUTSIDE_MARKER) {
            (Declaration::Outside, &trimmed[OUTSIDE_MARKER.len()..])
        } else if lower.starts_with(NOT_COVERED_MARKER) {
            (
                Declaration::NotCovered,
                &trimmed[NOT_COVERED_MARKER.len()..],
            )
        } else {
            continue;
        };
        let (screens_part, reason) = declaration_parts(rest);
        let reason = reason
            .trim_matches(|ch: char| ch.is_whitespace() || ch == '.' || ch == ';')
            .to_owned();
        out.push(DeclarationLine {
            line: index + 1,
            kind,
            screens: screen_ids_in(&screens_part),
            reason,
        });
    }
    out
}

/// The checklist text with the declaration lines removed, so a reason that cites a screen is not read as a
/// screen the checklist exercises (F-26).
fn text_without_declarations(text: &str) -> String {
    let mut out = String::new();
    for line in text.lines() {
        let lower = line.trim_start().to_lowercase();
        if lower.starts_with(OUTSIDE_MARKER) || lower.starts_with(NOT_COVERED_MARKER) {
            continue;
        }
        out.push_str(line);
        out.push('\n');
    }
    out
}

/// The screens of the checklist's `Screens:` line (F-26).
fn screens_line(text: &str) -> BTreeSet<String> {
    text.lines()
        .find(|line| line.trim_start().to_lowercase().starts_with("screens:"))
        .map(screen_ids_in)
        .unwrap_or_default()
}

/// F-26: a checklist's screens are the screens of its journey, plus documented declarations.
fn checklist_coverage_findings(
    files: &BTreeMap<String, String>,
    flows: &[Flow],
    journey_screens: &BTreeMap<String, BTreeSet<String>>,
) -> Vec<Finding> {
    let mut out = Vec::new();
    for flow in flows {
        let Some(text) = files.get(&flow.slug) else {
            continue;
        };
        let loc = format!("{CHECKLIST_DIR}/{}.md", flow.slug);
        let Some(journey) = journey_screens.get(&flow.id) else {
            out.push(at(
                loc.as_str(),
                format!(
                    "the journey {} has no readable `## Steps` table, so the checklist screen coverage cannot be checked (T-0022 A2, F-26)",
                    flow.id
                ),
            ));
            continue;
        };
        let declarations = declaration_lines(text);
        let mut outside = BTreeSet::new();
        let mut not_covered = BTreeSet::new();
        for declaration in &declarations {
            let at_line = format!("{CHECKLIST_DIR}/{}.md:{}", flow.slug, declaration.line);
            if declaration.screens.is_empty() {
                out.push(at(
                    at_line.as_str(),
                    format!(
                        "the `{}` declaration names no screen id (T-0022 A2, F-26)",
                        marker(declaration.kind)
                    ),
                ));
            }
            if declaration.reason.split_whitespace().count() < 3 {
                out.push(at(
                    at_line.as_str(),
                    format!(
                        "the `{}` declaration of {} needs a reason of at least three words after the screens (T-0022 A2, F-26)",
                        marker(declaration.kind),
                        declaration
                            .screens
                            .iter()
                            .cloned()
                            .collect::<Vec<_>>()
                            .join(", ")
                    ),
                ));
            }
            match declaration.kind {
                Declaration::Outside => {
                    for screen in &declaration.screens {
                        if journey.contains(screen) {
                            out.push(at(
                                at_line.as_str(),
                                format!(
                                    "`{screen}` is declared on an `Outside the journey:` line but the `## Steps` table of {} lists it; cover it in the checklist or remove the line (T-0022 A2, F-26)",
                                    flow.id
                                ),
                            ));
                        }
                    }
                    outside.extend(declaration.screens.iter().cloned());
                }
                Declaration::NotCovered => {
                    for screen in &declaration.screens {
                        if !journey.contains(screen) {
                            out.push(at(
                                at_line.as_str(),
                                format!(
                                    "`{screen}` is declared on a `Screens not covered:` line but it is not a screen of the `## Steps` table of {} (T-0022 A2, F-26)",
                                    flow.id
                                ),
                            ));
                        }
                    }
                    not_covered.extend(declaration.screens.iter().cloned());
                }
            }
        }
        let keyboard = section_body(text, "Keyboard path")
            .map(|body| body_text(&body))
            .unwrap_or_default();
        let script = section_body(text, "Screen-reader script")
            .map(|body| body_text(&body))
            .unwrap_or_default();
        let mut covered = screen_ids_in(&keyboard);
        covered.extend(screen_ids_in(&script));
        for screen in &outside {
            if !covered.contains(screen) {
                out.push(at(
                    loc.as_str(),
                    format!(
                        "`{screen}` is declared on an `Outside the journey:` line but the keyboard path and the screen-reader script do not exercise it; remove the line (T-0022 A2, F-26)"
                    ),
                ));
            }
        }
        for screen in screen_ids_in(&text_without_declarations(text)) {
            if !journey.contains(&screen) && !outside.contains(&screen) {
                out.push(at(
                    loc.as_str(),
                    format!(
                        "`{screen}` is not a screen of the `## Steps` table of {} and is not declared on an `Outside the journey:` line with a reason (T-0022 A2, F-26)",
                        flow.id
                    ),
                ));
            }
        }
        let declared = screens_line(text);
        if declared.is_empty() {
            out.push(at(
                loc.as_str(),
                "the checklist has no `Screens:` line listing the screens it exercises (T-0022 A2, F-26)",
            ));
        } else {
            for screen in journey {
                if !not_covered.contains(screen) && !declared.contains(screen) {
                    out.push(at(
                        loc.as_str(),
                        format!(
                            "the `Screens:` line does not list the journey screen {screen}; cover it or list it under `Screens not covered:` with a reason (T-0022 A2, F-26)"
                        ),
                    ));
                }
            }
            for screen in &declared {
                if not_covered.contains(screen) {
                    out.push(at(
                        loc.as_str(),
                        format!(
                            "the `Screens:` line lists `{screen}` but the checklist also lists it under `Screens not covered:` (T-0022 A2, F-26)"
                        ),
                    ));
                }
            }
        }
        for screen in journey {
            if !covered.contains(screen) && !not_covered.contains(screen) {
                out.push(at(
                    loc.as_str(),
                    format!(
                        "the journey screen {screen} is not covered by the keyboard path or the screen-reader script and is not listed under `Screens not covered:` with a reason (T-0022 A2, F-26)"
                    ),
                ));
            }
        }
    }
    out
}

/// The marker text of a declaration kind.
fn marker(kind: Declaration) -> &'static str {
    match kind {
        Declaration::Outside => "Outside the journey:",
        Declaration::NotCovered => "Screens not covered:",
    }
}

/// F-26: the strategy documents the checklist coverage rule the check enforces.
fn checklist_coverage_doc_findings(doc: &str) -> Vec<Finding> {
    let Some(body) = subsection_body(doc, "Manual checks", "Checklist screen coverage") else {
        return vec![at(
            ACCESSIBILITY,
            "the `## Manual checks` section has no `### Checklist screen coverage` subsection that documents the screen-coverage rule (T-0022 A2, F-26)",
        )];
    };
    let text = body_text(&body);
    let mut out = Vec::new();
    for (token, what) in [
        ("Screens:", "the `Screens:` line"),
        (OUTSIDE_MARKER, "the `Outside the journey:` line"),
        (NOT_COVERED_MARKER, "the `Screens not covered:` line"),
    ] {
        if !has_token(&text, token) {
            out.push(at(
                ACCESSIBILITY,
                format!(
                    "the `### Checklist screen coverage` subsection does not document {what} (T-0022 A2, F-26)"
                ),
            ));
        }
    }
    out
}

/// The journey screens of the repository at `root`, keyed by journey id.
fn read_journey_screens(root: &Path) -> (BTreeMap<String, BTreeSet<String>>, Vec<Finding>) {
    let mut out = BTreeMap::new();
    let mut findings = Vec::new();
    let dir = root.join(JOURNEY_DIR);
    if !dir.is_dir() {
        findings.push(at(
            JOURNEY_DIR,
            "the journey directory does not exist, so the checklist screen coverage cannot be checked (T-0022 A2, F-26)",
        ));
        return (out, findings);
    }
    for path in walk_files(&dir) {
        let Some(stem) = path.file_stem().and_then(|stem| stem.to_str()) else {
            continue;
        };
        let Some(number) = stem.strip_prefix("J-") else {
            continue;
        };
        if number.len() != 2 || !number.chars().all(|ch| ch.is_ascii_digit()) {
            continue;
        }
        let id = format!("J-{number}");
        let location = rel(root, &path);
        match read_text(&path) {
            Ok(text) => match journey_screen_ids(&text) {
                Ok(screens) => {
                    out.insert(id, screens);
                }
                Err(message) => findings.push(at(
                    location.as_str(),
                    format!(
                        "{message}, so the checklist screen coverage cannot be checked (T-0022 A2, F-26)"
                    ),
                )),
            },
            Err(error) => findings.push(at(location.as_str(), error.to_string())),
        }
    }
    (out, findings)
}

/// Rule T-0022 A2: the checklist directory holds exactly the 12 named flows.
fn checklist_set_findings(
    files: &BTreeMap<String, String>,
    flows: &[Flow],
    screens: &BTreeSet<String>,
) -> Vec<Finding> {
    let mut out = Vec::new();
    if flows.is_empty() {
        return out;
    }
    let mut expected = BTreeSet::new();
    for flow in flows {
        expected.insert(flow.slug.clone());
        match files.get(&flow.slug) {
            Some(text) => out.extend(checklist_findings(&flow.slug, text, flow, screens)),
            None => out.push(at(
                format!("{CHECKLIST_DIR}/{}.md", flow.slug),
                format!(
                    "the checklist for {} ({}) does not exist (T-0022 step 4, A2)",
                    flow.id, flow.name
                ),
            )),
        }
    }
    for slug in files.keys() {
        if !expected.contains(slug) {
            out.push(at(
                format!("{CHECKLIST_DIR}/{slug}.md"),
                "the file does not match any flow named in `## Critical flows` (T-0022 A2)",
            ));
        }
    }
    out
}

/// Rule T-0022 A2: one checklist has the required parts.
fn checklist_findings(
    slug: &str,
    text: &str,
    flow: &Flow,
    screens: &BTreeSet<String>,
) -> Vec<Finding> {
    let mut out = Vec::new();
    let loc = format!("{CHECKLIST_DIR}/{slug}.md");
    if !has_token(text, &flow.id) {
        out.push(at(
            loc.as_str(),
            format!(
                "the checklist does not name its flow {} (T-0022 A2)",
                flow.id
            ),
        ));
    }
    match section_body(text, "Keyboard path") {
        None => out.push(at(
            loc.as_str(),
            "no `## Keyboard path` section exists (T-0022 step 4)",
        )),
        Some(body) => {
            if numbered_items(&body) < 4 {
                out.push(at(
                    loc.as_str(),
                    "the keyboard path needs at least four numbered steps (T-0022 step 4)",
                ));
            }
            if !has_any(&body_text(&body), &["Tab", "Shift+Tab"]) {
                out.push(at(
                    loc.as_str(),
                    "the keyboard path must name the Tab key (T-0022 step 4)",
                ));
            }
        }
    }
    match section_body(text, "Screen-reader script") {
        None => out.push(at(
            loc.as_str(),
            "no `## Screen-reader script` section exists (T-0022 step 4)",
        )),
        Some(body) => {
            if table_rows(&body).len() < 3 {
                out.push(at(
                    loc.as_str(),
                    "the screen-reader script needs at least three rows of expected announcements (T-0022 step 4)",
                ));
            }
            let body = body_text(&body);
            if !has_any(&body, &["NVDA", "JAWS", "VoiceOver", "TalkBack"]) {
                out.push(at(
                    loc.as_str(),
                    "the screen-reader script must name a screen reader (T-0022 step 4)",
                ));
            }
            if !has_any(
                &body,
                &[
                    "announce",
                    "announces",
                    "announced",
                    "announcement",
                    "announcements",
                ],
            ) {
                out.push(at(
                    loc.as_str(),
                    "the screen-reader script must say what the screen reader announces (T-0022 step 4)",
                ));
            }
        }
    }
    match section_body(text, "Failure criteria") {
        None => out.push(at(
            loc.as_str(),
            "no `## Failure criteria` section exists (T-0022 step 4)",
        )),
        Some(body) => {
            if bullets(&body) < 3 {
                out.push(at(
                    loc.as_str(),
                    "the failure criteria need at least three bullets (T-0022 step 4)",
                ));
            }
            if !has_any(
                &body_text(&body),
                &["Critical", "Serious", "Moderate", "Minor"],
            ) {
                out.push(at(
                    loc.as_str(),
                    "each failure criterion needs a severity (T-0022 step 5)",
                ));
            }
        }
    }
    match section_body(text, "Human step") {
        None => out.push(at(
            loc.as_str(),
            "no `## Human step` section exists (T-0022 step 7, A4)",
        )),
        Some(body) => {
            let text = body_text(&body);
            if !has_token(&text, "human_step_pending") {
                out.push(at(
                    loc.as_str(),
                    "the checklist does not record the human step as `human_step_pending` (T-0022 step 7, A4)",
                ));
            }
            if !body
                .iter()
                .any(|(_, line)| line.trim_start().starts_with("Owner:"))
            {
                out.push(at(
                    loc.as_str(),
                    "the human step needs an `Owner:` line (T-0022 step 7, A4)",
                ));
            }
            if numbered_items(&body) < 2 {
                out.push(at(
                    loc.as_str(),
                    "the human step needs at least two numbered instructions (T-0022 step 7, A4)",
                ));
            }
            if !has_token(&text, "acceptance-ui") {
                out.push(at(
                    loc.as_str(),
                    "the human step must say where the record is stored in `acceptance-ui/` (T-0022 step 7, A4)",
                ));
            }
        }
    }
    for token in screen_ids_in(text) {
        if !screens.contains(&token) {
            out.push(at(
                loc.as_str(),
                format!(
                    "`{token}` is not a screen of the spec B12.1 screen table (T-0022 A2: no invented screen ids)"
                ),
            ));
        }
    }
    out
}

/// Every document rule over one accessibility strategy, its checklist files and the spec inventories.
fn document_findings(
    doc: &str,
    criteria: &BTreeMap<String, Criterion>,
    checklists: &BTreeMap<String, String>,
    components: &BTreeSet<String>,
    screens: &BTreeSet<String>,
    journeys: &BTreeMap<String, String>,
    journey_screens: &BTreeMap<String, BTreeSet<String>>,
) -> Vec<Finding> {
    let (patterns, mut out) = page_patterns_findings(doc, components);
    out.extend(sections_findings(doc));
    out.extend(mapping_findings(doc, criteria, components, &patterns));
    out.extend(identifier_findings(doc, screens, journeys));
    out.extend(matrix_findings(doc));
    out.extend(automated_findings(doc));
    out.extend(manual_findings(doc));
    out.extend(checklist_coverage_doc_findings(doc));
    out.extend(severity_findings(doc));
    out.extend(severity_example_findings(doc));
    out.extend(statement_findings(doc));
    out.extend(human_steps_findings(doc));
    out.extend(regression_findings(doc));
    let (flows, flow_findings) = flows_findings(doc, journeys);
    out.extend(flow_findings);
    out.extend(checklist_set_findings(checklists, &flows, screens));
    out.extend(checklist_coverage_findings(
        checklists,
        &flows,
        journey_screens,
    ));
    out
}

/// Whole T-0022 check on the repository at `root`, reading the checksum-verified master specification.
pub fn check(root: &Path) -> Vec<Finding> {
    match crate::spec::load_master(root) {
        Ok(spec) => check_with_spec(root, &spec),
        Err(e) => vec![at(
            "docs/SPEC.md",
            format!("cannot read the master specification: {}", e.0),
        )],
    }
}

/// Whole T-0022 check on the repository at `root`, with the checksum-verified master specification text.
pub fn check_with_spec(root: &Path, spec: &str) -> Vec<Finding> {
    let mut out = Vec::new();
    let components = super::component_names(spec);
    if components.is_empty() {
        out.push(at(
            "docs/SPEC.md",
            "the B11.8 component inventory has no component rows, so the criterion owners cannot be checked",
        ));
    }
    let screens = super::screen_ids(spec);
    if screens.is_empty() {
        out.push(at(
            "docs/SPEC.md",
            "the B12.1 screen table has no screen rows, so cited screens cannot be checked",
        ));
    }
    let journeys = super::journey_headings(spec);
    if journeys.is_empty() {
        out.push(at(
            "docs/SPEC.md",
            "the B3 journeys cannot be read, so the critical flows cannot be checked",
        ));
    }
    let criteria = match read_text(&root.join(CRITERIA_FILE)) {
        Ok(text) => match parse_criteria(&text) {
            Ok(criteria) => Some(criteria),
            Err(message) => {
                out.push(at(CRITERIA_FILE, message));
                None
            }
        },
        Err(_) => {
            out.push(at(
                CRITERIA_FILE,
                "the stored WCAG 2.2 criterion list does not exist (T-0022 A1)",
            ));
            None
        }
    };
    let doc = match read_text(&root.join(ACCESSIBILITY)) {
        Ok(text) => Some(text),
        Err(_) => {
            out.push(at(
                ACCESSIBILITY,
                "the accessibility strategy does not exist (T-0022 step 1)",
            ));
            None
        }
    };
    let checklists = if root.join(CHECKLIST_DIR).is_dir() {
        let mut files = BTreeMap::new();
        for path in walk_files(&root.join(CHECKLIST_DIR)) {
            if !path
                .extension()
                .is_some_and(|e| e.eq_ignore_ascii_case("md"))
            {
                continue;
            }
            let Some(stem) = path.file_stem().and_then(|stem| stem.to_str()) else {
                continue;
            };
            match read_text(&path) {
                Ok(text) => {
                    files.insert(stem.to_owned(), text);
                }
                Err(e) => out.push(at(rel(root, &path), e.to_string())),
            }
        }
        files
    } else {
        out.push(at(
            CHECKLIST_DIR,
            "the checklist directory does not exist (T-0022 step 4)",
        ));
        BTreeMap::new()
    };
    let (journey_screens, journey_findings) = read_journey_screens(root);
    out.extend(journey_findings);
    if let (Some(criteria), Some(doc)) = (criteria, doc) {
        out.extend(document_findings(
            &doc,
            &criteria,
            &checklists,
            &components,
            &screens,
            &journeys,
            &journey_screens,
        ));
    }
    out
}

#[cfg(test)]
pub(crate) mod fixtures {
    //! Fixtures shared by the accessibility unit tests and the `ux-docs` fixture tree.
    //!
    //! [`documents`] returns the files the Lead writes into the temporary fixture repository, and
    //! [`spec_section`] returns the fixture-spec rows that the existing fixture does not already carry.
    //! The fixture spec already has a B11.11 table, a B11.8 component inventory, a B12.1 screen table and
    //! the B3 journey headings, so no extra spec rows are needed.

    use std::collections::BTreeMap;

    /// The stored fixture criteria: id, level, title and owner as the mapping row writes them.
    const MAPPING: [(&str, &str, &str, &str); 8] = [
        ("1.1.1", "A", "Non-text Content", "Avatar"),
        (
            "1.2.1",
            "A",
            "Audio-only and Video-only (Prerecorded)",
            "not applicable: the fixture product ships no audio or video",
        ),
        ("1.4.3", "AA", "Contrast (Minimum)", "Button / IconButton"),
        ("2.1.1", "A", "Keyboard", "Menu / Dropdown"),
        ("2.4.1", "A", "Bypass Blocks", "page pattern: App frame"),
        ("2.4.7", "AA", "Focus Visible", "Link"),
        (
            "3.3.4",
            "AA",
            "Error Prevention (Legal, Financial, Data)",
            "Modal / Drawer / ConfirmDialog",
        ),
        ("4.1.2", "A", "Name, Role, Value", "TextInput / Textarea"),
    ];

    /// The 12 fixture flows: journey id and the exact B3 title.
    pub(crate) const JOURNEYS: [(&str, &str); 12] = [
        ("J-01", "Visitor discovers HDD and reads honest claims"),
        ("J-02", "Visitor signs up and verifies email"),
        ("J-03", "New user enrolls MFA"),
        ("J-04", "Returning user logs in"),
        ("J-05", "User resets a forgotten password"),
        ("J-06", "User accepts a team invite"),
        ("J-07", "Owner completes the onboarding checklist"),
        (
            "J-08",
            "Owner adds a domain using full nameserver delegation",
        ),
        ("J-09", "Owner adds a domain using CNAME (partial) setup"),
        (
            "J-10",
            "Owner attaches an apex via A/ALIAS or only a subdomain",
        ),
        ("J-11", "Owner verifies ownership"),
        ("J-12", "Owner configures and tests the origin"),
    ];

    /// The screens of each fixture journey, as the Lead's fixture journeys write them in the `Screen`
    /// column of their `## Steps` table (`FIXTURE_JOURNEYS` in `ux_docs/tests.rs`).
    ///
    /// A checklist fixture must agree with the journey fixture the Lead writes into the same fixture tree
    /// (F-26); the Lead updates this table if the fixture journeys change.
    pub(crate) const JOURNEY_SCREENS: [(&str, &[&str]); 12] = [
        ("J-01", &["S-001", "S-003", "S-006", "S-020"]),
        ("J-02", &["S-020", "S-021", "S-022", "S-035"]),
        ("J-03", &["S-030", "S-031"]),
        ("J-04", &["S-023", "S-024", "S-026", "S-034"]),
        ("J-05", &["S-027", "S-028"]),
        ("J-06", &["S-020", "S-023", "S-029"]),
        ("J-07", &["S-035", "S-040"]),
        ("J-08", &["S-042", "S-043", "S-099"]),
        ("J-09", &["S-042", "S-043", "S-099"]),
        ("J-10", &["S-042"]),
        ("J-11", &["S-042"]),
        ("J-12", &["S-043", "S-052"]),
    ];

    /// The fixture journey screens keyed by journey id.
    pub(crate) fn journey_screens() -> BTreeMap<String, std::collections::BTreeSet<String>> {
        JOURNEY_SCREENS
            .iter()
            .map(|(id, screens)| {
                (
                    (*id).to_owned(),
                    screens.iter().map(|screen| (*screen).to_owned()).collect(),
                )
            })
            .collect()
    }

    /// The 12 fixture checklist slugs, in [`JOURNEYS`] order.
    const SLUGS: [&str; 12] = [
        "fixture-flow-01",
        "fixture-flow-02",
        "fixture-flow-03",
        "fixture-flow-04",
        "fixture-flow-05",
        "fixture-flow-06",
        "fixture-flow-07",
        "fixture-flow-08",
        "fixture-flow-09",
        "fixture-flow-10",
        "fixture-flow-11",
        "fixture-flow-12",
    ];

    /// The stored criterion list of the fixture tree.
    pub(crate) fn criteria_toml() -> String {
        String::from(
            r#"# Fixture WCAG 2.2 A/AA criterion list for the accessibility checks.
# UNVERIFIED(no independent review of the transcription): fixture data.
version = "2.2"
source = "https://www.w3.org/TR/WCAG22/"
accessed = "2026-10-20"

[[criteria]]
id = "1.1.1"
title = "Non-text Content"
level = "A"

[[criteria]]
id = "1.2.1"
title = "Audio-only and Video-only (Prerecorded)"
level = "A"

[[criteria]]
id = "1.4.3"
title = "Contrast (Minimum)"
level = "AA"

[[criteria]]
id = "2.1.1"
title = "Keyboard"
level = "A"

[[criteria]]
id = "2.4.1"
title = "Bypass Blocks"
level = "A"

[[criteria]]
id = "2.4.7"
title = "Focus Visible"
level = "AA"

[[criteria]]
id = "3.3.4"
title = "Error Prevention (Legal, Financial, Data)"
level = "AA"

[[criteria]]
id = "4.1.2"
title = "Name, Role, Value"
level = "A"
"#,
        )
    }

    /// A strategy document that satisfies every rule.
    pub(crate) fn accessibility_doc() -> String {
        let mut mapping = String::new();
        for (id, level, title, owner) in MAPPING {
            mapping.push_str(&format!("| {id} | {level} | {title} | {owner} |\n"));
        }
        let mut flows = String::new();
        for (index, (id, name)) in JOURNEYS.iter().enumerate() {
            if let Some(slug) = SLUGS.get(index) {
                flows.push_str(&format!("| {id} | {name} | {slug} | A fixture flow. |\n"));
            }
        }
        format!(
            r#"# Accessibility fixture

Status: fixture for the T-0022 checks. The stored list is in [wcag22-criteria.toml](wcag22-criteria.toml).

## Critical flows

| Flow id | Flow name | Checklist slug | Why critical |
| --- | --- | --- | --- |
{flows}
## Criterion mapping

This mapping extends B11.11 and names real B11.8 components.

| Criterion | Level | Title | Owner |
| --- | --- | --- | --- |
{mapping}
### Page patterns

| Pattern | What it encodes | Components |
| --- | --- | --- |
| App frame | The skip link and the landmark set. | Link; Breadcrumbs |

## Assistive technology and browser matrix

| Modality | Coverage | How tested | Owner |
| --- | --- | --- | --- |
| Chromium-based | current and previous | CDP tests | qa |
| Firefox | current and previous | manual | qa |
| Safari | current | manual | qa |
| NVDA | current | human step | ux |
| JAWS | if available | human step | ux |
| VoiceOver | current | human step | ux |
| TalkBack | current | human step | ux |
| Keyboard only | every flow | walkthrough | ux |
| 200% zoom | every screen | automated | qa |
| 400% zoom | every screen | automated | qa |
| High contrast | every screen | manual | ux |
| Forced colors | every screen | automated | qa |
| Reduced motion | every screen | automated | qa |

## Automated checks

The axe-core oracle runs in the CDP suite and must report zero serious or critical violations.
The contrast token check reads the B11.2 pairs, and the heading, landmark and form label checks run beside it.
A focus order recording compares the Tab order with the DOM order.

## Manual checks

A keyboard walkthrough script runs for every critical flow, and the 12 screen reader checklists live beside this document.
The zoom and reflow checks run at 200% and 400% zoom and at 320 CSS pixels.

### Checklist screen coverage

Each checklist declares the screens it exercises on its `Screens:` line, which must equal the `Screen` column of the
flow's journey `## Steps` table. An `Outside the journey: S-nnn - <reason>` line declares a screen the checklist
exercises but the journey does not list. A `Screens not covered: S-nnn - <reason>` line declares a journey screen the
checklist does not exercise.

## Severity and gate rule

The scheme is a function of four inputs, not a judgement call. The precedence is evaluated in this order:

1. A security control is unreachable: Critical.
2. A critical flow cannot be finished: Critical.
3. A WCAG 2.2 A or AA criterion fails: Serious.
4. axe reports a serious or critical violation: Serious.
5. axe reports a moderate best-practice issue with no criterion failure: Moderate.
6. Otherwise the issue is Minor.

A WCAG 2.2 A or AA criterion failure is always Serious.

| Severity | Definition | Gate effect |
| --- | --- | --- |
| Critical | A person cannot finish a critical flow, or a security control is unreachable. | Blocks the gate. |
| Serious | A criterion fails on a product surface, or axe reports a serious or critical violation. | Blocks the gate. |
| Moderate | There is no criterion failure and axe reports a moderate best-practice issue. | Does not block. |
| Minor | A best-practice issue with no criterion failure and no blocked task. | Does not block. |

A serious or critical issue blocks the gate under AC-40.

### Severity examples

Each row is an example defect; the check recomputes the last column from the four inputs.

| Defect | Criterion failed | Critical flow blocked | Security control unreachable | axe impact | Severity |
| --- | --- | --- | --- | --- | --- |
| The MFA code field refuses paste in J-04. | yes | yes | no | serious | Critical |
| The under-attack control cannot be reached with the keyboard. | yes | yes | yes | serious | Critical |
| A DNS table header button does not expose its sort state. | yes | no | no | serious | Serious |
| The body text contrast is 3.9 to 1 on the login page. | yes | no | no | serious | Serious |
| The audit filter panel skips a heading level. | yes | no | no | moderate | Serious |
| A toast covers the focused confirm button until it fades. | yes | no | no | moderate | Serious |
| A report landmark repeats a name but the task still completes. | no | no | no | moderate | Moderate |
| The chart legend order differs although direct labels are present. | no | no | no | none | Minor |

## Accessibility statement

This draft does not claim WCAG 2.2 conformance; it reports the tests that ran.

### Known gaps

| Gap | Impact | Status |
| --- | --- | --- |
| Screen reader runs are not recorded. | Manual coverage is unknown. | human_step_pending |
| The contrast token check is not implemented. | Token pairs are unverified. | Planned with T-0030. |
| JAWS needs a licence. | One combination is unrecorded. | If available. |

## Human steps

Owner: operator or volunteer (human_step_pending).

1. Pick a checklist and run it with the current screen reader release.
2. Record each checkpoint and save the note under `acceptance-ui/`.
3. Report the outcome so the gate records `human_step_pending` until it is done.

## Regression strategy

Results are stored per screen under `acceptance-ui/` with a stable name.
The component baselines arrive with T-0052 and the visual baselines with T-0090.
"#,
            flows = flows,
            mapping = mapping
        )
    }

    /// One checklist file that satisfies every checklist rule.
    ///
    /// The checklist exercises exactly the screens of its fixture journey (`Screens:` line, keyboard path and
    /// screen-reader script), which is the F-26 coverage rule.
    fn checklist(id: &str, slug: &str, screens: &[&str]) -> String {
        let mut keyboard = String::new();
        let steps = screens.len().max(4);
        for index in 0..steps {
            let screen = screens
                .get(index % screens.len())
                .copied()
                .unwrap_or("S-001");
            keyboard.push_str(&format!(
                "{}. On {screen}, Tab reaches the next control and Enter activates it.\n",
                index + 1
            ));
        }
        let mut script = String::new();
        let rows = screens.len().max(3);
        for index in 0..rows {
            let screen = screens
                .get(index % screens.len())
                .copied()
                .unwrap_or("S-001");
            script.push_str(&format!(
                "| {} | {screen} | The screen heading and the primary action. |\n",
                index + 1
            ));
        }
        let declared = screens.join(", ");
        format!(
            r#"# {id} fixture flow

Checklist `{slug}` for {id}.
Screens: {declared}.
Journey: [../journeys/{id}.md](../journeys/{id}.md). Strategy: [ACCESSIBILITY.md](../ACCESSIBILITY.md).

## Keyboard path

{keyboard}
## Screen-reader script

NVDA and VoiceOver announce the controls in this order.

| Step | Screen | Expected announcement |
| --- | --- | --- |
{script}
## Failure criteria

- Critical: the skip link is missing.
- Serious: the primary action is unreachable.
- Moderate: a heading level is skipped.

## Human step

Owner: human_step_pending - the operator runs this script for {id}.

1. Run the keyboard path with the current NVDA release.
2. Save the record under `acceptance-ui/` and report the result.
"#
        )
    }

    /// The 12 fixture checklist files, keyed by slug.
    pub(crate) fn checklist_files() -> BTreeMap<String, String> {
        let mut out = BTreeMap::new();
        for (index, (id, _name)) in JOURNEYS.iter().enumerate() {
            let Some(slug) = SLUGS.get(index) else {
                continue;
            };
            let screens = JOURNEY_SCREENS
                .iter()
                .find(|(journey, _)| journey == id)
                .map(|(_, screens)| *screens)
                .unwrap_or(&["S-001"]);
            out.insert((*slug).to_owned(), checklist(id, slug, screens));
        }
        out
    }

    /// The files the Lead writes into the fixture repository: path and text.
    pub(crate) fn documents() -> Vec<(String, String)> {
        let mut out = vec![
            ("docs/UX/wcag22-criteria.toml".to_owned(), criteria_toml()),
            ("docs/UX/ACCESSIBILITY.md".to_owned(), accessibility_doc()),
        ];
        for (slug, text) in checklist_files() {
            out.push((format!("docs/UX/a11y-checklists/{slug}.md"), text));
        }
        out
    }

    /// Fixture-spec rows beyond what the existing fixture specification already has.
    ///
    /// The existing fixture spec already carries a B11.11 table, the B11.8 components, the B12.1 screens and
    /// every B3 journey heading the fixture flows name, so nothing extra is needed.
    pub(crate) fn spec_section() -> String {
        String::new()
    }

    /// The fixture journeys as the spec reader returns them.
    pub(crate) fn journeys() -> BTreeMap<String, String> {
        JOURNEYS
            .iter()
            .map(|(id, name)| ((*id).to_owned(), (*name).to_owned()))
            .collect()
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used, clippy::unwrap_used, reason = "tests")]

    use std::collections::{BTreeMap, BTreeSet};

    use super::fixtures;
    use super::*;

    fn messages(findings: &[Finding]) -> String {
        findings
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>()
            .join("\n")
    }

    fn base() -> String {
        fixtures::accessibility_doc()
    }

    fn criteria() -> BTreeMap<String, Criterion> {
        parse_criteria(&fixtures::criteria_toml()).expect("the fixture criteria parse")
    }

    fn components() -> BTreeSet<String> {
        [
            "Avatar",
            "Button",
            "IconButton",
            "Link",
            "Breadcrumbs",
            "Menu",
            "Dropdown",
            "Modal",
            "Drawer",
            "ConfirmDialog",
            "TextInput",
            "Textarea",
            "DataTable",
            "FormField",
            "ErrorSummary",
        ]
        .into_iter()
        .map(str::to_owned)
        .collect()
    }

    fn patterns() -> BTreeSet<String> {
        page_patterns_findings(&base(), &components()).0
    }

    fn screens() -> BTreeSet<String> {
        let mut out: BTreeSet<String> = (1..=12).map(|n| format!("S-{n:03}")).collect();
        for screens in fixtures::journey_screens().values() {
            out.extend(screens.iter().cloned());
        }
        out
    }

    fn journeys() -> BTreeMap<String, String> {
        fixtures::journeys()
    }

    fn checklists() -> BTreeMap<String, String> {
        fixtures::checklist_files()
    }

    fn document_findings() -> Vec<Finding> {
        super::document_findings(
            &base(),
            &criteria(),
            &checklists(),
            &components(),
            &screens(),
            &journeys(),
            &journey_screens(),
        )
    }

    #[test]
    fn whole_token_matching_rejects_longer_words_and_ids() {
        assert!(has_token("the DataTable component", "DataTable"));
        assert!(!has_token("the DataTableOfDoom component", "DataTable"));
        assert!(!has_token("an IconButton control", "Button"));
        assert!(has_token("Button / IconButton", "Button"));
        assert!(!has_token("criterion 1.1.10", "1.1.1"));
        assert!(!has_token("flow J-021", "J-02"));
        assert!(has_token("run at 200% zoom", "200% zoom"));
        assert!(!has_token("run at 1200% zoom", "200% zoom"));
        assert!(has_token(
            "The zoom and reflow checks run at 200%",
            "reflow"
        ));
        assert!(has_any(
            "The zoom and reflow checks run at 200%",
            &["reflow"]
        ));
    }

    #[test]
    fn sections_require_all_eight_with_a_body() {
        assert!(sections_findings(&base()).is_empty());
        let missing = base().replace("## Regression strategy", "## Retrospective plan");
        let found = messages(&sections_findings(&missing));
        assert!(found.contains("Regression strategy"), "{found}");
        let empty = base().replace(
            "Results are stored per screen under `acceptance-ui/` with a stable name.\nThe component baselines arrive with T-0052 and the visual baselines with T-0090.\n",
            "",
        );
        let found = messages(&sections_findings(&empty));
        assert!(found.contains("Regression strategy"), "{found}");
    }

    #[test]
    fn mapping_names_the_b11_11_extension() {
        let bad = base().replace("extends B11.11", "extends the accessibility contract");
        let found = messages(&mapping_findings(
            &bad,
            &criteria(),
            &components(),
            &patterns(),
        ));
        assert!(found.contains("B11.11"), "{found}");
    }

    #[test]
    fn criteria_file_parses_the_fixture_list() {
        let parsed = criteria();
        assert_eq!(parsed.len(), 8);
        assert_eq!(parsed.get("1.4.3").map(|c| c.level.as_str()), Some("AA"));
        assert_eq!(
            parsed.get("1.1.1").map(|c| c.title.as_str()),
            Some("Non-text Content")
        );
    }

    #[test]
    fn criteria_file_requires_an_unverified_provenance_marker() {
        let unmarked =
            fixtures::criteria_toml().replace("UNVERIFIED(", "not independently reviewed (");
        let message = parse_criteria(&unmarked).expect_err("a list without the marker is rejected");
        assert!(message.contains("UNVERIFIED"), "{message}");
    }

    #[test]
    fn criteria_file_rejects_malformed_toml() {
        let bad = fixtures::criteria_toml().replace("[[criteria]]", "[[criteria");
        assert!(parse_criteria(&bad).is_err());
    }

    #[test]
    fn criteria_file_rejects_a_bad_id_level_source_and_duplicate() {
        let bad_id = fixtures::criteria_toml().replace("id = \"1.1.1\"", "id = \"1.1.x\"");
        assert!(parse_criteria(&bad_id).is_err());
        let aaa = fixtures::criteria_toml().replace("level = \"AA\"", "level = \"AAA\"");
        assert!(parse_criteria(&aaa).is_err());
        let source = fixtures::criteria_toml()
            .replace("https://www.w3.org/TR/WCAG22/", "https://example.org/");
        assert!(parse_criteria(&source).is_err());
        let duplicate = fixtures::criteria_toml().replace("id = \"1.1.1\"", "id = \"4.1.2\"");
        assert!(parse_criteria(&duplicate).is_err());
        let accessed =
            fixtures::criteria_toml().replace("accessed = \"2026-10-20\"", "accessed = \"today\"");
        assert!(parse_criteria(&accessed).is_err());
    }

    #[test]
    fn mapping_accepts_the_fixture_and_every_owner_form() {
        assert!(
            mapping_findings(&base(), &criteria(), &components(), &patterns()).is_empty(),
            "{}",
            messages(&mapping_findings(
                &base(),
                &criteria(),
                &components(),
                &patterns()
            ))
        );
        let with_na = base();
        assert!(has_token(
            &with_na,
            "not applicable: the fixture product ships no audio or video"
        ));
        assert!(has_token(&with_na, "page pattern: App frame"));
    }

    #[test]
    fn mapping_reports_a_missing_criterion() {
        let bad = base().replace("| 1.1.1 | A | Non-text Content | Avatar |\n", "");
        let found = messages(&mapping_findings(
            &bad,
            &criteria(),
            &components(),
            &patterns(),
        ));
        assert!(found.contains("1.1.1"), "{found}");
        assert!(found.contains("missing"), "{found}");
    }

    #[test]
    fn mapping_reports_a_duplicate_row() {
        let bad = base().replace(
            "| 1.4.3 | AA | Contrast (Minimum) | Button / IconButton |",
            "| 1.1.1 | A | Non-text Content | Avatar |",
        );
        let found = messages(&mapping_findings(
            &bad,
            &criteria(),
            &components(),
            &patterns(),
        ));
        assert!(found.contains("more than once"), "{found}");
    }

    #[test]
    fn mapping_reports_an_id_not_in_the_stored_list() {
        let bad = base().replace(
            "| 1.1.1 | A | Non-text Content | Avatar |",
            "| 9.9.9 | A | Non-text Content | Avatar |",
        );
        let found = messages(&mapping_findings(
            &bad,
            &criteria(),
            &components(),
            &patterns(),
        ));
        assert!(found.contains("9.9.9"), "{found}");
        assert!(found.contains("stored list"), "{found}");
    }

    #[test]
    fn mapping_reports_a_whole_token_owner_that_is_not_a_component() {
        let bad = base().replace(
            "| 1.1.1 | A | Non-text Content | Avatar |",
            "| 1.1.1 | A | Non-text Content | DataTableOfDoom |",
        );
        let found = messages(&mapping_findings(
            &bad,
            &criteria(),
            &components(),
            &patterns(),
        ));
        assert!(found.contains("DataTableOfDoom"), "{found}");
        assert!(found.contains("B11.8"), "{found}");
    }

    #[test]
    fn mapping_reports_a_vacuous_not_applicable_reason() {
        let bad = base().replace(
            "not applicable: the fixture product ships no audio or video",
            "not applicable: n/a",
        );
        let found = messages(&mapping_findings(
            &bad,
            &criteria(),
            &components(),
            &patterns(),
        ));
        assert!(found.contains("not applicable"), "{found}");
    }

    #[test]
    fn mapping_reports_an_undeclared_page_pattern() {
        let bad = base().replace("page pattern: App frame", "page pattern: Ghost frame");
        let found = messages(&mapping_findings(
            &bad,
            &criteria(),
            &components(),
            &patterns(),
        ));
        assert!(found.contains("Ghost frame"), "{found}");
        assert!(found.contains("not declared"), "{found}");
    }

    #[test]
    fn mapping_reports_a_level_or_title_drift() {
        let level = base().replace("| 1.1.1 | A |", "| 1.1.1 | AA |");
        let found = messages(&mapping_findings(
            &level,
            &criteria(),
            &components(),
            &patterns(),
        ));
        assert!(found.contains("level"), "{found}");
        let title = base().replace(
            "| 1.1.1 | A | Non-text Content |",
            "| 1.1.1 | A | Text alternatives |",
        );
        let found = messages(&mapping_findings(
            &title,
            &criteria(),
            &components(),
            &patterns(),
        ));
        assert!(found.contains("title"), "{found}");
    }

    #[test]
    fn page_patterns_require_a_real_component() {
        let bad = base().replace(
            "| App frame | The skip link and the landmark set. | Link; Breadcrumbs |",
            "| App frame | The skip link and the landmark set. | DataTableOfDoom |",
        );
        let (declared, findings) = page_patterns_findings(&bad, &components());
        assert!(declared.contains("App frame"));
        let found = messages(&findings);
        assert!(found.contains("DataTableOfDoom"), "{found}");
        assert!(found.contains("component"), "{found}");
    }

    #[test]
    fn matrix_requires_every_modality() {
        assert!(matrix_findings(&base()).is_empty());
        let bad = base().replace("| TalkBack | current | human step | ux |\n", "");
        let found = messages(&matrix_findings(&bad));
        assert!(found.contains("TalkBack"), "{found}");
    }

    #[test]
    fn matrix_marks_jaws_as_available_only_if_available() {
        let bad = base().replace("| JAWS | if available |", "| JAWS | required |");
        let found = messages(&matrix_findings(&bad));
        assert!(found.contains("JAWS"), "{found}");
        assert!(found.contains("if available"), "{found}");
    }

    #[test]
    fn automated_checks_name_the_axe_oracle_and_the_named_checks() {
        assert!(automated_findings(&base()).is_empty());
        let bad = base().replace("in the CDP suite", "in the browser suite");
        let found = messages(&automated_findings(&bad));
        assert!(found.contains("CDP"), "{found}");
        let bad = base().replace("The contrast token check", "The token check");
        let found = messages(&automated_findings(&bad));
        assert!(found.contains("contrast"), "{found}");
    }

    #[test]
    fn manual_checks_name_walkthroughs_twelve_scripts_zoom_and_reflow() {
        assert!(manual_findings(&base()).is_empty());
        let bad = base().replace(
            "The zoom and reflow checks run at 200% and 400% zoom and at 320 CSS pixels.\n",
            "",
        );
        let found = messages(&manual_findings(&bad));
        assert!(found.contains("zoom"), "{found}");
        let bad = base().replace(
            "the 12 screen reader checklists",
            "the screen reader checklists",
        );
        let found = messages(&manual_findings(&bad));
        assert!(found.contains("12"), "{found}");
    }

    #[test]
    fn severity_names_the_four_levels_and_the_ac40_gate_rule() {
        assert!(severity_findings(&base()).is_empty());
        let bad = base().replace("under AC-40", "under the gate");
        let found = messages(&severity_findings(&bad));
        assert!(found.contains("AC-40"), "{found}");
        let bad = base().replace(
            "| Serious | A criterion fails on a product surface, or axe reports a serious or critical violation. | Blocks the gate. |\n",
            "",
        );
        let found = messages(&severity_findings(&bad));
        assert!(found.contains("Serious"), "{found}");
    }

    #[test]
    fn statement_rejects_an_absolute_conformance_claim() {
        let bad = base().replace(
            "This draft does not claim WCAG 2.2 conformance; it reports the tests that ran.",
            "This draft is fully compliant with WCAG 2.2 AA.",
        );
        let found = messages(&statement_findings(&bad));
        assert!(found.contains("fully compliant"), "{found}");
    }

    #[test]
    fn statement_requires_known_gaps() {
        let bad = base().replace("### Known gaps", "### Later work");
        let found = messages(&statement_findings(&bad));
        assert!(found.contains("Known gaps"), "{found}");
    }

    #[test]
    fn human_steps_require_the_pending_marker_and_instructions() {
        assert!(human_steps_findings(&base()).is_empty());
        let bad = base().replace("human_step_pending", "pending");
        let found = messages(&human_steps_findings(&bad));
        assert!(found.contains("human_step_pending"), "{found}");
        let bad = base().replace("1. Pick a checklist", "- Pick a checklist");
        let found = messages(&human_steps_findings(&bad));
        assert!(found.contains("instruction"), "{found}");
    }

    #[test]
    fn regression_names_the_artifact_directory_and_the_baseline_tasks() {
        assert!(regression_findings(&base()).is_empty());
        let bad = base().replace("`acceptance-ui/`", "the artifact directory");
        let found = messages(&regression_findings(&bad));
        assert!(found.contains("acceptance-ui/"), "{found}");
        let bad = base().replace("T-0052", "a later task");
        let found = messages(&regression_findings(&bad));
        assert!(found.contains("T-0052"), "{found}");
    }

    #[test]
    fn flows_require_twelve_real_journeys_with_exact_titles() {
        let (flows, findings) = flows_findings(&base(), &journeys());
        assert!(findings.is_empty(), "{}", messages(&findings));
        assert_eq!(flows.len(), FLOW_COUNT);
        let short = base().replace(
            "| J-12 | Owner configures and tests the origin | fixture-flow-12 | A fixture flow. |\n",
            "",
        );
        let (_, findings) = flows_findings(&short, &journeys());
        let found = messages(&findings);
        assert!(found.contains("12"), "{found}");
        let invented = base().replace("| J-01 |", "| J-99 |");
        let (_, findings) = flows_findings(&invented, &journeys());
        let found = messages(&findings);
        assert!(found.contains("J-99"), "{found}");
        let renamed = base().replace(
            "| J-02 | Visitor signs up and verifies email |",
            "| J-02 | Sign-up |",
        );
        let (_, findings) = flows_findings(&renamed, &journeys());
        let found = messages(&findings);
        assert!(found.contains("title"), "{found}");
        let duplicate = base().replace("| fixture-flow-02 |", "| fixture-flow-01 |");
        let (_, findings) = flows_findings(&duplicate, &journeys());
        let found = messages(&findings);
        assert!(found.contains("slug"), "{found}");
    }

    #[test]
    fn checklist_set_requires_exactly_the_named_files() {
        let files = checklists();
        let (flows, _) = flows_findings(&base(), &journeys());
        assert!(checklist_set_findings(&files, &flows, &screens()).is_empty());
        let mut missing = files.clone();
        missing.remove("fixture-flow-12");
        let found = messages(&checklist_set_findings(&missing, &flows, &screens()));
        assert!(found.contains("fixture-flow-12"), "{found}");
        let mut extra = files.clone();
        extra.insert("rogue-flow".to_owned(), fixtures::accessibility_doc());
        let found = messages(&checklist_set_findings(&extra, &flows, &screens()));
        assert!(found.contains("rogue-flow"), "{found}");
    }

    #[test]
    fn checklist_has_the_required_parts() {
        let files = checklists();
        let (flows, _) = flows_findings(&base(), &journeys());
        let flow = flows.first().expect("a fixture flow");
        let text = files.get(&flow.slug).expect("the fixture checklist");
        assert!(checklist_findings(&flow.slug, text, flow, &screens()).is_empty());
        let no_script = text.replace("## Failure criteria", "## Known issues");
        let found = messages(&checklist_findings(
            &flow.slug,
            &no_script,
            flow,
            &screens(),
        ));
        assert!(found.contains("Failure criteria"), "{found}");
        let no_human = text.replace("human_step_pending", "later");
        let found = messages(&checklist_findings(&flow.slug, &no_human, flow, &screens()));
        assert!(found.contains("human_step_pending"), "{found}");
        let invented = text.replace("S-001", "S-999");
        let found = messages(&checklist_findings(&flow.slug, &invented, flow, &screens()));
        assert!(found.contains("S-999"), "{found}");
        let no_tab = text.replace("Tab", "Pointer");
        let found = messages(&checklist_findings(&flow.slug, &no_tab, flow, &screens()));
        assert!(found.contains("Tab"), "{found}");
        let no_rows = text.replace(
            "| 1 | S-001 | The screen heading and the primary action. |\n| 2 | S-003 | The screen heading and the primary action. |\n| 3 | S-006 | The screen heading and the primary action. |\n",
            "",
        );
        let found = messages(&checklist_findings(&flow.slug, &no_rows, flow, &screens()));
        assert!(found.contains("rows"), "{found}");
    }

    #[test]
    fn strategy_cites_only_real_screens_and_journeys() {
        assert!(identifier_findings(&base(), &screens(), &journeys()).is_empty());
        let screen = format!("{}\nSee S-999 for the test screen.\n", base());
        let found = messages(&identifier_findings(&screen, &screens(), &journeys()));
        assert!(found.contains("S-999"), "{found}");
        let journey = base().replace("J-01", "J-99");
        let found = messages(&identifier_findings(&journey, &screens(), &journeys()));
        assert!(found.contains("J-99"), "{found}");
    }

    #[test]
    fn the_fixture_documents_pass_every_rule() {
        let found = messages(&document_findings());
        assert!(found.is_empty(), "{found}");
    }

    #[test]
    fn fixtures_cover_the_files_the_lead_writes() {
        let docs = fixtures::documents();
        assert_eq!(docs.len(), 14);
        assert!(
            docs.iter()
                .any(|(path, _)| path == "docs/UX/ACCESSIBILITY.md")
        );
        assert!(
            docs.iter()
                .any(|(path, _)| path == "docs/UX/wcag22-criteria.toml")
        );
        assert_eq!(
            docs.iter()
                .filter(|(path, _)| path.starts_with("docs/UX/a11y-checklists/"))
                .count(),
            12
        );
        assert!(fixtures::spec_section().is_empty());
    }

    #[test]
    fn missing_documents_are_findings_not_panics() {
        let root = std::env::temp_dir().join(format!("hdd-a11y-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).expect("temporary repository");
        let findings = check_with_spec(&root, "");
        let _ = std::fs::remove_dir_all(&root);
        let found = messages(&findings);
        assert!(found.contains("wcag22-criteria.toml"), "{found}");
        assert!(found.contains("ACCESSIBILITY.md"), "{found}");
        assert!(found.contains("a11y-checklists"), "{found}");
    }

    // --- F-25: the severity scheme is a function of four inputs, not prose. ---

    #[test]
    fn severity_classifier_precedence_is_a_function() {
        // The first matching rule of the precedence wins.
        assert_eq!(
            classify(true, true, true, AxeImpact::Critical),
            Severity::Critical
        );
        assert_eq!(
            classify(true, false, true, AxeImpact::None),
            Severity::Critical
        );
        assert_eq!(
            classify(false, true, false, AxeImpact::None),
            Severity::Critical
        );
        // A criterion failure is always Serious, whatever axe says.
        assert_eq!(
            classify(true, false, false, AxeImpact::None),
            Severity::Serious
        );
        assert_eq!(
            classify(true, false, false, AxeImpact::Minor),
            Severity::Serious
        );
        // axe serious or critical without a known criterion failure is Serious too.
        assert_eq!(
            classify(false, false, false, AxeImpact::Serious),
            Severity::Serious
        );
        assert_eq!(
            classify(false, false, false, AxeImpact::Critical),
            Severity::Serious
        );
        // Moderate needs no criterion failure and no blocked task.
        assert_eq!(
            classify(false, false, false, AxeImpact::Moderate),
            Severity::Moderate
        );
        assert_eq!(
            classify(false, false, false, AxeImpact::Minor),
            Severity::Minor
        );
        assert_eq!(
            classify(false, false, false, AxeImpact::None),
            Severity::Minor
        );
        for severity in [
            Severity::Critical,
            Severity::Serious,
            Severity::Moderate,
            Severity::Minor,
        ] {
            assert_eq!(Severity::parse(severity.name()), Some(severity));
        }
        for (impact, name) in [
            (AxeImpact::None, "none"),
            (AxeImpact::Minor, "minor"),
            (AxeImpact::Moderate, "moderate"),
            (AxeImpact::Serious, "serious"),
            (AxeImpact::Critical, "critical"),
        ] {
            assert_eq!(AxeImpact::parse(name), Some(impact));
        }
        assert_eq!(AxeImpact::parse("blocker"), None);
        assert_eq!(Severity::parse("blocking"), None);
    }

    #[test]
    fn severity_examples_are_evaluated_by_the_classifier() {
        assert!(
            severity_example_findings(&base()).is_empty(),
            "{}",
            messages(&severity_example_findings(&base()))
        );
        // A stated Moderate on a criterion-failure row is the overlap F-25 names.
        let bad = base().replace(
            "| A DNS table header button does not expose its sort state. | yes | no | no | serious | Serious |",
            "| A DNS table header button does not expose its sort state. | yes | no | no | serious | Moderate |",
        );
        let found = messages(&severity_example_findings(&bad));
        assert!(found.contains("Moderate"), "{found}");
        assert!(found.contains("Serious"), "{found}");
        // The same row with the criterion input flipped to no and a moderate impact is Moderate.
        let bad = base().replace(
            "| A DNS table header button does not expose its sort state. | yes | no | no | serious | Serious |",
            "| A DNS table header button does not expose its sort state. | no | no | no | moderate | Serious |",
        );
        let found = messages(&severity_example_findings(&bad));
        assert!(found.contains("Serious"), "{found}");
        // A critical flow row cannot be downgraded to Serious.
        let bad = base().replace(
            "| The MFA code field refuses paste in J-04. | yes | yes | no | serious | Critical |",
            "| The MFA code field refuses paste in J-04. | yes | yes | no | serious | Serious |",
        );
        let found = messages(&severity_example_findings(&bad));
        assert!(found.contains("Critical"), "{found}");
        // An unreachable security control cannot be tolerated as Minor.
        let bad = base().replace(
            "| The under-attack control cannot be reached with the keyboard. | yes | yes | yes | serious | Critical |",
            "| The under-attack control cannot be reached with the keyboard. | yes | yes | yes | serious | Minor |",
        );
        let found = messages(&severity_example_findings(&bad));
        assert!(found.contains("Critical"), "{found}");
    }

    #[test]
    fn severity_examples_need_six_rows_and_all_four_severities() {
        let short = base().replace(
            "| The chart legend order differs although direct labels are present. | no | no | no | none | Minor |\n",
            "",
        );
        let short = short.replace(
            "| A report landmark repeats a name but the task still completes. | no | no | no | moderate | Moderate |\n",
            "",
        );
        let short = short.replace(
            "| A toast covers the focused confirm button until it fades. | yes | no | no | moderate | Serious |\n",
            "",
        );
        let found = messages(&severity_example_findings(&short));
        assert!(found.contains("six"), "{found}");
        let no_minor = base().replace(
            "| The chart legend order differs although direct labels are present. | no | no | no | none | Minor |\n",
            "",
        );
        let found = messages(&severity_example_findings(&no_minor));
        assert!(found.contains("Minor"), "{found}");
        let bad_value = base().replace(
            "| The audit filter panel skips a heading level. | yes | no | no | moderate | Serious |",
            "| The audit filter panel skips a heading level. | maybe | no | no | moderate | Serious |",
        );
        let found = messages(&severity_example_findings(&bad_value));
        assert!(found.contains("maybe"), "{found}");
    }

    #[test]
    fn severity_rejects_a_moderate_row_that_names_a_criterion_failure() {
        let overlap = base().replace(
            "| Moderate | There is no criterion failure and axe reports a moderate best-practice issue. |",
            "| Moderate | A criterion fails in a state outside the 12 flows. |",
        );
        let found = messages(&severity_findings(&overlap));
        assert!(found.contains("criterion failure"), "{found}");
        let blocking = base().replace(
            "| Moderate | There is no criterion failure and axe reports a moderate best-practice issue. | Does not block. |",
            "| Moderate | There is no criterion failure and axe reports a moderate best-practice issue. | Blocks the gate. |",
        );
        let found = messages(&severity_findings(&blocking));
        assert!(found.contains("gate"), "{found}");
        let no_precedence = base().replace(
            "A WCAG 2.2 A or AA criterion failure is always Serious.",
            "",
        );
        let found = messages(&severity_findings(&no_precedence));
        assert!(found.contains("Serious"), "{found}");
        let no_order = base().replace(
            "The precedence is evaluated in this order:",
            "The inputs are:",
        );
        let found = messages(&severity_findings(&no_order));
        assert!(found.contains("order"), "{found}");
    }

    // --- F-26: checklists and journey maps agree on screens. ---

    fn fixture_flows() -> Vec<Flow> {
        let (flows, findings) = flows_findings(&base(), &journeys());
        assert!(findings.is_empty(), "{}", messages(&findings));
        flows
    }

    fn journey_screens() -> BTreeMap<String, BTreeSet<String>> {
        fixtures::journey_screens()
    }

    /// The coverage findings of one fixture checklist, optionally replaced by `text`.
    fn coverage(flow_id: &str, text: Option<&str>) -> Vec<Finding> {
        let flows = fixture_flows();
        let flow = flows
            .into_iter()
            .find(|flow| flow.id == flow_id)
            .expect("a fixture flow");
        let mut files = checklists();
        let text = text
            .map(str::to_owned)
            .unwrap_or_else(|| files.get(&flow.slug).expect("a fixture checklist").clone());
        files.insert(flow.slug.clone(), text);
        checklist_coverage_findings(&files, std::slice::from_ref(&flow), &journey_screens())
    }

    fn flow_checklist(flow_id: &str) -> String {
        let flow = fixture_flows()
            .into_iter()
            .find(|flow| flow.id == flow_id)
            .expect("a fixture flow");
        checklists()
            .get(&flow.slug)
            .expect("a fixture checklist")
            .clone()
    }

    #[test]
    fn screen_ids_are_whole_tokens_not_parts_of_error_codes() {
        // `ERR-SYS-001` and `ERR-DNS-002` are not screens; that substring reading produced F-26's counts.
        assert!(screen_ids_in("the ERR-SYS-001 code").is_empty());
        assert!(screen_ids_in("the ERR-DNS-002 code").is_empty());
        assert_eq!(
            screen_ids_in("See S-020 and S-021."),
            ["S-020", "S-021"]
                .iter()
                .map(|id| (*id).to_owned())
                .collect()
        );
        assert_eq!(
            screen_ids_in("| S-140 | none |").iter().next(),
            Some(&"S-140".to_owned())
        );
    }

    #[test]
    fn journey_screen_ids_read_the_steps_screen_column() {
        let journey = "# J-02 Fixture journey\n\n## Steps\n\n| Step | User action | System response | Screen |\n| --- | --- | --- | --- |\n| 1 | Types the email. | The form validates. | S-020 |\n| 2 | Waits for the message. | The mailbox gets a link. | email |\n| 3 | Confirms. | The account is active. | S-022 |\n| 4 | Fails with ERR-SYS-001. | The form keeps the values. | S-022 |\n";
        let screens = journey_screen_ids(journey).expect("the steps table parses");
        assert_eq!(
            screens,
            ["S-020", "S-022"]
                .iter()
                .map(|id| (*id).to_owned())
                .collect()
        );
        let no_table = journey_screen_ids("# J-02 Fixture journey\n\nNo steps here.\n");
        assert!(no_table.is_err());
    }

    #[test]
    fn checklist_screen_coverage_accepts_the_fixture() {
        assert!(
            coverage("J-02", None).is_empty(),
            "{}",
            messages(&coverage("J-02", None))
        );
        assert!(
            coverage("J-04", None).is_empty(),
            "{}",
            messages(&coverage("J-04", None))
        );
    }

    #[test]
    fn checklist_reports_a_screen_outside_the_journey() {
        let text = flow_checklist("J-02").replace(
            "Screens: S-020, S-021, S-022, S-035",
            "Screens: S-020, S-021, S-022, S-035, S-025",
        );
        let text = text.replace(
            "1. On S-020, Tab reaches the next control and Enter activates it.",
            "1. On S-020, Tab reaches the next control and on S-025 Enter activates it.",
        );
        let found = messages(&coverage("J-02", Some(&text)));
        assert!(found.contains("S-025"), "{found}");
        assert!(found.contains("Outside the journey"), "{found}");
    }

    #[test]
    fn checklist_accepts_an_outside_the_journey_line_with_a_reason() {
        let text = flow_checklist("J-02").replace(
            "Screens: S-020, S-021, S-022, S-035",
            "Screens: S-020, S-021, S-022, S-035, S-025",
        );
        let text = text.replace(
            "1. On S-020, Tab reaches the next control and Enter activates it.",
            "1. On S-020, Tab reaches the next control and on S-025 Enter activates it.",
        );
        let text = text.replace(
            "## Keyboard path",
            "Outside the journey: S-025 - the recovery-code screen is a branch of S-024 that J-02 does not step through.\n\n## Keyboard path",
        );
        assert!(
            coverage("J-02", Some(&text)).is_empty(),
            "{}",
            messages(&coverage("J-02", Some(&text)))
        );
        // The same line without a reason is a finding.
        let reasonless = text.replace(
            "Outside the journey: S-025 - the recovery-code screen is a branch of S-024 that J-02 does not step through.",
            "Outside the journey: S-025",
        );
        let found = messages(&coverage("J-02", Some(&reasonless)));
        assert!(found.contains("reason"), "{found}");
    }

    #[test]
    fn checklist_reports_an_uncovered_journey_screen() {
        // S-035 appears in the declarative screens line but is not exercised by the checklist.
        let text = flow_checklist("J-02").replace(
            "4. On S-035, Tab reaches the next control and Enter activates it.",
            "4. On S-020, Tab reaches the next control and Enter activates it.",
        );
        let text = text.replace(
            "| 4 | S-035 | The screen heading and the primary action. |",
            "",
        );
        let found = messages(&coverage("J-02", Some(&text)));
        assert!(found.contains("S-035"), "{found}");
        assert!(found.contains("Screens not covered"), "{found}");
    }

    #[test]
    fn checklist_accepts_screens_not_covered_with_a_reason() {
        let text = flow_checklist("J-02").replace(
            "4. On S-035, Tab reaches the next control and Enter activates it.",
            "4. On S-020, Tab reaches the next control and Enter activates it.",
        );
        let text = text.replace(
            "| 4 | S-035 | The screen heading and the primary action. |",
            "",
        );
        let text = text.replace(
            "Screens: S-020, S-021, S-022, S-035",
            "Screens: S-020, S-021, S-022",
        );
        let text = text.replace(
            "## Keyboard path",
            "Screens not covered: S-035 - the onboarding wizard is covered by the J-07 checklist instead.\n\n## Keyboard path",
        );
        assert!(
            coverage("J-02", Some(&text)).is_empty(),
            "{}",
            messages(&coverage("J-02", Some(&text)))
        );
    }

    #[test]
    fn checklist_requires_the_screens_line() {
        let text = flow_checklist("J-02").replace("Screens: S-020, S-021, S-022, S-035", "");
        let found = messages(&coverage("J-02", Some(&text)));
        assert!(found.contains("Screens:"), "{found}");
    }

    #[test]
    fn checklist_coverage_requires_the_doc_subsection() {
        assert!(
            checklist_coverage_doc_findings(&base()).is_empty(),
            "{}",
            messages(&checklist_coverage_doc_findings(&base()))
        );
        let bad = base().replace("### Checklist screen coverage", "### Later work");
        let found = messages(&checklist_coverage_doc_findings(&bad));
        assert!(found.contains("Checklist screen coverage"), "{found}");
        let bad = base().replace("`Outside the journey:", "`Skip list:");
        let found = messages(&checklist_coverage_doc_findings(&bad));
        assert!(found.contains("Outside the journey"), "{found}");
    }

    #[test]
    fn checklist_coverage_reports_a_missing_journey() {
        let flow = fixture_flows()
            .into_iter()
            .find(|flow| flow.id == "J-02")
            .expect("a fixture flow");
        let mut journey_screens = journey_screens();
        journey_screens.remove("J-02");
        let found = messages(&checklist_coverage_findings(
            &checklists(),
            std::slice::from_ref(&flow),
            &journey_screens,
        ));
        assert!(found.contains("J-02"), "{found}");
        assert!(found.contains("Steps"), "{found}");
    }
}
