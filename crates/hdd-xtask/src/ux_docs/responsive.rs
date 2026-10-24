//! `ux-docs` checks for T-0024 (responsive and device strategy).
//!
//! The rules, one documented function each. Every rule reads `docs/UX/RESPONSIVE.md`; the rules that need
//! thresholds read them from the checksum-verified master specification instead of a hard-coded copy.
//!
//! 1. [`sections_findings`] (T-0024 steps 1 to 8): the document opens with a title and has the eleven
//!    level-2 sections the deliverable needs, each with a body.
//! 2. [`breakpoint_findings`] (T-0024 step 1, A1; spec B11.4): the breakpoints table matches the
//!    `Breakpoints` row of B11.4 one row per breakpoint, with `px` units, and states the two container
//!    maxima of the same row.
//! 3. [`layout_findings`] (T-0024 step 1; spec B11.7): the sidebar becomes a drawer below the width the
//!    spec names, tables become cards below the width the spec names and only where horizontal scrolling
//!    would hide primary data, every other table region is focusable and hinted, and wizards are single
//!    column.
//! 4. [`device_matrix_findings`] (T-0024 step 2, A1 and A5): exactly the seven viewports of the task, each
//!    with light and dark themes and LTR and pseudo-RTL directions, the tablet rows, a landscape row, and
//!    the statement that the matrix is used by T-0090.
//! 5. [`input_modalities_findings`] (T-0024 step 3, A5; spec B11.4 and B11.11): the target floor, the
//!    default and touch control heights read from B11.4, a hover alternative, a keyboard path and
//!    orientation, with landscape phones and tablets named.
//! 6. [`screen_categories_findings`] (T-0024 step 1, A2): one small-screen behaviour row per screen
//!    category, each naming real B12.1 screens of its category.
//! 7. [`security_controls_findings`] (T-0024 note, F-22): the controls the dangerous-actions catalog
//!    marks as enforcement-changing or time-boxed (safe mode, the block mode switch, ban and unban, the
//!    global ban, the self-lockout warning, under attack, pause protection, access-list deny and allow,
//!    geo-block, origin lockdown, origin unlock, the platform never-ban list and the platform emergency
//!    controls) stay visible and never move into an overflow menu.
//! 8. [`content_priority_findings`] (T-0024 step 6): a content-priority row for every B11.4 breakpoint,
//!    with no security-critical control in a "moves to overflow" cell and each `Never moves` cell naming
//!    every control of the table ([`never_moves_findings`], F-22).
//! 9. [`data_dense_findings`] (T-0024 step 7): the live threat monitor S-065 keeps a stated set of real
//!    columns and moves the rest to the event drawer S-066, with the pause control still on screen.
//! 10. [`performance_findings`] (T-0024 step 5, A4; T-0029 and T-0052): a numeric Core Web Vitals, JS, CSS and request budget for every device class, explicitly labelled as budgets and not measurements.
//! 11. [`print_findings`] (T-0024 step 4, A3): report pages (S-073, S-074) and the audit export (S-084) have a print layout with a page size, margins, header and footer, hidden chrome, page breaks, contrast and no interactive-only data.
//! 12. [`testing_hooks_findings`] (T-0024 step 8, A1): the viewport helper, the screenshot directory and naming rule, stable names and the T-0052 baselines used by T-0090.
//! 13. [`screen_reference_findings`] (document rule): every `S-nnn` cited anywhere in the document is a screen of the spec B12.1 table.
//! 14. [`placeholder_findings`] (R-01): no empty, dash-only, `TBD`, `TODO` or `n/a` table cell.
//! 15. [`gap_note_findings`] (F-21): no table cell carries a review note, because a `gap:` note is not
//!     published content and the one that existed in the self-lockout row was false once the catalog
//!     named the self-lockout preview.
//! 16. [`never_moves_findings`] (F-22): every `Never moves` cell of the Content priority table names
//!     every control of the Security-critical controls table, at every breakpoint.
//! 17. [`catalog_coverage_findings`] (F-22): every row of the dangerous-actions catalog whose Safeguards
//!     carry a `time box` or whose Screen is a security-critical screen is either covered by a control
//!     row or excluded by an explicit `excluded: <reason>` row.
//! 18. [`print_margin_findings`] (F-23): the print margin is the canonical A4 value in [`PRINT_MARGIN_MM`],
//!     and `docs/UX/DATAVIZ.md` points to this document instead of stating its own margin.
//!
//! The self-lockout control of rule 7 is cross-checked in [`safeguard_crosscheck_findings`] against the
//! dangerous-actions catalog and not against a journey `Safeguards` table: no journey names a self-lockout
//! as a `Risky action`, while catalog rows DA-05 to DA-08 name the self-lockout preview on this control's
//! screens. Rule 17 makes that catalog requirement real, so the cross-check cannot pass on a gap note.
//!
//! All matching is by whole token (review lesson 1): `T-0090` does not match `T-00900`, `S-065` does not
//! match `S-0650`, and `block mode` does not match `block mode switch` unless both words are present. A
//! missing document is one finding; a missing section is left to [`sections_findings`] so the caller sees
//! one reason, not eleven. Nothing here panics on malformed input.

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

use regex::Regex;

use crate::util::{Finding, read_text};

use super::{cells, column, section_body, section_table};

/// The responsive and device strategy document.
pub const DOC: &str = "docs/UX/RESPONSIVE.md";

/// Level-2 sections the document must have, with the step or acceptance criterion that requires each.
const SECTIONS: [(&str, &str); 11] = [
    ("Breakpoints", "T-0024 step 1"),
    ("Layout transformations", "T-0024 step 1, B11.7"),
    ("Device matrix", "T-0024 step 2, A1 and A5"),
    ("Input modalities", "T-0024 step 3"),
    ("Screen categories", "T-0024 step 1, A2"),
    ("Security-critical controls", "T-0024 note"),
    ("Content priority", "T-0024 step 6"),
    ("Data-dense screens", "T-0024 step 7"),
    ("Performance budgets", "T-0024 step 5, A4"),
    ("Printing and PDF", "T-0024 step 4, A3"),
    ("Testing hooks", "T-0024 step 8"),
];

/// The seven screenshot viewports of T-0024 step 2, as the task writes them (width x height in CSS px).
const VIEWPORTS: [&str; 7] = [
    "360x740",
    "390x844",
    "768x1024",
    "1024x768",
    "1280x800",
    "1536x864",
    "1920x1080",
];

/// The target-size floor of WCAG 2.2 AA success criterion 2.5.8, which the task names and B11.11 records.
const MIN_TARGET_CSS_PX: u32 = 24;

/// Every screen category needs a small-screen behaviour row (T-0024 A2). The screens are real B12.1 ids;
/// a category satisfies the rule when its row names at least one of them.
const SCREEN_CATEGORIES: [(&str, &[&str]); 8] = [
    ("Wizard", &["S-042", "S-094", "S-098"]),
    ("Data table", &["S-041", "S-045", "S-067"]),
    ("Live feed", &["S-065"]),
    ("Analytics chart", &["S-043", "S-054", "S-070"]),
    ("Settings form", &["S-055", "S-086", "S-092"]),
    ("Admin table", &["S-101", "S-102", "S-114"]),
    ("Report page", &["S-073", "S-074"]),
    ("Empty state", &["S-041", "S-065", "S-067"]),
];

/// Screens a category row must name, not merely one of a set: the task names the live monitor and the
/// two report screens, so a category row with a different screen of the same surface is not enough.
const REQUIRED_CATEGORY_SCREENS: [(&str, &[&str]); 2] = [
    ("Live feed", &["S-065"]),
    ("Report page", &["S-073", "S-074"]),
];

/// The dangerous-actions catalog (T-0025) the never-hidden list is cross-checked against (F-22).
pub const CATALOG: &str = "docs/UX/dangerous-actions.md";

/// The data-visualization document whose print rule points at [`DOC`] (F-23).
pub const DATAVIZ: &str = "docs/UX/DATAVIZ.md";

/// The canonical print margin of F-23: A4 portrait with 12 mm margins on every edge, stated in [`DOC`].
const PRINT_MARGIN_MM: u32 = 12;

/// The controls that are never hidden on a small screen (T-0024 note, F-22). The set follows the
/// dangerous-actions catalog: every action that is time-boxed or sits on a security-critical screen is
/// either one of these rows or an explicit `excluded:` row of the same table. The needle is matched as
/// a whole word or phrase against the `Control` cell; the screens are the B12.1 screens that own it.
const REQUIRED_CONTROLS: [(&str, &[&str]); 13] = [
    ("safe mode", &["S-093", "S-122"]),
    ("block mode", &["S-055"]),
    ("ban and unban", &["S-067"]),
    ("global ban", &["S-106"]),
    ("lockout", &["S-063", "S-131"]),
    ("under attack", &["S-093"]),
    ("pause protection", &["S-093"]),
    ("access-list", &["S-063"]),
    ("geo-block", &["S-063"]),
    ("origin lockdown", &["S-098"]),
    ("origin unlock", &["S-052"]),
    ("never-ban", &["S-109"]),
    ("platform emergency", &["S-122"]),
];

/// The catalog action phrases that cover each required control (F-22): a catalog row is covered only
/// when its `Screen` is one of the control's screens and its `Action` contains one of these phrases.
/// The list is the reviewed mapping, so a similar-sounding action on the same screen cannot stand in
/// for the real control (a ban is not a global ban, a lockdown is not an unlock).
const CATALOG_ACTION_TERMS: [(&str, &[&str]); 13] = [
    ("safe mode", &["safe mode"]),
    ("block mode", &["block mode", "protection mode"]),
    ("ban and unban", &["manual ban", "ban"]),
    ("global ban", &["global ban"]),
    ("lockout", &["self-lockout"]),
    ("under attack", &["under attack"]),
    ("pause protection", &["pause protection"]),
    ("access-list", &["access-list", "access list"]),
    ("geo-block", &["geo-block", "geo block"]),
    ("origin lockdown", &["origin lockdown"]),
    (
        "origin unlock",
        &["removing the lockdown", "origin unlock", "open the origin"],
    ),
    ("never-ban", &["never-ban"]),
    (
        "platform emergency",
        &["platform emergency", "emergency control"],
    ),
];

/// Words that are too generic to prove that an `excluded:` row names a catalog action (F-22).
const GENERIC_ACTION_WORDS: [&str; 6] = ["mode", "action", "change", "domain", "value", "release"];

/// Device classes with a numeric budget (T-0024 A4); each label is matched by all of its words.
const BUDGET_CLASSES: [(&str, &[&str]); 4] = [
    ("Mobile mid-range", &["mobile", "mid-range"]),
    ("Tablet", &["tablet"]),
    ("Laptop", &["laptop"]),
    ("Desktop", &["desktop"]),
];

/// Words that show a row describes an actual small-screen behaviour rather than a wish (T-0024 A2).
const BEHAVIOUR_WORDS: [&str; 16] = [
    "single",
    "stacked",
    "card",
    "cards",
    "drawer",
    "scroll",
    "collapse",
    "collapses",
    "wrap",
    "wraps",
    "simplified",
    "scales",
    "condensed",
    "full",
    "print",
    "sticky",
];

/// Cells that stand in for a real value (R-01). A whole-token match, so `N/A` is caught but a word that
/// merely contains the letters (for example `todos`) is not.
const PLACEHOLDERS: [&str; 8] = [
    "TBD",
    "TBC",
    "TODO",
    "FIXME",
    "XXX",
    "lorem",
    "placeholder",
    "n/a",
];

/// A finding at the document (no line number).
fn at(message: impl Into<String>) -> Finding {
    super::finding(DOC, message)
}

/// A finding at one line of the document.
fn line(n: usize, message: impl Into<String>) -> Finding {
    super::finding(format!("{DOC}:{n}"), message)
}

/// A finding at another document (the print alignment of F-23 reads `docs/UX/DATAVIZ.md`).
fn finding_doc(location: impl Into<String>, message: impl Into<String>) -> Finding {
    super::finding(location, message)
}

/// True when `needle` appears in `haystack` as a whole word or whole phrase (case-insensitive).
fn word(haystack: &str, needle: &str) -> bool {
    if needle.trim().is_empty() {
        return false;
    }
    Regex::new(&format!(r"(?i)\b{}\b", regex::escape(needle))).is_ok_and(|re| re.is_match(haystack))
}

/// The unsigned whole numbers in `text`, in order.
fn numbers(text: &str) -> Vec<u32> {
    let mut out = Vec::new();
    let mut cur = String::new();
    for c in text.chars() {
        if c.is_ascii_digit() {
            cur.push(c);
        } else if !cur.is_empty() {
            if let Ok(n) = cur.parse::<u32>() {
                out.push(n);
            }
            cur.clear();
        }
    }
    if !cur.is_empty()
        && let Ok(n) = cur.parse::<u32>()
    {
        out.push(n);
    }
    out
}

/// The first `WxH` (or `W x H`, or `W` followed by the multiplication sign) viewport of a cell,
/// normalised to `WxH`.
fn viewport_key(cell: &str) -> Option<String> {
    let chars: Vec<char> = cell.chars().collect();
    let mut i = 0usize;
    while i < chars.len() {
        let Some(c) = chars.get(i).copied() else {
            break;
        };
        if !c.is_ascii_digit() {
            i += 1;
            continue;
        }
        let mut width = String::new();
        while let Some(d) = chars.get(i).copied() {
            if !d.is_ascii_digit() {
                break;
            }
            width.push(d);
            i += 1;
        }
        let after_width = i;
        while chars.get(i).copied() == Some(' ') {
            i += 1;
        }
        let separator = chars.get(i).copied()?;
        if separator != 'x' && separator != 'X' && separator != '\u{00D7}' {
            i = after_width;
            continue;
        }
        i += 1;
        while chars.get(i).copied() == Some(' ') {
            i += 1;
        }
        let mut height = String::new();
        while let Some(d) = chars.get(i).copied() {
            if !d.is_ascii_digit() {
                break;
            }
            height.push(d);
            i += 1;
        }
        if !width.is_empty() && !height.is_empty() {
            return Some(format!("{width}x{height}"));
        }
        i = after_width;
    }
    None
}

/// True when the viewport string is landscape (width greater than height).
fn is_landscape(viewport: &str) -> bool {
    let parts: Vec<u32> = viewport
        .split('x')
        .filter_map(|part| part.parse::<u32>().ok())
        .collect();
    match (parts.first(), parts.get(1)) {
        (Some(width), Some(height)) => width > height,
        _ => false,
    }
}

/// The named cell of a table row, or `""` when the column or the cell is absent.
fn cell(row: &[String], index: Option<usize>) -> &str {
    index.and_then(|i| row.get(i)).map_or("", String::as_str)
}

/// Header cells and body rows (with line numbers) of a Markdown table.
type Table = (Vec<String>, Vec<(usize, Vec<String>)>);

/// The first table under `title`, or one finding when the section exists without a table. A missing
/// section returns an empty finding list because [`sections_findings`] already reports it once.
fn table_or(text: &str, title: &str, step: &str) -> Result<Table, Vec<Finding>> {
    match section_table(text, title) {
        Some(table) => Ok(table),
        None => {
            if section_body(text, title).is_some() {
                Err(vec![at(format!("`## {title}` has no table ({step})"))])
            } else {
                Err(Vec::new())
            }
        }
    }
}

/// The first row whose `Modality` cell names `modality` and, when `requirement` is not empty, whose
/// `Requirement` cell also names that word (T-0024 step 3).
fn input_row<'a>(
    rows: &'a [(usize, Vec<String>)],
    col_modality: usize,
    col_requirement: usize,
    modality: &str,
    requirement: &str,
) -> Option<&'a (usize, Vec<String>)> {
    rows.iter().find(|(_, row)| {
        word(cell(row, Some(col_modality)), modality)
            && (requirement.is_empty() || word(cell(row, Some(col_requirement)), requirement))
    })
}

/// One row of the B11.4 table, by its first cell.
fn spec_row(spec: &str, heading: &str, first: &str) -> Option<Vec<String>> {
    for (_, line) in super::spec_section(spec, heading) {
        let Some(row) = super::cells(line) else {
            continue;
        };
        if row
            .first()
            .is_some_and(|value| value.trim().eq_ignore_ascii_case(first))
        {
            return Some(row);
        }
    }
    None
}

/// The breakpoints and the container maxima of the B11.4 `Breakpoints` row, read from the spec text.
fn spec_breakpoints(spec: &str) -> Option<(Vec<u32>, Vec<u32>)> {
    let row = spec_row(spec, "B11.4", "Breakpoints")?;
    let values = row.get(1)?.to_lowercase();
    let (left, right) = values.split_once("container")?;
    let points = numbers(left);
    let containers = numbers(right);
    if points.len() < 2 || containers.len() < 2 {
        return None;
    }
    let ascending = points
        .windows(2)
        .all(|pair| match (pair.first(), pair.get(1)) {
            (Some(first), Some(second)) => first < second,
            _ => false,
        });
    ascending.then_some((points, containers))
}

/// The card minimum of the B11.7 `Grid` bullet (F-24), read from the spec text: the count of a card
/// row follows from the available width and this minimum, so the last breakpoint can state a testable
/// behaviour instead of `may show more cards`.
fn spec_card_minimum(spec: &str) -> Option<u32> {
    let re = Regex::new(r"(?i)minimum\s+(\d+)\s*px").ok()?;
    for (_, line_text) in super::spec_section(spec, "B11.7") {
        if !word(line_text, "grid") || !word(line_text, "card") && !word(line_text, "cards") {
            continue;
        }
        let value = re
            .captures(line_text)
            .and_then(|capture| capture.get(1))
            .and_then(|value| value.as_str().parse::<u32>().ok());
        if value.is_some() {
            return value;
        }
    }
    None
}

/// The default and touch control heights of the B11.4 `Control heights` row.
fn spec_targets(spec: &str) -> Option<(u32, u32)> {
    let row = spec_row(spec, "B11.4", "Control heights")?;
    let values = row.get(1)?;
    let default = Regex::new(r"(?i)minimum hit area (\d+)\s*px")
        .ok()?
        .captures(values)?
        .get(1)?
        .as_str()
        .parse::<u32>()
        .ok()?;
    let touch = Regex::new(r"(?i)\((\d+)\s*for touch\)")
        .ok()?
        .captures(values)?
        .get(1)?
        .as_str()
        .parse::<u32>()
        .ok()?;
    Some((default, touch))
}

/// The two widths of the B11.7 `Responsive behavior` bullet: the sidebar drawer width and the table-card
/// width, in the order the spec names them.
fn spec_layout(spec: &str) -> Option<(u32, u32)> {
    let re = Regex::new(r"(?i)below\s+(\d+)\s*px").ok()?;
    for (_, line) in super::spec_section(spec, "B11.7") {
        if !word(line, "responsive") || !word(line, "behavior") {
            continue;
        }
        let mut widths = re
            .captures_iter(line)
            .filter_map(|capture| capture.get(1))
            .filter_map(|value| value.as_str().parse::<u32>().ok());
        let sidebar = widths.next()?;
        let tables = widths.next()?;
        return Some((sidebar, tables));
    }
    None
}

/// The text of the `#### S-nnn` specification block, for the data-dense column check.
fn spec_screen_text(spec: &str, id: &str) -> Option<String> {
    let title = format!("{id} ");
    let mut inside = false;
    let mut out = String::new();
    for raw in spec.lines() {
        let text = raw.trim_start();
        if inside {
            if text.starts_with('#') {
                break;
            }
            out.push_str(raw);
            out.push(' ');
        } else if text.starts_with("#### ") {
            let rest = text.trim_start_matches('#').trim_start();
            if rest.starts_with(&title) || rest == id {
                inside = true;
            }
        }
    }
    let trimmed = out.trim();
    if trimmed.is_empty() {
        None
    } else {
        Some(trimmed.to_owned())
    }
}

/// The `S-nnn` references of a cell.
fn screen_refs(cell: &str, re: &Regex) -> Vec<String> {
    re.find_iter(cell)
        .map(|found| found.as_str().to_owned())
        .collect()
}

/// The number of whitespace-separated words in `text`.
fn word_count(text: &str) -> usize {
    text.split_whitespace().count()
}

/// The `## Security-critical controls` table, with the four columns every rule of this family needs.
fn controls_table(text: &str) -> Result<Table, Vec<Finding>> {
    let (header, rows) = table_or(text, "Security-critical controls", "T-0024 note")?;
    if column(&header, "Control").is_none()
        || column(&header, "Screens").is_none()
        || column(&header, "Small-screen treatment").is_none()
        || column(&header, "Why it cannot be hidden").is_none()
    {
        return Err(vec![at(
            "the `## Security-critical controls` table needs the columns `Control`, `Screens`, `Small-screen treatment` and `Why it cannot be hidden` (T-0024 note)",
        )]);
    }
    Ok((header, rows))
}

/// The reason after an `excluded:` control name, or `None` for a covered control row.
fn excluded_reason(control: &str) -> Option<String> {
    control
        .trim()
        .to_lowercase()
        .strip_prefix("excluded:")
        .map(|reason| reason.trim().to_owned())
}

/// The distinct words of `text` that are long enough to identify an action (F-22 exclusion matching).
fn distinctive_words(text: &str) -> BTreeSet<String> {
    text.split(|c: char| !c.is_ascii_alphanumeric())
        .map(str::to_ascii_lowercase)
        .filter(|word| word.len() >= 5 && !GENERIC_ACTION_WORDS.contains(&word.as_str()))
        .collect()
}

/// True when the two texts share a distinctive word (the `excluded:` row names the catalog action).
fn shares_distinctive_word(left: &str, right: &str) -> bool {
    let left_words = distinctive_words(left);
    distinctive_words(right)
        .iter()
        .any(|word| left_words.contains(word))
}

/// The margin numbers stated with `mm margins` in `text`, in ascending order.
fn margin_values(text: &str) -> BTreeSet<u32> {
    let mut out = BTreeSet::new();
    let Ok(re) = Regex::new(r"(?i)(\d{1,4})\s*mm\s+margins?\b") else {
        return out;
    };
    for capture in re.captures_iter(text) {
        if let Some(value) = capture
            .get(1)
            .and_then(|value| value.as_str().parse::<u32>().ok())
        {
            out.insert(value);
        }
    }
    out
}

/// True when a catalog row on one of `screens` carries the self-lockout preview the control promises
/// (F-21): the self-lockout control is cross-checked through the dangerous-actions catalog, not a gap.
fn catalog_names_self_lockout_preview(catalog: &str, screens: &[String]) -> bool {
    let Some((header, rows)) = section_table(catalog, "Catalog") else {
        return false;
    };
    let (Some(col_screen), Some(col_safeguards)) =
        (column(&header, "Screen"), column(&header, "Safeguards"))
    else {
        return false;
    };
    let Ok(id_re) = Regex::new(r"\bS-\d{3}\b") else {
        return false;
    };
    rows.iter().any(|(_, row)| {
        word(cell(row, Some(col_safeguards)), "self-lockout preview")
            && screen_refs(cell(row, Some(col_screen)), &id_re)
                .iter()
                .any(|screen| screens.iter().any(|owned| owned == screen))
    })
}

// ---------------------------------------------------------------------------------------------------------
// Rules: one documented function per rule. The failing run before these bodies existed is kept as
// `docs/evidence/P01/T-0024-red.txt`.
// ---------------------------------------------------------------------------------------------------------

/// T-0024 steps 1 to 8: the document opens with a title and carries every required level-2 section.
fn sections_findings(text: &str) -> Vec<Finding> {
    let mut out = Vec::new();
    let first = text
        .lines()
        .find(|line_text| !line_text.trim().is_empty())
        .unwrap_or_default();
    if !first.trim_start().starts_with("# ") || !word(first, "Responsive") {
        out.push(at(
            "the document must open with a `# ` title that names the responsive strategy (T-0024)",
        ));
    }
    for (title, step) in SECTIONS {
        match section_body(text, title) {
            None => out.push(at(format!("no `## {title}` section ({step})"))),
            Some(lines)
                if lines
                    .iter()
                    .all(|(_, line_text)| line_text.trim().is_empty()) =>
            {
                out.push(at(format!("`## {title}` has no body ({step})")));
            }
            Some(_) => {}
        }
    }
    out
}

/// T-0024 step 1 and A1: the breakpoints table matches the B11.4 `Breakpoints` row and its containers.
fn breakpoint_findings(text: &str, spec: &str) -> Vec<Finding> {
    let Some((points, containers)) = spec_breakpoints(spec) else {
        return vec![at(
            "the `Breakpoints` row of spec B11.4 cannot be read, so the document breakpoints cannot be checked (T-0024 step 1)",
        )];
    };
    let (header, rows) = match table_or(text, "Breakpoints", "T-0024 step 1") {
        Ok(table) => table,
        Err(findings) => return findings,
    };
    let mut out = Vec::new();
    let (Some(col_breakpoint), Some(col_width), Some(col_fluid)) = (
        column(&header, "Breakpoint"),
        column(&header, "Min width"),
        column(&header, "Fluid behaviour"),
    ) else {
        return vec![at(
            "the `## Breakpoints` table needs the columns `Breakpoint`, `Min width` and `Fluid behaviour` (T-0024 step 1)",
        )];
    };
    if rows.len() != points.len() {
        out.push(at(format!(
            "the `## Breakpoints` table has {} rows; B11.4 names {} breakpoints",
            rows.len(),
            points.len()
        )));
    }
    for (index, (n, row)) in rows.iter().enumerate() {
        let Some(expected) = points.get(index) else {
            break;
        };
        let width = cell(row, Some(col_width)).trim();
        let found = numbers(width);
        if !width.to_lowercase().contains("px")
            || found.len() != 1
            || found.first() != Some(expected)
        {
            out.push(line(
                *n,
                format!(
                    "row {} names the width `{width}`; the B11.4 breakpoint is `{expected} px` (T-0024 step 1)",
                    index + 1
                ),
            ));
        }
        let label = cell(row, Some(col_breakpoint)).trim();
        if !numbers(label).contains(expected) {
            out.push(line(
                *n,
                format!(
                    "the `Breakpoint` cell `{label}` does not name the B11.4 breakpoint {expected} px"
                ),
            ));
        }
        if cell(row, Some(col_fluid)).trim().is_empty() {
            out.push(line(
                *n,
                format!("the B11.4 breakpoint {expected} px has no fluid behaviour"),
            ));
        }
    }
    let body = section_body(text, "Breakpoints").unwrap_or_default();
    for maximum in &containers {
        let stated = body.iter().any(|(_, line_text)| {
            numbers(line_text).contains(maximum) && word(line_text, "container")
        });
        if !stated {
            out.push(at(format!(
                "the B11.4 container maximum of {maximum} px is not stated with the word `container` (T-0024 step 1)"
            )));
        }
    }
    if !body
        .iter()
        .any(|(_, line_text)| !line_text.trim_start().starts_with('|') && word(line_text, "fluid"))
    {
        out.push(at(
            "the breakpoint section does not say that layouts are fluid between the breakpoints (T-0024 step 1)",
        ));
    }
    // F-24: the last breakpoint row states a testable behaviour instead of saying that it "may" add cards.
    match spec_card_minimum(spec) {
        None => out.push(at(
            "the `Grid` bullet of spec B11.7 cannot be read, so the last breakpoint behaviour cannot be checked (T-0024 F-24)",
        )),
        Some(card_minimum) => match (points.last(), rows.get(points.len().saturating_sub(1))) {
            (Some(last_point), Some((n, row))) => {
                let fluid = cell(row, Some(col_fluid));
                let cap = containers.first().copied().unwrap_or_default();
                if !numbers(fluid).contains(&card_minimum) || !numbers(fluid).contains(&cap) {
                    out.push(line(
                        *n,
                        format!(
                            "the {last_point} px breakpoint row does not define its behaviour: it must state the B11.7 card minimum of {card_minimum} px and the {cap} px container maximum so the row is testable (T-0024 F-24)"
                        ),
                    ));
                }
            }
            _ => out.push(at(
                "the `## Breakpoints` table has no row for the last B11.4 breakpoint (T-0024 F-24)",
            )),
        },
    }
    out
}

/// T-0024 step 1: the B11.7 transformations (sidebar drawer, table cards, scroll regions, wizards).
fn layout_findings(text: &str, spec: &str) -> Vec<Finding> {
    let Some((sidebar, tables)) = spec_layout(spec) else {
        return vec![at(
            "the `Responsive behavior` bullet of spec B11.7 cannot be read (T-0024 step 1)",
        )];
    };
    let (header, rows) = match table_or(text, "Layout transformations", "T-0024 step 1") {
        Ok(table) => table,
        Err(findings) => return findings,
    };
    let (Some(col_region), Some(col_change), Some(col_width), Some(col_behaviour)) = (
        column(&header, "Region"),
        column(&header, "Transformation"),
        column(&header, "Width"),
        column(&header, "Behaviour"),
    ) else {
        return vec![at(
            "the `## Layout transformations` table needs the columns `Region`, `Transformation`, `Width` and `Behaviour` (T-0024 step 1)",
        )];
    };
    let mut out = Vec::new();
    let find = |needle: &str| {
        rows.iter()
            .find(|(_, row)| word(cell(row, Some(col_region)), needle))
    };
    match find("sidebar") {
        None => out.push(at(
            "no `Sidebar` row states the B11.7 drawer transformation",
        )),
        Some((n, row)) => {
            if !word(cell(row, Some(col_change)), "drawer") {
                out.push(line(*n, "the sidebar row does not become a drawer (B11.7)"));
            }
            let width = cell(row, Some(col_width));
            if !word(width, "below") || !numbers(width).contains(&sidebar) {
                out.push(line(
                    *n,
                    format!(
                        "the sidebar drawer applies at `{width}`; B11.7 places it below {sidebar} px"
                    ),
                ));
            }
            if cell(row, Some(col_behaviour)).trim().is_empty() {
                out.push(line(*n, "the sidebar drawer row has no behaviour"));
            }
        }
    }
    match find("tables") {
        None => out.push(at("no `Tables` row states the B11.7 card transformation")),
        Some((n, row)) => {
            let change = cell(row, Some(col_change));
            let width = cell(row, Some(col_width));
            let behaviour = cell(row, Some(col_behaviour));
            let exception = format!("{change} {width}");
            if !word(change, "cards") {
                out.push(line(*n, "the tables row does not become cards (B11.7)"));
            }
            if !word(width, "below") || !numbers(width).contains(&tables) {
                out.push(line(
                    *n,
                    format!(
                        "the table cards apply at `{width}`; B11.7 places them below {tables} px"
                    ),
                ));
            }
            for requirement in ["only", "where", "primary", "data"] {
                if !word(&exception, requirement) {
                    out.push(line(
                        *n,
                        format!(
                            "the table cards must apply only where scrolling would hide primary data (B11.7; `{requirement}` is missing)"
                        ),
                    ));
                }
            }
            if !word(&exception, "horizontal")
                || (!word(&exception, "scroll") && !word(&exception, "scrolling"))
            {
                out.push(line(
                    *n,
                    "the tables row does not mention horizontal scrolling (B11.7)",
                ));
            }
            if !word(behaviour, "focusable") || !word(behaviour, "scroll hint") {
                out.push(line(
                    *n,
                    "the non-card table region must be focusable and carry a visible scroll hint (B11.7)",
                ));
            }
        }
    }
    match find("wizards") {
        None => out.push(at(
            "no `Wizards` row states the single-column rule (T-0024 step 1)",
        )),
        Some((n, row)) => {
            if !word(cell(row, Some(col_change)), "single column") {
                out.push(line(
                    *n,
                    "wizards must be single column at every width (T-0024 step 1)",
                ));
            }
        }
    }
    out
}

/// T-0024 step 2, A1 and A5: the seven-viewport matrix with themes, directions, tablets and landscape.
fn device_matrix_findings(text: &str) -> Vec<Finding> {
    let (header, rows) = match table_or(text, "Device matrix", "T-0024 step 2") {
        Ok(table) => table,
        Err(findings) => return findings,
    };
    let (Some(col_view), Some(col_class), Some(col_theme), Some(col_direction), Some(col_verified)) = (
        column(&header, "Viewport"),
        column(&header, "Device class"),
        column(&header, "Themes"),
        column(&header, "Direction"),
        column(&header, "What is verified"),
    ) else {
        return vec![at(
            "the `## Device matrix` table needs the columns `Viewport`, `Device class`, `Themes`, `Direction` and `What is verified` (T-0024 step 2)",
        )];
    };
    let mut out = Vec::new();
    if rows.len() != VIEWPORTS.len() {
        out.push(at(format!(
            "the device matrix has {} rows; T-0024 step 2 names exactly seven viewports",
            rows.len()
        )));
    }
    let mut seen = BTreeSet::new();
    let mut landscape = false;
    let mut tablet = false;
    for (n, row) in &rows {
        let view = cell(row, Some(col_view));
        let Some(viewport) = viewport_key(view) else {
            out.push(line(
                *n,
                format!("the viewport cell `{view}` has no `width x height` pair"),
            ));
            continue;
        };
        if !VIEWPORTS.contains(&viewport.as_str()) {
            out.push(line(
                *n,
                format!("`{viewport}` is not one of the seven viewports of T-0024 step 2"),
            ));
        }
        if !seen.insert(viewport.clone()) {
            out.push(line(
                *n,
                format!("the viewport `{viewport}` appears more than once in the matrix"),
            ));
        }
        landscape |= is_landscape(&viewport);
        tablet |= word(cell(row, Some(col_class)), "tablet");
        let themes = cell(row, Some(col_theme));
        if !word(themes, "light") || !word(themes, "dark") {
            out.push(line(
                *n,
                format!("the themes cell `{themes}` must name both light and dark (T-0024 step 2)"),
            ));
        }
        let direction = cell(row, Some(col_direction));
        if !word(direction, "LTR") || !word(direction, "pseudo-RTL") {
            out.push(line(
                *n,
                format!(
                    "the direction cell `{direction}` must name both LTR and pseudo-RTL (T-0024 step 2)"
                ),
            ));
        }
        if cell(row, Some(col_verified)).trim().is_empty() {
            out.push(line(*n, "the `What is verified` cell is empty"));
        }
    }
    for viewport in VIEWPORTS {
        if !seen.contains(viewport) {
            out.push(at(format!(
                "the viewport `{viewport}` is missing from the matrix (T-0024 step 2)"
            )));
        }
    }
    if !tablet {
        out.push(at(
            "no device matrix row is a tablet; T-0024 A5 requires tablets to be covered",
        ));
    }
    if !landscape {
        out.push(at(
            "no device matrix row is landscape; T-0024 A5 requires landscape screens to be covered",
        ));
    }
    let body = section_body(text, "Device matrix").unwrap_or_default();
    if !body.iter().any(|(_, line_text)| word(line_text, "T-0090")) {
        out.push(at(
            "the device matrix does not say that T-0090 uses it (T-0024 A1)",
        ));
    }
    out
}

/// T-0024 step 3, A5: target sizes from B11.4, hover alternatives, keyboard paths and orientation.
fn input_modalities_findings(text: &str, spec: &str) -> Vec<Finding> {
    let Some((default_px, touch_px)) = spec_targets(spec) else {
        return vec![at(
            "the `Control heights` row of spec B11.4 cannot be read (T-0024 step 3)",
        )];
    };
    let (header, rows) = match table_or(text, "Input modalities", "T-0024 step 3") {
        Ok(table) => table,
        Err(findings) => return findings,
    };
    let (Some(col_modality), Some(col_requirement), Some(col_value)) = (
        column(&header, "Modality"),
        column(&header, "Requirement"),
        column(&header, "Value"),
    ) else {
        return vec![at(
            "the `## Input modalities` table needs the columns `Modality`, `Requirement` and `Value` (T-0024 step 3)",
        )];
    };
    let mut out = Vec::new();
    let touch_floor = input_row(
        &rows,
        col_modality,
        col_requirement,
        "touch targets",
        "smallest",
    );
    if touch_floor.is_none() {
        out.push(at(
            "no input-modality row for the minimum touch target (T-0024 step 3)",
        ));
    }
    if let Some((n, row)) = touch_floor {
        let value = cell(row, Some(col_value));
        if !numbers(value).contains(&MIN_TARGET_CSS_PX) || !word(value, "CSS") || !word(value, "px")
        {
            out.push(line(
                *n,
                format!(
                    "the minimum target cell `{value}` must state {MIN_TARGET_CSS_PX} CSS px (T-0024 step 3 and B11.11 2.5.8)"
                ),
            ));
        }
    }
    let default_height = input_row(
        &rows,
        col_modality,
        col_requirement,
        "touch targets",
        "default",
    );
    if default_height.is_none() {
        out.push(at(
            "no input-modality row for the default control height (T-0024 step 3)",
        ));
    }
    if let Some((n, row)) = default_height {
        let value = cell(row, Some(col_value));
        if !numbers(value).contains(&default_px) || !word(value, "px") {
            out.push(line(
                *n,
                format!(
                    "the default control-height cell `{value}` must state {default_px} px (B11.4)"
                ),
            ));
        }
    }
    let touch_height = input_row(
        &rows,
        col_modality,
        col_requirement,
        "touch targets",
        "touch",
    );
    if touch_height.is_none() {
        out.push(at(
            "no input-modality row for the touch control height (T-0024 step 3)",
        ));
    }
    if let Some((n, row)) = touch_height {
        let value = cell(row, Some(col_value));
        if !numbers(value).contains(&touch_px) || !word(value, "px") {
            out.push(line(
                *n,
                format!("the touch control-height cell `{value}` must state {touch_px} px (B11.4)"),
            ));
        }
    }
    let hover = input_row(&rows, col_modality, col_requirement, "hover", "");
    if hover.is_none() {
        out.push(at(
            "no input-modality row for the hover alternative (T-0024 step 3)",
        ));
    }
    if let Some((n, row)) = hover {
        let value = cell(row, Some(col_value));
        if !word(value, "focus") || (!word(value, "tap") && !word(value, "touch")) {
            out.push(line(
                *n,
                "the hover row must give a focus and touch path for the same detail (WCAG 1.4.13)",
            ));
        }
    }
    let keyboard = input_row(&rows, col_modality, col_requirement, "keyboard", "");
    if keyboard.is_none() {
        out.push(at(
            "no input-modality row for the keyboard path (T-0024 step 3)",
        ));
    }
    if let Some((n, row)) = keyboard {
        let value = cell(row, Some(col_value));
        if !word(value, "tab") || !word(value, "escape") || !word(value, "focus") {
            out.push(line(
                *n,
                "the keyboard row must state the Tab order, Enter or Space activation, Escape and focus return (B11.11 2.1.x)",
            ));
        }
    }
    let orientation = input_row(&rows, col_modality, col_requirement, "orientation", "");
    if orientation.is_none() {
        out.push(at("no input-modality row for orientation (T-0024 step 3)"));
    }
    if let Some((n, row)) = orientation {
        let value = cell(row, Some(col_value));
        if !word(value, "portrait") || !word(value, "landscape") || !word(value, "lock") {
            out.push(line(
                *n,
                "the orientation row must state portrait and landscape and that orientation is not locked (B11.11 1.3.x, T-0024 A5)",
            ));
        }
    }
    let body = section_body(text, "Input modalities").unwrap_or_default();
    if !body
        .iter()
        .any(|(_, line_text)| word(line_text, "landscape") && word(line_text, "phone"))
    {
        out.push(at(
            "the input section does not cover landscape phones; T-0024 A5 names them",
        ));
    }
    if !body.iter().any(|(_, line_text)| word(line_text, "tablet")) {
        out.push(at(
            "the input section does not cover tablets; T-0024 A5 names them",
        ));
    }
    out
}

/// T-0024 step 1, A2: one small-screen behaviour row per screen category, with real screens.
fn screen_categories_findings(text: &str, spec: &str) -> Vec<Finding> {
    let screens = super::screen_ids(spec);
    if screens.is_empty() {
        return vec![at(
            "the B12.1 screen table cannot be read from the specification, so screen categories cannot be checked (T-0024 A2)",
        )];
    }
    let (header, rows) = match table_or(text, "Screen categories", "T-0024 A2") {
        Ok(table) => table,
        Err(findings) => return findings,
    };
    let (Some(col_category), Some(col_behaviour), Some(col_screens)) = (
        column(&header, "Category"),
        column(&header, "Small-screen behaviour"),
        column(&header, "Screens"),
    ) else {
        return vec![at(
            "the `## Screen categories` table needs the columns `Category`, `Small-screen behaviour` and `Screens` (T-0024 A2)",
        )];
    };
    let Ok(id_re) = Regex::new(r"\bS-\d{3}\b") else {
        return vec![at("internal: the `S-nnn` pattern failed to compile")];
    };
    let mut out = Vec::new();
    for (category, allowed) in SCREEN_CATEGORIES {
        let count = rows
            .iter()
            .filter(|(_, row)| {
                cell(row, Some(col_category))
                    .trim()
                    .eq_ignore_ascii_case(category)
            })
            .count();
        let Some((n, row)) = rows.iter().find(|(_, row)| {
            cell(row, Some(col_category))
                .trim()
                .eq_ignore_ascii_case(category)
        }) else {
            out.push(at(format!(
                "no small-screen behaviour row for the screen category `{category}` (T-0024 A2)"
            )));
            continue;
        };
        if count > 1 {
            out.push(line(
                *n,
                format!("the screen category `{category}` has {count} rows; one is enough"),
            ));
        }
        let behaviour = cell(row, Some(col_behaviour));
        if behaviour.trim().is_empty() {
            out.push(line(
                *n,
                format!("the `{category}` row has no small-screen behaviour"),
            ));
        } else if !BEHAVIOUR_WORDS.iter().any(|needle| word(behaviour, needle)) {
            out.push(line(
                *n,
                format!(
                    "the `{category}` row does not describe a small-screen behaviour (T-0024 A2)"
                ),
            ));
        }
        let references = screen_refs(cell(row, Some(col_screens)), &id_re);
        if references.is_empty() {
            out.push(line(*n, format!("the `{category}` row names no screen")));
        }
        for reference in &references {
            if !screens.contains(reference) {
                out.push(line(
                    *n,
                    format!("`{reference}` in the `{category}` row is not a screen of B12.1"),
                ));
            }
        }
        if !references
            .iter()
            .any(|reference| allowed.contains(&reference.as_str()))
        {
            out.push(line(
                *n,
                format!(
                    "the `{category}` row must name at least one of {}",
                    allowed.join(", ")
                ),
            ));
        }
        if let Some((_, required)) = REQUIRED_CATEGORY_SCREENS
            .iter()
            .find(|(name, _)| *name == category)
        {
            for required_screen in *required {
                if !references
                    .iter()
                    .any(|reference| reference == required_screen)
                {
                    out.push(line(
                        *n,
                        format!("the `{category}` row must name `{required_screen}` (T-0024)"),
                    ));
                }
            }
        }
    }
    out
}

/// T-0024 note and F-22: every required security-critical control stays visible and never moves into
/// an overflow menu, and every list row names a real B12.1 screen that owns the control.
fn security_controls_findings(text: &str, spec: &str) -> Vec<Finding> {
    let screens = super::screen_ids(spec);
    if screens.is_empty() {
        return vec![at(
            "the B12.1 screen table cannot be read from the specification, so the security-critical controls cannot be checked (T-0024 note)",
        )];
    }
    let (header, rows) = match controls_table(text) {
        Ok(table) => table,
        Err(findings) => return findings,
    };
    let (Some(col_control), Some(col_screens), Some(col_treatment), Some(col_why)) = (
        column(&header, "Control"),
        column(&header, "Screens"),
        column(&header, "Small-screen treatment"),
        column(&header, "Why it cannot be hidden"),
    ) else {
        return vec![at(
            "the `## Security-critical controls` table needs the columns `Control`, `Screens`, `Small-screen treatment` and `Why it cannot be hidden` (T-0024 note)",
        )];
    };
    let Ok(id_re) = Regex::new(r"\bS-\d{3}\b") else {
        return vec![at("internal: the `S-nnn` pattern failed to compile")];
    };
    let mut out = Vec::new();
    for (control, allowed) in REQUIRED_CONTROLS {
        let Some((n, row)) = rows
            .iter()
            .find(|(_, row)| word(cell(row, Some(col_control)), control))
        else {
            out.push(at(format!(
                "the security-critical control `{control}` is not listed; it must stay reachable on a small screen (T-0024 note)"
            )));
            continue;
        };
        let treatment = cell(row, Some(col_treatment));
        if !["visible", "reachable", "stays", "stay"]
            .iter()
            .any(|needle| word(treatment, needle))
        {
            out.push(line(
                *n,
                format!(
                    "the `{control}` row does not say how the control stays visible or reachable (T-0024 note)"
                ),
            ));
        }
        for hide in [
            "hidden",
            "hides",
            "hide",
            "overflow",
            "collapsed",
            "hover-only",
        ] {
            if word(treatment, hide)
                && !word(treatment, "never")
                && !word(treatment, "not")
                && !word(treatment, "no")
            {
                out.push(line(
                    *n,
                    format!(
                        "the `{control}` row moves a security-critical control into `{hide}`; it must stay visible (T-0024 note)"
                    ),
                ));
            }
        }
        let references = screen_refs(cell(row, Some(col_screens)), &id_re);
        for reference in &references {
            if !screens.contains(reference) {
                out.push(line(
                    *n,
                    format!("`{reference}` in the `{control}` row is not a screen of B12.1"),
                ));
            }
        }
        if !references
            .iter()
            .any(|reference| allowed.contains(&reference.as_str()))
        {
            out.push(line(
                *n,
                format!(
                    "the `{control}` row must name one of {}",
                    allowed.join(", ")
                ),
            ));
        }
        if cell(row, Some(col_why)).trim().is_empty() {
            out.push(line(*n, format!("the `{control}` row has no reason")));
        }
    }
    let body = section_body(text, "Security-critical controls").unwrap_or_default();
    // Only the prose states the rule: the table header itself carries `never-ban`, `hidden` and
    // `Small-screen`, so scanning table lines would make the rule true by accident.
    let prose: Vec<&str> = body
        .iter()
        .map(|(_, line_text)| line_text.as_str())
        .filter(|line_text| !line_text.trim_start().starts_with('|'))
        .collect();
    let prose_has = |needle: &str| prose.iter().any(|line_text| word(line_text, needle));
    let rule_stated =
        prose_has("never") && prose_has("hidden") && prose_has("small") && prose_has("screen");
    if !rule_stated {
        out.push(at(
            "the section does not state the rule that security-critical controls are never hidden on a small screen (T-0024 note)",
        ));
    }
    out
}

/// T-0024 step 6: a content-priority row per breakpoint, with security controls never in overflow.
fn content_priority_findings(text: &str, spec: &str) -> Vec<Finding> {
    let Some((points, _)) = spec_breakpoints(spec) else {
        return vec![at(
            "the `Breakpoints` row of spec B11.4 cannot be read, so content priority cannot be checked (T-0024 step 6)",
        )];
    };
    let (header, rows) = match table_or(text, "Content priority", "T-0024 step 6") {
        Ok(table) => table,
        Err(findings) => return findings,
    };
    let (Some(col_breakpoint), Some(col_always), Some(col_overflow), Some(col_never)) = (
        column(&header, "Breakpoint"),
        column(&header, "Always visible"),
        column(&header, "Moves to overflow"),
        column(&header, "Never moves"),
    ) else {
        return vec![at(
            "the `## Content priority` table needs the columns `Breakpoint`, `Always visible`, `Moves to overflow` and `Never moves` (T-0024 step 6)",
        )];
    };
    let mut out = Vec::new();
    if rows.len() < 4 {
        out.push(at(format!(
            "the content-priority table has {} rows; it must cover the B11.4 breakpoints (T-0024 step 6)",
            rows.len()
        )));
    }
    for (n, row) in &rows {
        for (label, index) in [
            ("Always visible", col_always),
            ("Moves to overflow", col_overflow),
            ("Never moves", col_never),
        ] {
            if cell(row, Some(index)).trim().is_empty() {
                out.push(line(
                    *n,
                    format!("the content-priority row has an empty `{label}` cell"),
                ));
            }
        }
        let overflow = cell(row, Some(col_overflow));
        for (control, _) in REQUIRED_CONTROLS {
            if word(overflow, control) {
                out.push(line(
                    *n,
                    format!(
                        "the security-critical control `{control}` is placed in the overflow menu; it must never move (T-0024 note)"
                    ),
                ));
            }
        }
    }
    for point in &points {
        if !rows
            .iter()
            .any(|(_, row)| numbers(cell(row, Some(col_breakpoint))).contains(point))
        {
            out.push(at(format!(
                "no content-priority row covers the B11.4 breakpoint {point} px (T-0024 step 6)"
            )));
        }
    }
    if !rows.iter().any(|(_, row)| {
        REQUIRED_CONTROLS
            .iter()
            .any(|(control, _)| word(cell(row, Some(col_never)), control))
    }) {
        out.push(at(
            "no content-priority row lists a security-critical control under `Never moves` (T-0024 note)",
        ));
    }
    out
}

/// T-0024 step 7: S-065 keeps real columns and moves the rest to the S-066 drawer.
fn data_dense_findings(text: &str, spec: &str) -> Vec<Finding> {
    let screens = super::screen_ids(spec);
    if screens.is_empty() {
        return vec![at(
            "the B12.1 screen table cannot be read from the specification, so the data-dense screens cannot be checked (T-0024 step 7)",
        )];
    }
    let Some(monitor) = spec_screen_text(spec, "S-065") else {
        return vec![at(
            "the S-065 block of spec B12.2 cannot be read, so its columns cannot be checked (T-0024 step 7)",
        )];
    };
    let (header, rows) = match table_or(text, "Data-dense screens", "T-0024 step 7") {
        Ok(table) => table,
        Err(findings) => return findings,
    };
    let (Some(col_screen), Some(col_columns), Some(col_drawer), Some(col_behaviour)) = (
        column(&header, "Screen"),
        column(&header, "Persistent columns"),
        column(&header, "Moves to the drawer"),
        column(&header, "Behaviour"),
    ) else {
        return vec![at(
            "the `## Data-dense screens` table needs the columns `Screen`, `Persistent columns`, `Moves to the drawer` and `Behaviour` (T-0024 step 7)",
        )];
    };
    let Ok(id_re) = Regex::new(r"\bS-\d{3}\b") else {
        return vec![at("internal: the `S-nnn` pattern failed to compile")];
    };
    let mut out = Vec::new();
    let Some((n, row)) = rows.iter().find(|(_, row)| {
        screen_refs(cell(row, Some(col_screen)), &id_re)
            .iter()
            .any(|reference| reference == "S-065")
    }) else {
        return vec![at(
            "the `## Data-dense screens` table has no `S-065` row (T-0024 step 7)",
        )];
    };
    let columns = cell(row, Some(col_columns));
    let names: Vec<&str> = columns
        .split(',')
        .map(str::trim)
        .filter(|name| !name.is_empty())
        .collect();
    if names.len() < 3 {
        out.push(line(
            *n,
            format!(
                "the S-065 row lists {} persistent columns; at least three are needed (T-0024 step 7)",
                names.len()
            ),
        ));
    }
    for name in names.iter().copied() {
        if !word(&monitor, name) {
            out.push(line(
                *n,
                format!("`{name}` is not a column of S-065 in spec B12.2"),
            ));
        }
    }
    if cell(row, Some(col_drawer)).trim().is_empty() {
        out.push(line(
            *n,
            "the S-065 row does not say what moves to the drawer",
        ));
    }
    let body = section_body(text, "Data-dense screens").unwrap_or_default();
    if !body.iter().any(|(_, line_text)| word(line_text, "S-066")) {
        out.push(at(
            "the data-dense section does not name the event drawer S-066 (T-0024 step 7)",
        ));
    }
    if !body.iter().any(|(_, line_text)| word(line_text, "pause")) {
        out.push(at(
            "the data-dense section does not keep the pause control on screen (T-0024 step 7)",
        ));
    }
    for (n2, row2) in &rows {
        let references = screen_refs(cell(row2, Some(col_screen)), &id_re);
        for reference in &references {
            if !screens.contains(reference) {
                out.push(line(
                    *n2,
                    format!("`{reference}` in the data-dense table is not a screen of B12.1"),
                ));
            }
        }
        if cell(row2, Some(col_behaviour)).trim().is_empty() {
            out.push(line(*n2, "a data-dense row has no behaviour"));
        }
    }
    out
}

/// T-0024 step 5 and A4: numeric budgets for every device class, labelled as budgets.
fn performance_findings(text: &str) -> Vec<Finding> {
    let (header, rows) = match table_or(text, "Performance budgets", "T-0024 step 5") {
        Ok(table) => table,
        Err(findings) => return findings,
    };
    let names = [
        "Device class",
        "Profile",
        "LCP (ms)",
        "INP (ms)",
        "CLS",
        "JS (KiB)",
        "CSS (KiB)",
        "Requests",
    ];
    let mut out = Vec::new();
    let mut columns = Vec::new();
    for name in names {
        match column(&header, name) {
            Some(index) => columns.push(index),
            None => out.push(at(format!(
                "the `## Performance budgets` table has no `{name}` column; the unit belongs in the header (T-0024 A4)"
            ))),
        }
    }
    if columns.len() != names.len() {
        return out;
    }
    let (
        Some(&col_class),
        Some(&_col_profile),
        Some(&col_lcp),
        Some(&col_inp),
        Some(&col_cls),
        Some(&col_js),
        Some(&col_css),
        Some(&col_requests),
    ) = (
        columns.first(),
        columns.get(1),
        columns.get(2),
        columns.get(3),
        columns.get(4),
        columns.get(5),
        columns.get(6),
        columns.get(7),
    )
    else {
        return out;
    };
    for (label, needles) in BUDGET_CLASSES {
        let Some((n, row)) = rows.iter().find(|(_, row)| {
            needles
                .iter()
                .all(|needle| word(cell(row, Some(col_class)), needle))
        }) else {
            out.push(at(format!(
                "no performance budget row for the device class `{label}` (T-0024 A4)"
            )));
            continue;
        };
        for (name, index) in [
            ("LCP", col_lcp),
            ("INP", col_inp),
            ("JS", col_js),
            ("CSS", col_css),
            ("Requests", col_requests),
        ] {
            let value = cell(row, Some(index)).trim();
            match value.parse::<u32>() {
                Ok(number) if number > 0 => {}
                _ => out.push(line(
                    *n,
                    format!(
                        "the `{name}` cell of `{label}` is `{value}`; it must be a positive whole number with the unit in the header (T-0024 A4)"
                    ),
                )),
            }
        }
        let cls = cell(row, Some(col_cls)).trim();
        match cls.parse::<f64>() {
            Ok(value) if value > 0.0 && value <= 0.25 => {}
            _ => out.push(line(
                *n,
                format!(
                    "the `CLS` cell of `{label}` is `{cls}`; it must be a budget above 0 and at most 0.25 (T-0024 A4)"
                ),
            )),
        }
    }
    let body = section_body(text, "Performance budgets").unwrap_or_default();
    let has = |needle: &str| body.iter().any(|(_, line_text)| word(line_text, needle));
    for needle in ["budget", "Core", "Web", "Vitals", "T-0029", "T-0052"] {
        if !has(needle) {
            out.push(at(format!(
                "the performance section does not state `{needle}` (T-0024 A4)"
            )));
        }
    }
    if !has("measurement") && !has("measurements") {
        out.push(at(
            "the performance section does not say that the numbers are budgets and not measurements (T-0024 A4 and R-16)",
        ));
    }
    if !has("mobile") || !has("mid-range") {
        out.push(at(
            "the performance section does not name the mobile mid-range profile (T-0024 step 5)",
        ));
    }
    out
}

/// T-0024 step 4 and A3: report pages and audit exports have a complete print layout.
fn print_findings(text: &str, spec: &str) -> Vec<Finding> {
    let screens = super::screen_ids(spec);
    if screens.is_empty() {
        return vec![at(
            "the B12.1 screen table cannot be read from the specification, so the print rules cannot be checked (T-0024 A3)",
        )];
    }
    let (header, rows) = match table_or(text, "Printing and PDF", "T-0024 A3") {
        Ok(table) => table,
        Err(findings) => return findings,
    };
    let (
        Some(col_subject),
        Some(col_layout),
        Some(col_hidden),
        Some(col_breaks),
        Some(col_contrast),
    ) = (
        column(&header, "Subject"),
        column(&header, "Page layout"),
        column(&header, "Hidden in print"),
        column(&header, "Page breaks"),
        column(&header, "Contrast"),
    )
    else {
        return vec![at(
            "the `## Printing and PDF` table needs the columns `Subject`, `Page layout`, `Hidden in print`, `Page breaks` and `Contrast` (T-0024 A3)",
        )];
    };
    let Ok(id_re) = Regex::new(r"\bS-\d{3}\b") else {
        return vec![at("internal: the `S-nnn` pattern failed to compile")];
    };
    let mut out = Vec::new();
    let check_row = |out: &mut Vec<Finding>, subject: &str, required: &[&str]| {
        let Some((n, row)) = rows
            .iter()
            .find(|(_, row)| word(cell(row, Some(col_subject)), subject))
        else {
            out.push(at(format!(
                "the print table has no `{subject}` row (T-0024 A3)"
            )));
            return;
        };
        let row_text = row.join(" ");
        let references = screen_refs(&row_text, &id_re);
        for reference in &references {
            if !screens.contains(reference) {
                out.push(line(
                    *n,
                    format!("`{reference}` in the `{subject}` print row is not a screen of B12.1"),
                ));
            }
        }
        for screen in required {
            if !references.iter().any(|reference| reference == screen) {
                out.push(line(
                    *n,
                    format!("the `{subject}` print row must name `{screen}` (T-0024 step 4)"),
                ));
            }
        }
        for (label, index) in [
            ("Page layout", col_layout),
            ("Hidden in print", col_hidden),
            ("Page breaks", col_breaks),
            ("Contrast", col_contrast),
        ] {
            if cell(row, Some(index)).trim().is_empty() {
                out.push(line(
                    *n,
                    format!("the `{subject}` print row has an empty `{label}` cell"),
                ));
            }
        }
    };
    check_row(&mut out, "report", &["S-073", "S-074"]);
    check_row(&mut out, "audit", &["S-084"]);
    let body = section_body(text, "Printing and PDF").unwrap_or_default();
    let joined = body
        .iter()
        .map(|(_, line_text)| line_text.as_str())
        .collect::<Vec<_>>()
        .join("\n");
    for needle in [
        "A4", "mm", "header", "footer", "contrast", "tooltip", "printed", "audit",
    ] {
        if !word(&joined, needle) {
            out.push(at(format!(
                "the print section does not state `{needle}` (T-0024 step 4 and A3)"
            )));
        }
    }
    if !word(&joined, "page") || (!word(&joined, "break") && !word(&joined, "breaks")) {
        out.push(at(
            "the print section does not state the page-break rule (T-0024 step 4)",
        ));
    }
    if !body
        .iter()
        .any(|(_, line_text)| !line_text.trim_start().starts_with('|') && word(line_text, "hidden"))
    {
        out.push(at(
            "the print section does not say what is hidden in print (T-0024 step 4)",
        ));
    }
    out
}

/// T-0024 step 8 and A1: viewport helper, screenshot naming, stable names and T-0052 baselines.
fn testing_hooks_findings(text: &str) -> Vec<Finding> {
    let Some(body) = section_body(text, "Testing hooks") else {
        return Vec::new();
    };
    let joined = body
        .iter()
        .map(|(_, line_text)| line_text.as_str())
        .collect::<Vec<_>>()
        .join("\n");
    let mut out = Vec::new();
    for needle in [
        "viewport", "helper", "T-0090", "T-0052", "baseline", "stable", "matrix",
    ] {
        if !word(&joined, needle) {
            out.push(at(format!(
                "the testing hooks section does not state `{needle}` (T-0024 step 8 and A1)"
            )));
        }
    }
    for path in ["acceptance-ui/screens/", "design/baselines/"] {
        if !joined.contains(path) {
            out.push(at(format!(
                "the testing hooks section does not name the path `{path}` (T-0024 step 8; T-0047 step 5, T-0090 step 3)"
            )));
        }
    }
    if !joined.contains("<theme>-<viewport>.png") {
        out.push(at(
            "the screenshot naming rule `<state>-<theme>-<viewport>.png` is missing (T-0090 step 3)",
        ));
    }
    out
}

/// Every `S-nnn` cited in the document is a screen of the spec B12.1 table.
fn screen_reference_findings(text: &str, spec: &str) -> Vec<Finding> {
    let screens = super::screen_ids(spec);
    if screens.is_empty() {
        return vec![at(
            "the B12.1 screen table cannot be read from the specification, so cited screens cannot be checked",
        )];
    }
    let Ok(id_re) = Regex::new(r"\bS-\d{3}\b") else {
        return vec![at("internal: the `S-nnn` pattern failed to compile")];
    };
    let mut out = Vec::new();
    for (n, line_text) in super::prose_lines(text) {
        for reference in screen_refs(line_text, &id_re) {
            if !screens.contains(&reference) {
                out.push(line(
                    n,
                    format!("`{reference}` is not a screen of the spec B12.1 table"),
                ));
            }
        }
    }
    out
}

/// R-01: no empty, dash-only or placeholder table cell anywhere in the document.
fn placeholder_findings(text: &str) -> Vec<Finding> {
    let mut out = Vec::new();
    for (n, line_text) in super::prose_lines(text) {
        let Some(row) = super::cells(line_text) else {
            continue;
        };
        let separator = row
            .iter()
            .all(|value| !value.is_empty() && value.chars().all(|c| c == '-' || c == ':'));
        if separator {
            continue;
        }
        for value in &row {
            let value = value.trim();
            if value.is_empty() {
                out.push(line(n, "a table cell is empty (R-01)"));
                continue;
            }
            if value == "-" || value == "?" || value == "\u{2013}" {
                out.push(line(
                    n,
                    format!("the table cell `{value}` is a placeholder (R-01)"),
                ));
                continue;
            }
            for placeholder in PLACEHOLDERS {
                if word(value, placeholder) {
                    out.push(line(
                        n,
                        format!(
                            "the table cell `{value}` contains the placeholder `{placeholder}` (R-01)"
                        ),
                    ));
                }
            }
        }
    }
    out
}

/// The whole T-0024 check on the repository at `root`, reading the checksum-verified master specification.
pub fn check(root: &Path) -> Vec<Finding> {
    match crate::spec::load_master(root) {
        Ok(spec) => check_with_spec(root, &spec),
        Err(e) => vec![super::finding(
            "docs/SPEC.md",
            format!("cannot read the master specification: {}", e.0),
        )],
    }
}

/// The bold surface headings of the spec B12.1 screen table and the screens listed under each one.
fn b12_groups(spec: &str) -> BTreeMap<String, BTreeSet<String>> {
    let mut groups: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    let mut current: Option<String> = None;
    let mut in_section = false;
    let Ok(id_re) = Regex::new(r"\bS-\d{3}\b") else {
        return groups;
    };
    for line in spec.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with("### B12.1") {
            in_section = true;
            continue;
        }
        if !in_section {
            continue;
        }
        if trimmed.starts_with("### ") {
            break;
        }
        if let Some(name) = trimmed
            .strip_prefix("**")
            .and_then(|rest| rest.strip_suffix("**"))
        {
            let name = name.trim().to_owned();
            groups.entry(name.clone()).or_default();
            current = Some(name);
            continue;
        }
        if let (Some(group), Some(first)) = (
            current.as_ref(),
            cells(trimmed).and_then(|row| row.first().cloned()),
        ) {
            for id in screen_refs(&first, &id_re) {
                groups.entry(group.clone()).or_default().insert(id);
            }
        }
    }
    groups
}

/// T-0024 A2 (the review brief): one small-screen behaviour row for every screen category of the
/// spec B12.1 group headings. The row's Category must name the group (case-insensitive) and its
/// Screens cell must contain at least one real screen of that group. A missing group, an empty
/// behaviour or a screen from another group is a finding.
fn surface_categories_findings(text: &str, spec: &str) -> Vec<Finding> {
    let groups = b12_groups(spec);
    if groups.is_empty() {
        return vec![at(
            "the B12.1 screen table has no bold surface headings, so the screen categories cannot be derived from the specification (T-0024 A2)",
        )];
    }
    let (header, rows) = match table_or(text, "Screen categories", "T-0024 A2") {
        Ok(table) => table,
        Err(findings) => return findings,
    };
    let (Some(col_category), Some(col_behaviour), Some(col_screens)) = (
        column(&header, "Category"),
        column(&header, "Small-screen behaviour"),
        column(&header, "Screens"),
    ) else {
        return vec![at(
            "the `## Screen categories` table needs the columns `Category`, `Small-screen behaviour` and `Screens` (T-0024 A2)",
        )];
    };
    let Ok(id_re) = Regex::new(r"\bS-\d{3}\b") else {
        return vec![at("internal: the `S-nnn` pattern failed to compile")];
    };
    let mut out = Vec::new();
    for (group, members) in &groups {
        let row = rows.iter().find(|(_, row)| {
            cell(row, Some(col_category))
                .trim()
                .eq_ignore_ascii_case(group)
        });
        let Some((number, row)) = row else {
            out.push(at(format!(
                "no small-screen behaviour row for the B12.1 surface category `{group}` (T-0024 A2)"
            )));
            continue;
        };
        if cell(row, Some(col_behaviour)).trim().is_empty() {
            out.push(line(
                *number,
                format!("the `{group}` row has no small-screen behaviour (T-0024 A2)"),
            ));
        }
        let referenced = screen_refs(cell(row, Some(col_screens)), &id_re);
        if referenced.is_empty() {
            out.push(line(*number, format!("the `{group}` row names no screen")));
            continue;
        }
        if !referenced.iter().any(|id| members.contains(id)) {
            out.push(line(
                *number,
                format!("the `{group}` row names no screen of that B12.1 surface (T-0024 A2)"),
            ));
        }
    }
    out
}

/// T-0024 note: the journey `Safeguards` risky-action phrases each security-critical control is
/// cross-checked against. The self-lockout control is not in this list: no journey names it as a
/// `Risky action`, so it is cross-checked through the dangerous-actions catalog instead (F-21).
const CONTROL_SAFEGUARD_TERMS: [(&str, &[&str]); 4] = [
    ("safe mode", &["safe mode", "safe-mode"]),
    (
        "block mode",
        &["block mode", "switch to block", "protection mode"],
    ),
    ("ban", &["ban", "banning", "ban-on-first-hit"]),
    ("unban", &["unban", "unbanning"]),
];

/// T-0024 note and F-21: cross-check the security-critical controls against what names them. The safe
/// mode, block mode, ban and unban controls must appear as a `Risky action` in at least one
/// `docs/UX/journeys/*.md` `Safeguards` table. The self-lockout control is cross-checked through
/// [`CATALOG`]: a dangerous-action row on one of the control's screens must carry the whole phrase
/// `self-lockout preview` in its `Safeguards`. There is no `gap:` escape: a missing cross-check is a
/// finding, and a review note is not a cross-check.
fn safeguard_crosscheck_findings(
    text: &str,
    journeys: &[(String, String)],
    catalog: Option<&str>,
) -> Vec<Finding> {
    let (header, rows) = match controls_table(text) {
        Ok(table) => table,
        Err(findings) => return findings,
    };
    let (Some(col_control), Some(col_screens), Some(col_why)) = (
        column(&header, "Control"),
        column(&header, "Screens"),
        column(&header, "Why it cannot be hidden"),
    ) else {
        return vec![at(
            "the `## Security-critical controls` table needs the columns `Control`, `Screens` and `Why it cannot be hidden` (T-0024 note)",
        )];
    };
    let Ok(id_re) = Regex::new(r"\bS-\d{3}\b") else {
        return vec![at("internal: the `S-nnn` pattern failed to compile")];
    };
    let mut risky: Vec<String> = Vec::new();
    for (_, journey) in journeys {
        let Some((journey_header, journey_rows)) = section_table(journey, "Safeguards") else {
            continue;
        };
        let Some(col_action) = column(&journey_header, "Risky action") else {
            continue;
        };
        for (_, row) in journey_rows {
            if let Some(action) = row.get(col_action) {
                risky.push(action.clone());
            }
        }
    }
    let mut out = Vec::new();
    for (control, terms) in CONTROL_SAFEGUARD_TERMS {
        let Some((number, _row)) = rows
            .iter()
            .find(|(_, row)| word(cell(row, Some(col_control)), control))
        else {
            continue;
        };
        let matched = risky
            .iter()
            .any(|action| terms.iter().any(|term| word(action, term)));
        if !matched {
            out.push(line(
                *number,
                format!(
                    "the security-critical control `{control}` has no matching Risky action in any journey `## Safeguards` table (T-0024 note)"
                ),
            ));
        }
    }
    // The self-lockout warning has no journey risky action, so it is cross-checked through the catalog.
    let lockout_row = rows
        .iter()
        .find(|(_, row)| word(cell(row, Some(col_control)), "lockout"));
    if let Some((number, row)) = lockout_row {
        let screens = screen_refs(cell(row, Some(col_screens)), &id_re);
        let matched =
            catalog.is_some_and(|catalog| catalog_names_self_lockout_preview(catalog, &screens));
        if !matched {
            out.push(line(
                *number,
                format!(
                    "the self-lockout warning is not cross-checked: no `{}` row on {} carries the whole phrase `self-lockout preview` in its `Safeguards` (T-0024 note, F-21)",
                    CATALOG,
                    screens.join(", ")
                ),
            ));
        }
        let why = cell(row, Some(col_why));
        if why.contains("gap:") {
            out.push(line(
                *number,
                "the self-lockout row still carries a `gap:` review note; the catalog names the self-lockout preview, so the note is false (F-21)",
            ));
        }
    }
    out
}

/// F-21: no table cell of the responsive document carries a review note (`gap:`). Review notes are not
/// published content; the one that existed in the self-lockout row was false once the catalog named
/// the self-lockout preview.
fn gap_note_findings(text: &str) -> Vec<Finding> {
    let mut out = Vec::new();
    for (n, line_text) in super::prose_lines(text) {
        let Some(row) = super::cells(line_text) else {
            continue;
        };
        for value in &row {
            if value.contains("gap:") {
                out.push(line(
                    n,
                    "a table cell contains a review note (`gap:`); a review note is not published content and the self-lockout one is false (F-21)",
                ));
            }
        }
    }
    out
}

/// F-22: each `Never moves` cell of the Content priority table names every control of the
/// Security-critical controls table, at every breakpoint. The control set is derived from the table,
/// so adding a control to the table without updating the breakpoint rows is a finding.
fn never_moves_findings(text: &str) -> Vec<Finding> {
    let (control_header, control_rows) = match controls_table(text) {
        Ok(table) => table,
        Err(findings) => return findings,
    };
    let Some(col_control) = column(&control_header, "Control") else {
        return Vec::new();
    };
    let controls: Vec<String> = control_rows
        .iter()
        .map(|(_, row)| cell(row, Some(col_control)).trim().to_owned())
        .filter(|control| !control.is_empty() && excluded_reason(control).is_none())
        .collect();
    if controls.is_empty() {
        return vec![at(
            "the `## Security-critical controls` table has no control row, so the `Never moves` cells cannot be checked (F-22)",
        )];
    }
    let (header, rows) = match table_or(text, "Content priority", "T-0024 step 6") {
        Ok(table) => table,
        Err(findings) => return findings,
    };
    let Some(col_never) = column(&header, "Never moves") else {
        return vec![at(
            "the `## Content priority` table has no `Never moves` column (T-0024 step 6)",
        )];
    };
    let mut out = Vec::new();
    for (n, row) in &rows {
        let never = cell(row, Some(col_never));
        if never.trim().is_empty() {
            continue;
        }
        for control in &controls {
            if !word(never, control) {
                out.push(line(
                    *n,
                    format!(
                        "the `Never moves` cell does not name the security-critical control `{control}`; every breakpoint names the same control set as the `## Security-critical controls` table (F-22)"
                    ),
                ));
            }
        }
    }
    out
}

/// F-22: every dangerous-actions catalog row whose `Safeguards` carry a whole `time box`, or whose
/// `Screen` is one of the screens of the Security-critical controls table, is either covered by a
/// control row (same screen and a reviewed action phrase, see [`CATALOG_ACTION_TERMS`]) or excluded by
/// an explicit `excluded: <reason>` row. An `excluded:` row must name the catalog action by a
/// distinctive word and state a reason; a filler exclusion is a finding.
fn catalog_coverage_findings(text: &str, catalog: Option<&str>) -> Vec<Finding> {
    let Some(catalog) = catalog else {
        return vec![at(format!(
            "the dangerous-actions catalog `{CATALOG}` cannot be read, so the never-hidden list cannot be checked against it (F-22)"
        ))];
    };
    let (control_header, control_rows) = match controls_table(text) {
        Ok(table) => table,
        Err(findings) => return findings,
    };
    let (Some(col_control), Some(col_screens), Some(col_why)) = (
        column(&control_header, "Control"),
        column(&control_header, "Screens"),
        column(&control_header, "Why it cannot be hidden"),
    ) else {
        return Vec::new();
    };
    let Ok(id_re) = Regex::new(r"\bS-\d{3}\b") else {
        return vec![at("internal: the `S-nnn` pattern failed to compile")];
    };
    let screens_of = |row: &[String]| screen_refs(cell(row, Some(col_screens)), &id_re);
    let mut critical: BTreeSet<String> = BTreeSet::new();
    for (_, row) in &control_rows {
        critical.extend(screens_of(row));
    }
    if critical.is_empty() {
        return vec![at(
            "the `## Security-critical controls` table names no screen, so the catalog coverage cannot be derived (F-22)",
        )];
    }
    let Some((catalog_header, catalog_rows)) = section_table(catalog, "Catalog") else {
        return vec![at(
            "the dangerous-actions catalog has no `## Catalog` table, so the never-hidden list cannot be checked against it (F-22)",
        )];
    };
    let (Some(col_id), Some(col_action), Some(col_catalog_screen), Some(col_safeguards)) = (
        column(&catalog_header, "ID"),
        column(&catalog_header, "Action"),
        column(&catalog_header, "Screen"),
        column(&catalog_header, "Safeguards"),
    ) else {
        return vec![at(format!(
            "the `## Catalog` table of `{CATALOG}` needs the columns `ID`, `Action`, `Screen` and `Safeguards` (F-22)"
        ))];
    };
    let catalog_screens = |row: &[String]| screen_refs(cell(row, Some(col_catalog_screen)), &id_re);
    let covered = |action: &str, catalog_row_screens: &[String]| {
        control_rows.iter().any(|(_, row)| {
            let control = cell(row, Some(col_control));
            if excluded_reason(control).is_some()
                || !screens_of(row)
                    .iter()
                    .any(|screen| catalog_row_screens.iter().any(|own| own == screen))
            {
                return false;
            }
            let Some((_, terms)) = CATALOG_ACTION_TERMS
                .iter()
                .find(|(needle, _)| word(control, needle))
            else {
                return false;
            };
            terms.iter().any(|term| word(action, term))
        })
    };
    let excluded = |action: &str, catalog_row_screens: &[String]| {
        control_rows.iter().any(|(_, row)| {
            let control = cell(row, Some(col_control));
            let Some(reason) = excluded_reason(control) else {
                return false;
            };
            if reason.is_empty()
                || !screens_of(row)
                    .iter()
                    .any(|screen| catalog_row_screens.iter().any(|own| own == screen))
            {
                return false;
            }
            shares_distinctive_word(action, &reason)
        })
    };
    let mut out = Vec::new();
    for (n, row) in &catalog_rows {
        let action = cell(row, Some(col_action));
        let screens = catalog_screens(row);
        let time_boxed = word(cell(row, Some(col_safeguards)), "time box");
        let on_critical_screen = screens.iter().any(|screen| critical.contains(screen));
        if !time_boxed && !on_critical_screen {
            continue;
        }
        if !covered(action, &screens) && !excluded(action, &screens) {
            out.push(line(
                *n,
                format!(
                    "the catalog row `{}` is time-boxed or sits on a security-critical screen, but no `## Security-critical controls` row covers it and no `excluded:` row names it with a reason (T-0024 F-22)",
                    cell(row, Some(col_id))
                ),
            ));
        }
    }
    // An excluded row is a real exclusion only when it names a catalog action and states a reason.
    for (n, row) in &control_rows {
        let control = cell(row, Some(col_control));
        let Some(reason) = excluded_reason(control) else {
            continue;
        };
        let why = cell(row, Some(col_why));
        if word_count(why) < 6 {
            out.push(line(
                *n,
                "the `excluded:` row names no reason in `Why it cannot be hidden`; an exclusion needs a stated reason (T-0024 F-22)",
            ));
        }
        let row_screens = screens_of(row);
        let names_action = catalog_rows.iter().any(|(_, catalog_row)| {
            let action = cell(catalog_row, Some(col_action));
            let screens = catalog_screens(catalog_row);
            screens
                .iter()
                .any(|screen| row_screens.iter().any(|own| own == screen))
                && shares_distinctive_word(action, &reason)
        });
        if !names_action {
            out.push(line(
                *n,
                "the `excluded:` row names no dangerous action of the catalog on its screens; a filler exclusion is not an exclusion (T-0024 F-22)",
            ));
        }
    }
    out
}

/// F-23: the print margin is canonical in this document (A4 portrait, [`PRINT_MARGIN_MM`] mm) and
/// `docs/UX/DATAVIZ.md` points here for the shared print setup instead of stating its own value.
fn print_margin_findings(text: &str, dataviz: Option<&str>) -> Vec<Finding> {
    let mut out = Vec::new();
    let body = section_body(text, "Printing and PDF").unwrap_or_default();
    let joined = body
        .iter()
        .map(|(_, line_text)| line_text.as_str())
        .collect::<Vec<_>>()
        .join("\n");
    let margins = margin_values(&joined);
    if margins.is_empty() {
        out.push(at(format!(
            "the `## Printing and PDF` section does not state the page margin as `<n> mm margins`; the canonical rule is A4 portrait with {PRINT_MARGIN_MM} mm margins (F-23)"
        )));
    }
    for value in &margins {
        if *value != PRINT_MARGIN_MM {
            out.push(at(format!(
                "the print margin is stated as {value} mm; the canonical rule is A4 portrait with {PRINT_MARGIN_MM} mm margins (F-23)"
            )));
        }
    }
    let Some(dataviz) = dataviz else {
        out.push(finding_doc(
            DATAVIZ,
            format!(
                "the `{DATAVIZ}` document cannot be read, so the shared print margin cannot be checked (F-23)"
            ),
        ));
        return out;
    };
    let dataviz_body = section_body(dataviz, "Performance and print").unwrap_or_default();
    let dataviz_text = dataviz_body
        .iter()
        .map(|(_, line_text)| line_text.as_str())
        .collect::<Vec<_>>()
        .join("\n");
    if !dataviz_text.contains("RESPONSIVE.md") {
        out.push(finding_doc(
            DATAVIZ,
            "the `Performance and print` section must point to RESPONSIVE.md for the shared print setup (F-23)",
        ));
    }
    for value in margin_values(&dataviz_text) {
        if value != PRINT_MARGIN_MM {
            out.push(finding_doc(
                DATAVIZ,
                format!(
                    "the DATAVIZ print rule states {value} mm margins while RESPONSIVE.md is canonical at {PRINT_MARGIN_MM} mm (F-23)"
                ),
            ));
        } else {
            out.push(finding_doc(
                DATAVIZ,
                "the DATAVIZ print rule states its own margin number; it must point to RESPONSIVE.md instead (F-23)",
            ));
        }
    }
    out
}

/// The whole T-0024 check on the repository at `root`, with the checksum-verified master specification.
pub fn check_with_spec(root: &Path, spec: &str) -> Vec<Finding> {
    let text = match read_text(&root.join(DOC)) {
        Ok(text) => text,
        Err(_) => {
            return vec![at(
                "the responsive and device strategy document does not exist (T-0024 deliverable)",
            )];
        }
    };
    let mut out = Vec::new();
    let catalog = read_text(&root.join(CATALOG)).ok();
    let dataviz = read_text(&root.join(DATAVIZ)).ok();
    out.extend(super::mojibake_findings(DOC, &text));
    out.extend(gap_note_findings(&text));
    out.extend(sections_findings(&text));
    out.extend(breakpoint_findings(&text, spec));
    out.extend(layout_findings(&text, spec));
    out.extend(device_matrix_findings(&text));
    out.extend(input_modalities_findings(&text, spec));
    out.extend(screen_categories_findings(&text, spec));
    out.extend(surface_categories_findings(&text, spec));
    out.extend(security_controls_findings(&text, spec));
    let mut journeys: Vec<(String, String)> = Vec::new();
    for id in 1..=34 {
        let path = format!("docs/UX/journeys/J-{id:02}.md");
        if let Ok(journey) = read_text(&root.join(&path)) {
            journeys.push((path, journey));
        }
    }
    out.extend(safeguard_crosscheck_findings(
        &text,
        &journeys,
        catalog.as_deref(),
    ));
    out.extend(never_moves_findings(&text));
    out.extend(catalog_coverage_findings(&text, catalog.as_deref()));
    out.extend(content_priority_findings(&text, spec));
    out.extend(data_dense_findings(&text, spec));
    out.extend(performance_findings(&text));
    out.extend(print_findings(&text, spec));
    out.extend(print_margin_findings(&text, dataviz.as_deref()));
    out.extend(testing_hooks_findings(&text));
    out.extend(screen_reference_findings(&text, spec));
    out.extend(placeholder_findings(&text));
    out
}

#[cfg(test)]
pub(crate) mod fixtures {
    //! Fixtures for the T-0024 rules: the specification rows the rules read and one document that
    //! satisfies every rule. The shipped `docs/UX/RESPONSIVE.md` is checked by `ux-docs` itself; these
    //! fixtures let the unit tests run without the repository.

    use super::DOC;

    /// The B11.4, B11.7 and B12.2 rows and bullets the T-0024 rules read, in the master's shape.
    ///
    /// The fixture specification already carries B11.8, B11.11 and B12.1; it does not carry B11.4,
    /// B11.7 or the S-065 block of B12.2, so a caller appends this text once.
    pub(crate) fn spec_section() -> String {
        String::from(
            r##"
### B11.4 Space, size, shape, elevation, layers

| Token set | Values |
| --- | --- |
| Control heights | 32 (compact), 40 (default), 48 (large) px; minimum hit area 40 px for primary controls (44 for touch) |
| Breakpoints | 360 (min), 480, 768, 1024, 1280, 1536 px; layouts are fluid between; container max 1280 px for app content, 1100 px for reading |

### B11.7 Layout

- **App frame:** fixed top bar 56 px; left sidebar 240 px expanded, 64 px collapsed.
- **Responsive behavior:** below 1024 px the sidebar becomes a drawer opened by a labeled menu button; tables become cards (stacked key-value) below 640 px only where horizontal scrolling would hide primary data; otherwise tables scroll horizontally inside a focusable region with a visible scroll hint.
- **Grid:** 12 columns above 1024 px, 4 below; cards use CSS grid `auto-fit` with minimum 280 px.

### B12.2 Detailed specifications of critical screens

#### S-065 Live threat monitor

Table columns: time, Ray ID chip, IP chip (country, ASN), domain, category + subtype, action, rule, vector/field, redacted payload excerpt (escaped, 120 characters, expand in drawer), status. Controls: Pause/Resume, "N new events", filters (category, action, severity, IP, rule, vector, country), density, column visibility, saved views, export. SSE connection status indicator in text. Row Enter opens S-066 in a drawer (focus returns to row). Virtualization applies above 500 rows with `aria-rowcount`.
"##,
        )
    }

    /// The fixture document: one row for every rule, terse but real. It is not the shipped document.
    fn document() -> String {
        String::from(
            r##"# Responsive and device strategy (fixture)

Task T-0024 (fixture). Sources: B11.4, B11.7, B11.9, B11.11 and B12.1. The matrix below is the input to T-0090.

## Breakpoints

Layouts are fluid between the boundaries. The app container is capped at 1280 px and the reading container at 1100 px.

| Breakpoint | Min width | Fluid behaviour |
| --- | --- | --- |
| 360 | 360 px | Base layout; every function stays reachable. |
| 480 | 480 px | The top bar gains the search field. |
| 768 | 768 px | Overlay drawer; tabs wrap; four-column grid. |
| 1024 | 1024 px | Sidebar returns; twelve-column grid; sticky contents. |
| 1280 | 1280 px | App content reaches the container maximum. |
| 1536 | 1536 px | The app container is already at its 1280 px maximum, so the extra width becomes margin; auto-fit keeps the card at the 280 px minimum and the reading page at 1100 px. |

## Layout transformations

Each region changes at one width and keeps every function.

| Region | Transformation | Width | Behaviour |
| --- | --- | --- | --- |
| Sidebar | Persistent column becomes a drawer with a labelled menu button | below 1024 px | The drawer closes on Esc and returns focus to the button. |
| Tables | Stacked key-value cards replace the table only where horizontal scrolling would hide primary data | below 640 px | Otherwise the table stays inside a focusable region with a visible scroll hint. |
| Wizards | Single column at every width | every width | Steps stack and Back and Next span the width. |
| Grid | Twelve columns become four | below 1024 px | Cards use auto-fit with a 280 px minimum. |
| Reading pages | Single column 65ch with a sticky table of contents | above 1024 px | Below 1024 px the contents list moves under the title. |

## Device matrix

Seven viewports, both themes, both directions. The matrix is the input to T-0090; rows 3 and 4 are the tablet pair.

| Viewport | Device class | Themes | Direction | What is verified |
| --- | --- | --- | --- | --- |
| 360x740 | Phone portrait | light, dark | LTR, pseudo-RTL | Reflow at the minimum width and the drawer. |
| 390x844 | Phone portrait | light, dark | LTR, pseudo-RTL | Touch targets and the bottom action bar. |
| 768x1024 | Tablet portrait | light, dark | LTR, pseudo-RTL | Overlay drawer and the four-column grid. |
| 1024x768 | Tablet landscape | light, dark | LTR, pseudo-RTL | Sidebar returns and tables scroll in focusable regions. |
| 1280x800 | Laptop | light, dark | LTR, pseudo-RTL | Container maximum and table density. |
| 1536x864 | Desktop | light, dark | LTR, pseudo-RTL | Container cap and card grid. |
| 1920x1080 | Desktop | light, dark | LTR, pseudo-RTL | Extra width becomes margin and lines stay short. |

## Input modalities

A pointer is optional. A landscape phone and a tablet in either orientation keep a usable layout.

| Modality | Requirement | Value |
| --- | --- | --- |
| Touch targets | Smallest accepted target, the WCAG 2.2 AA floor | 24 CSS px minimum |
| Touch targets | Default control height | 40 px default |
| Touch targets | Touch-device control height | 44 px on touch |
| Hover | Hover adds detail, never the only path | The same tooltip shows on focus and on tap |
| Keyboard | Every action, in DOM order | Tab reaches every control in focus order, Enter activates, Escape closes an overlay |
| Orientation | Portrait and landscape | Portrait and landscape both work; no lock, so a landscape phone keeps the phone layout |

## Screen categories

| Category | Small-screen behaviour | Screens |
| --- | --- | --- |
| Wizard | Single column with one step per view. | S-042, S-094, S-098 |
| Data table | Cards below 640 px or a focusable scroll region. | S-041, S-045, S-067 |
| Live feed | Simplified cards with the event detail in a drawer. | S-065, S-066 |
| Analytics chart | The chart scales and the text summary stays. | S-043, S-054, S-070 |
| Settings form | Single column with a sticky save bar. | S-055, S-086, S-092 |
| Admin table | Stacked columns with a details drawer. | S-101, S-102, S-114 |
| Report page | The print layout comes first; controls hide under a disclosure. | S-073, S-074 |
| Empty state | A full-width message and one primary action. | S-041, S-065, S-067 |
| Public surface | One reading column at every width and code scrolls in a focusable region. | S-001, S-003 |
| Authentication and onboarding | One column with labels above the field and no horizontal scroll. | S-020, S-024 |
| Customer app: overview and domains | KPI cards stack two per row and the domain table becomes cards. | S-040, S-041 |
| DNS, TLS, origin | The record table scrolls in a focusable region and the editor is one column. | S-045, S-050 |
| Security center | The mode banner and the emergency controls stay in the first screen. | S-054, S-055 |
| Events, bans, appeals, analytics | The event list becomes cards and the detail opens in a drawer. | S-065, S-067 |
| Reports, notifications, integrations, team | Tables condense to key columns with a details drawer. | S-073, S-076 |
| Platform admin surface | Dense tables scroll in a focusable region and emergency actions stay visible. | S-101, S-106 |
| Visitor-facing pages served by the data plane | The block page and the appeal form are one column and readable at 200% text size. | S-140, S-145 |

## Security-critical controls

Security-critical controls are never hidden on a small screen; no security control moves into an overflow menu or a hover-only affordance. The list follows the catalog: every time-boxed or enforcement-changing action is a row here or an `excluded:` row.

| Control | Screens | Small-screen treatment | Why it cannot be hidden |
| --- | --- | --- | --- |
| Safe mode | S-093, S-122 | Visible in the emergency control bar at every width, with the time box in the label. | Safe mode is the deliberate pass-through. |
| Block mode switch | S-055 | Visible in the settings header; the consequences list opens inline. | The switch changes what visitors receive. |
| Ban and unban | S-067 | Both stay visible on the row card; the bulk unban is a labelled button. | Removing a ban restores a blocked visitor. |
| Global ban | S-106 | The ban and release actions stay on the row card and in the page header. | A platform-wide refusal affects every tenant. |
| Self-lockout warning | S-063, S-131 | The warning stays visible above the action and is never a toast. | The operator must see the self-lockout risk. |
| Under attack | S-093 | Visible in the emergency control bar at every width. | The response must be one reachable action. |
| Pause protection | S-093 | The pause and resume controls stay in the emergency bar with the time box. | Nothing is inspected while the pause runs. |
| Access-list deny and allow | S-063 | The add and remove controls stay on the list row. | A deny or an allow is reversible on the same screen. |
| Geo-block | S-063 | The country and ASN controls stay in the list toolbar. | A whole country or network is refused, including customers. |
| Origin lockdown | S-098 | The apply control and the probe results stay in the wizard step. | A bypass guard is applied during an incident. |
| Origin unlock | S-052 | The unlock action stays in the origin header. | Opening the origin again removes the bypass guard. |
| Platform never-ban list | S-109 | The add and remove controls stay on the list row. | An exempt network is edited while an incident runs. |
| Platform emergency controls | S-122 | All three controls stay in the S-122 header with their end time. | The window changes what every visitor sees. |
| excluded: virtual patch emergency release | S-126 | The release and rollback live in the S-126 release pipeline. | The release needs two-person approval and its expiry is enforced server-side, so there is no page control to hide. |

## Content priority

| Breakpoint | Always visible | Moves to overflow | Never moves |
| --- | --- | --- | --- |
| 360 to 479 px | Title, status and the primary action | Density, column visibility, saved views | Safe mode; block mode switch; ban and unban; global ban; self-lockout warning; under attack; pause protection; access-list deny and allow; geo-block; origin lockdown; origin unlock; platform never-ban list; platform emergency controls |
| 480 to 767 px | Title, status and the primary action | Filters not yet applied, secondary sort | Safe mode; block mode switch; ban and unban; global ban; self-lockout warning; under attack; pause protection; access-list deny and allow; geo-block; origin lockdown; origin unlock; platform never-ban list; platform emergency controls |
| 768 to 1023 px | Title and the row identity | Column visibility, share | Safe mode; block mode switch; ban and unban; global ban; self-lockout warning; under attack; pause protection; access-list deny and allow; geo-block; origin lockdown; origin unlock; platform never-ban list; platform emergency controls |
| 1024 to 1279 px | The full page header | Secondary page-header actions | Safe mode; block mode switch; ban and unban; global ban; self-lockout warning; under attack; pause protection; access-list deny and allow; geo-block; origin lockdown; origin unlock; platform never-ban list; platform emergency controls |
| 1280 to 1535 px | The full page header | Help and keyboard shortcuts | Safe mode; block mode switch; ban and unban; global ban; self-lockout warning; under attack; pause protection; access-list deny and allow; geo-block; origin lockdown; origin unlock; platform never-ban list; platform emergency controls |
| 1536 px and up | The full page header | Nothing beyond the standard menus | Safe mode; block mode switch; ban and unban; global ban; self-lockout warning; under attack; pause protection; access-list deny and allow; geo-block; origin lockdown; origin unlock; platform never-ban list; platform emergency controls |

## Data-dense screens

The live threat monitor S-065 keeps its row identity on a phone; the event detail S-066 opens in a drawer and returns focus, and the pause control stays on screen.

| Screen | Persistent columns | Moves to the drawer | Behaviour |
| --- | --- | --- | --- |
| S-065 | Time, IP, action, status | Ray ID, category, rule, vector, payload | Rows become stacked cards below 640 px. |
| S-067 | IP, reason, expires | Rule and subtype, hits, source | The countdown stays on the card. |
| S-084 | Time, actor, action | Target, request ID, chain position | The table scrolls in a focusable region. |

## Performance budgets

These are budgets, not measurements. The mobile mid-range profile is the reference; the budget tests land in T-0029 and are reported in T-0052. Core Web Vitals are the measure.

| Device class | Profile | LCP (ms) | INP (ms) | CLS | JS (KiB) | CSS (KiB) | Requests |
| --- | --- | --- | --- | --- | --- | --- | --- |
| Mobile mid-range | 4x CPU slowdown, 1.6 Mbps down, 150 ms RTT | 2500 | 200 | 0.10 | 120 | 40 | 40 |
| Tablet | Same network, no CPU slowdown | 2200 | 180 | 0.08 | 150 | 50 | 50 |
| Laptop | Wi-Fi, no throttling | 2000 | 150 | 0.05 | 180 | 60 | 60 |
| Desktop | Cable, no throttling | 1800 | 150 | 0.05 | 200 | 60 | 60 |

## Printing and PDF

Page setup: A4 portrait at 210 x 297 mm, 12 mm margins, a 10 mm header and a 10 mm footer. Navigation is hidden in print. A report section starts a new page and the audit export repeats its header. Contrast is black on white. A value that a tooltip or drawer shows is printed in full. Reports S-073 and S-074 and the audit export S-084 share one stylesheet.

| Subject | Page layout | Hidden in print | Page breaks | Contrast |
| --- | --- | --- | --- | --- |
| Report pages | S-073 and S-074 print the KPI table and the charts on A4. | Navigation, filters, export and schedule buttons. | Each section starts a page; charts do not split. | Black on white with icon and label. |
| Audit exports | S-084 prints the event table and the chain result. | Navigation, filters, export and row actions. | The header repeats and a row does not split. | Statuses are text, not a coloured dot. |

## Testing hooks

The harness exposes a viewport helper that sets the window, theme and direction before first paint. Screenshots go to `acceptance-ui/screens/` and follow the T-0090 naming rule `<state>-<theme>-<viewport>.png`; the baseline path under `design/baselines/` is created in T-0052. Names are stable because screen, state, theme and viewport are the only variables. Every capture uses the device matrix of this document.

| Helper | Argument | Effect |
| --- | --- | --- |
| Viewport helper | `width` x `height` | Sets the window to a matrix viewport. |
| Theme flag | `--theme light` or `--theme dark` | Sets the theme before first paint. |
| Direction flag | `--direction ltr` or `--direction rtl` | Sets the document direction. |
"##,
        )
    }

    /// The fixture tree entries: one document at the path the rule reads.
    ///
    /// `docs/UX/DATAVIZ.md` is deliberately not part of this list: the T-0027 fixture writes the same
    /// path and the Lead owns the fixture-tree order. [`dataviz_document`] is the pointer the T-0024
    /// whole-check test writes for itself.
    pub(crate) fn documents() -> Vec<(String, String)> {
        vec![(DOC.to_owned(), document())]
    }

    /// The dangerous-actions catalog fixture the T-0024 rules read: the rows of the shipped catalog
    /// that the F-22 rule must classify (time-boxed or on a security-critical screen), with the shipped
    /// ids, actions, screens and safeguards so a regression on the real catalog is caught here first.
    /// The Lead's shared fixture tree writes the T-0025 fixture catalog at the same path; both must
    /// satisfy [`catalog_coverage_findings`].
    pub(crate) fn catalog_document() -> String {
        String::from(
            r#"# Dangerous actions (fixture)

The fixture catalog for the F-22 check.

## Catalog

| ID | Action | Screen | Safeguards |
| --- | --- | --- | --- |
| DA-01 | Remove a domain (decommission) | S-094 | Preview of the records and the zone export. |
| DA-05 | Switch protection to block mode | S-054, S-055 | Consequences preview; self-lockout preview; time box option. |
| DA-06 | Create a manual ban | S-067, S-069 | Self-lockout preview; dry-run against recent traffic; time box on the TTL. |
| DA-07 | Add an access-list entry (deny or allow) | S-063, S-069 | Preview of affected sessions; self-lockout preview; step-up (stronger than B4.2). |
| DA-08 | Apply a geo-block by country or ASN | S-063 | Preview of the recent visitor count; self-lockout preview of the session country and ASN. |
| DA-09 | Create a WAF rule with a broad scope | S-059 | Plain-language preview; dry-run replay over recent traffic. |
| DA-10 | Enable safe mode | S-093 | Step-up and a reason; time box; visible banner. |
| DA-11 | Apply origin lockdown | S-098 | Preview of the allowlist; verification probes. |
| DA-16 | Create a global ban | S-106 | Preview of the affected sites; typed confirmation of the address; time box on the TTL; step-up. |
| DA-18 | Push a virtual patch as an emergency release | S-126 | Two-person approval; preview of the evidence; time box on the expiry; step-up. |
| DA-23 | Change the never-ban list | S-109 | Preview of collisions with active bans; typed confirmation of the CIDR; step-up. |
| DA-24 | Enable under attack mode | S-093 | Effect preview; typed confirmation of the domain name; time box; visible banner. |
| DA-25 | Pause protection for a domain | S-093 | Step-up (stronger than B4.2) and a reason; time box; visible banner. |
| DA-29 | Open the origin by removing the lockdown | S-052 | Preview of the direct path; step-up (stronger than B4.2). |
| DA-30 | Use a platform emergency control (safe mode, signup freeze or global challenge) | S-122 | Preview of the affected tenants and the end time; typed confirmation of the emergency control name; step-up. |
"#,
        )
    }

    /// The `docs/UX/DATAVIZ.md` fixture: its `Performance and print` rule points to RESPONSIVE.md and
    /// states no margin number of its own (F-23).
    pub(crate) fn dataviz_document() -> String {
        String::from(
            r#"# Data visualization (fixture)

## Performance and print

| Rule | Value | Note |
| --- | --- | --- |
| Print | The print page comes from RESPONSIVE.md, which owns the shared setup. | One chart per page when the chart is taller than 90 mm; patterns keep the series readable. |
"#,
        )
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used, clippy::unwrap_used, reason = "tests")]

    use std::fs;
    use std::path::{Path, PathBuf};

    use super::fixtures::{documents, spec_section};
    use super::*;

    /// Real B12.1 screens the fixture document cites; all of them exist in the real B12.1 table too.
    const FIXTURE_SCREENS: [&str; 37] = [
        "S-001", "S-003", "S-020", "S-024", "S-040", "S-041", "S-042", "S-043", "S-045", "S-050",
        "S-052", "S-054", "S-055", "S-063", "S-065", "S-066", "S-067", "S-070", "S-073", "S-074",
        "S-076", "S-084", "S-086", "S-092", "S-093", "S-094", "S-098", "S-101", "S-102", "S-106",
        "S-109", "S-114", "S-122", "S-126", "S-131", "S-140", "S-145",
    ];

    /// The fixture specification: the B11.4, B11.7 and B12.2 rows the rules read plus a B12.1 table.
    fn fixture_spec() -> String {
        let mut spec = spec_section();
        spec.push_str("\n### B12.1 Screen table\n\n| ID | Name | Purpose |\n| --- | --- | --- |\n");
        let groups = [
            ("Public surface", "S-001"),
            ("Authentication and onboarding", "S-020"),
            ("Customer app: overview and domains", "S-040"),
            ("DNS, TLS, origin", "S-045"),
            ("Security center", "S-054"),
            ("Events, bans, appeals, analytics", "S-065"),
            ("Reports, notifications, integrations, team", "S-073"),
            ("Platform admin surface", "S-101"),
            ("Visitor-facing pages served by the data plane", "S-140"),
        ];
        for id in FIXTURE_SCREENS {
            if let Some((name, _)) = groups.iter().find(|(_, first)| *first == id) {
                spec.push_str(&format!("**{name}**\n\n"));
            }
            spec.push_str(&format!("| {id} | A fixture screen | A purpose. |\n"));
        }
        spec
    }

    /// The fixture document text.
    fn fixture_document() -> String {
        documents()
            .into_iter()
            .find_map(|(path, text)| (path == DOC).then_some(text))
            .expect("the fixture contains the responsive document")
    }

    fn messages(findings: &[Finding]) -> String {
        findings
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>()
            .join("\n")
    }

    /// A temporary repository that holds the fixture document, removed on drop.
    struct Repo(PathBuf);

    impl Repo {
        fn new(name: &str) -> Repo {
            let dir = std::env::temp_dir().join(format!(
                "hdd-xtask-responsive-{}-{name}",
                std::process::id()
            ));
            let _ = fs::remove_dir_all(&dir);
            fs::create_dir_all(dir.join("docs").join("UX")).expect("mkdir");
            Repo(dir)
        }

        fn put(&self, rel: &str, text: &str) {
            let path = self.0.join(rel);
            if let Some(parent) = path.parent() {
                fs::create_dir_all(parent).expect("mkdir");
            }
            fs::write(path, text).expect("write");
        }

        fn root(&self) -> &Path {
            &self.0
        }
    }

    impl Drop for Repo {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    // ------------------------------------------------------------------------------------------ sections

    #[test]
    fn t24_sections_are_required_with_a_body() {
        let text = fixture_document();
        assert!(
            sections_findings(&text).is_empty(),
            "{}",
            messages(&sections_findings(&text))
        );
        let cut = text
            .split("## Testing hooks")
            .next()
            .unwrap_or_default()
            .to_owned();
        let m = messages(&sections_findings(&cut));
        assert!(m.contains("Testing hooks"), "{m}");
        let mut blank = cut.clone();
        blank.push_str("## Testing hooks\n");
        assert!(
            messages(&sections_findings(&blank)).contains("Testing hooks"),
            "a section without a body is a finding"
        );
        let other = text.replace(
            "| Category | Small-screen behaviour | Screens |",
            "| Category | Behaviour | Screens |",
        );
        assert!(
            messages(&sections_findings(&other)).is_empty(),
            "a renamed table column is the table rule's finding, not the section rule's"
        );
    }

    // ---------------------------------------------------------------------------------------- breakpoints

    #[test]
    fn t24_breakpoints_match_b11_4() {
        let spec = fixture_spec();
        let text = fixture_document();
        assert!(
            breakpoint_findings(&text, &spec).is_empty(),
            "{}",
            messages(&breakpoint_findings(&text, &spec))
        );
        let wrong = text.replace("| 480 | 480 px |", "| 480 | 481 px |");
        let m = messages(&breakpoint_findings(&wrong, &spec));
        assert!(m.contains("480"), "{m}");
        let too_wide = text.replace("| 360 | 360 px |", "| 360 | 1360 px |");
        let m = messages(&breakpoint_findings(&too_wide, &spec));
        assert!(m.contains("360"), "{m}");
        // the fixture specification is the source of the list, not a constant in the check
        let truncated = fixture_spec().replace(", 1280, 1536 px;", " px;");
        assert!(
            breakpoint_findings(&text, &truncated)
                .iter()
                .any(|finding| finding.message.contains("B11.4")),
            "a spec without a readable breakpoint list is a finding"
        );
        let container = text.replace("at 1100 px", "at 1000 px");
        let m = messages(&breakpoint_findings(&container, &spec));
        assert!(m.contains("1100"), "{m}");
    }

    // ------------------------------------------------------------------------------------------- layout

    #[test]
    fn t24_b11_7_transformations_are_stated() {
        let spec = fixture_spec();
        let text = fixture_document();
        assert!(
            layout_findings(&text, &spec).is_empty(),
            "{}",
            messages(&layout_findings(&text, &spec))
        );
        let sidebar = text.replace(
            "| below 1024 px | The drawer closes",
            "| below 1023 px | The drawer closes",
        );
        let m = messages(&layout_findings(&sidebar, &spec));
        assert!(m.contains("1024"), "{m}");
        let no_exception = text.replace(
            "only where horizontal scrolling would hide primary data",
            "whenever it fits",
        );
        let m = messages(&layout_findings(&no_exception, &spec));
        assert!(
            m.contains("primary data") || m.contains("only where"),
            "{m}"
        );
        let no_scroll = text.replace("focusable region with a visible scroll hint", "plain block");
        let m = messages(&layout_findings(&no_scroll, &spec));
        assert!(m.contains("focusable") || m.contains("scroll hint"), "{m}");
        let no_wizard = text.replace(
            "| Wizards | Single column at every width |",
            "| Wizards | Two columns |",
        );
        let m = messages(&layout_findings(&no_wizard, &spec));
        assert!(m.contains("single column"), "{m}");
    }

    // ---------------------------------------------------------------------------------- surface categories

    #[test]
    fn t24_surface_categories_are_derived_from_the_b12_1_groups() {
        let spec = fixture_spec();
        let text = fixture_document();
        assert!(
            surface_categories_findings(&text, &spec).is_empty(),
            "{}",
            messages(&surface_categories_findings(&text, &spec))
        );
        let missing = text.replace("| Security center |", "| Security overview |");
        let m = messages(&surface_categories_findings(&missing, &spec));
        assert!(m.contains("Security center"), "{m}");
        let wrong_screen = text.replace(
            "| Visitor-facing pages served by the data plane | The block page and the appeal form are one column and readable at 200% text size. | S-140, S-145 |",
            "| Visitor-facing pages served by the data plane | The block page and the appeal form are one column and readable at 200% text size. | S-001 |",
        );
        assert_ne!(wrong_screen, text);
        let m = messages(&surface_categories_findings(&wrong_screen, &spec));
        assert!(m.contains("no screen of that B12.1 surface"), "{m}");
    }

    // ---------------------------------------------------------------------------- control cross-check

    #[test]
    fn t24_security_controls_are_cross_checked_against_journey_safeguards() {
        let text = fixture_document();
        let catalog = fixtures::catalog_document();
        let journeys = vec![(
            "docs/UX/journeys/J-16.md".to_owned(),
            String::from(
                "## Safeguards\n\n\
                 | Step | Risky action | Safeguard | Kind | Copy key | Exact copy |\n\
                 | --- | --- | --- | --- | --- | --- |\n\
                 | 1 | Switching the protection mode. | A preview. | preview | fixture-copy | Review the change. |\n\
                 | 2 | Banning the address. | A preview. | preview | fixture-copy | Review the change. |\n\
                 | 3 | Unbanning an address. | A preview. | preview | fixture-copy | Review the change. |\n\
                 | 4 | Enabling platform safe mode. | A preview. | preview | fixture-copy | Review the change. |\n",
            ),
        )];
        assert!(
            safeguard_crosscheck_findings(&text, &journeys, Some(&catalog)).is_empty(),
            "{}",
            messages(&safeguard_crosscheck_findings(
                &text,
                &journeys,
                Some(&catalog)
            ))
        );
        let none: Vec<(String, String)> = Vec::new();
        let message = messages(&safeguard_crosscheck_findings(&text, &none, Some(&catalog)));
        assert!(message.contains("no matching Risky action"), "{message}");
        assert!(
            message.contains("safe mode") && message.contains("block mode"),
            "{message}"
        );
        // The self-lockout warning has no journey risky action: the catalog names the preview instead.
        let no_preview = catalog.replace("self-lockout preview", "a warning");
        let m = messages(&safeguard_crosscheck_findings(
            &text,
            &journeys,
            Some(&no_preview),
        ));
        assert!(
            m.contains("self-lockout") && m.contains("not cross-checked"),
            "{m}"
        );
        // A `gap:` note is not a cross-check any more.
        let gap = text.replace(
            "The operator must see the self-lockout risk.",
            "The operator must see the self-lockout risk. gap: no journey names it.",
        );
        assert_ne!(gap, text);
        let m = messages(&safeguard_crosscheck_findings(
            &gap,
            &journeys,
            Some(&catalog),
        ));
        assert!(m.contains("gap:"), "{m}");
        // Without a readable catalog the self-lockout cross-check cannot pass.
        let m = messages(&safeguard_crosscheck_findings(&text, &journeys, None));
        assert!(m.contains("self-lockout"), "{m}");
    }

    // ---------------------------------------------------------------------------------------- F-21 gap note

    #[test]
    fn t24_f21_no_table_cell_carries_a_gap_note() {
        let text = fixture_document();
        assert!(
            gap_note_findings(&text).is_empty(),
            "{}",
            messages(&gap_note_findings(&text))
        );
        let gap = text.replace(
            "| The operator must see the self-lockout risk. |",
            "| The operator must see the self-lockout risk. gap: no journey names it yet. |",
        );
        assert_ne!(gap, text);
        let m = messages(&gap_note_findings(&gap));
        assert!(m.contains("gap:"), "{m}");
        let prose = format!("{text}\n\nA note about the gap: the catalog names the preview.\n");
        assert!(
            gap_note_findings(&prose).is_empty(),
            "only table cells are published content, so prose is out of scope"
        );
    }

    // ------------------------------------------------------------------------------------ F-22 never moves

    #[test]
    fn t24_f22_every_never_moves_cell_names_the_same_control_set() {
        let text = fixture_document();
        assert!(
            never_moves_findings(&text).is_empty(),
            "{}",
            messages(&never_moves_findings(&text))
        );
        // A real control dropped from one breakpoint only: the 360 px row.
        let next = "Safe mode; block mode switch; ban and unban; global ban; self-lockout warning; under attack; pause protection; access-list deny and allow; geo-block; origin lockdown; origin unlock; platform never-ban list; platform emergency controls";
        let without_ban = "Safe mode; block mode switch; global ban; self-lockout warning; under attack; pause protection; access-list deny and allow; geo-block; origin lockdown; origin unlock; platform never-ban list; platform emergency controls";
        let dropped = text.replacen(next, without_ban, 1);
        assert_ne!(dropped, text);
        let m = messages(&never_moves_findings(&dropped));
        assert!(m.to_lowercase().contains("ban and unban"), "{m}");
        let m = messages(&never_moves_findings(
            &text.replace(next, "Nothing must move"),
        ));
        assert!(m.to_lowercase().contains("safe mode"), "{m}");
    }

    // ------------------------------------------------------------------------------ F-22 catalog coverage

    #[test]
    fn t24_f22_catalog_time_boxed_and_critical_rows_are_covered_or_excluded() {
        let text = fixture_document();
        let catalog = fixtures::catalog_document();
        assert!(
            catalog_coverage_findings(&text, Some(&catalog)).is_empty(),
            "{}",
            messages(&catalog_coverage_findings(&text, Some(&catalog)))
        );
        // A time-boxed action with no control row: the safe-mode row is removed.
        let no_safe_mode = text.replace(
            "| Safe mode | S-093, S-122 | Visible in the emergency control bar at every width, with the time box in the label. | Safe mode is the deliberate pass-through. |\n",
            "",
        );
        assert_ne!(no_safe_mode, text);
        let m = messages(&catalog_coverage_findings(&no_safe_mode, Some(&catalog)));
        assert!(m.contains("DA-10"), "{m}");
        // A security-critical action with no control row: the geo-block row is removed.
        let no_geo = text.replace(
            "| Geo-block | S-063 | The country and ASN controls stay in the list toolbar. | A whole country or network is refused, including customers. |\n",
            "",
        );
        assert_ne!(no_geo, text);
        let m = messages(&catalog_coverage_findings(&no_geo, Some(&catalog)));
        assert!(m.contains("DA-08"), "{m}");
        // The widened access-list row (DA-07, screens S-063 and S-069) needs its own control row.
        let no_access = text.replace(
            "| Access-list deny and allow | S-063 | The add and remove controls stay on the list row. | A deny or an allow is reversible on the same screen. |\n",
            "",
        );
        assert_ne!(no_access, text);
        let m = messages(&catalog_coverage_findings(&no_access, Some(&catalog)));
        assert!(m.contains("DA-07"), "{m}");
        // An excluded row that names no catalog action is a filler, so DA-18 stays uncovered too.
        let filler = text.replace(
            "| excluded: virtual patch emergency release | S-126 |",
            "| excluded: telemetry export | S-126 |",
        );
        assert_ne!(filler, text);
        let m = messages(&catalog_coverage_findings(&filler, Some(&catalog)));
        assert!(
            m.contains("DA-18") && m.contains("no dangerous action"),
            "{m}"
        );
        // An excluded row without a reason is refused.
        let no_reason = text.replace(
            "| The release needs two-person approval and its expiry is enforced server-side, so there is no page control to hide. |",
            "| none |",
        );
        let m = messages(&catalog_coverage_findings(&no_reason, Some(&catalog)));
        assert!(m.contains("no reason"), "{m}");
        // Without a readable catalog the rule cannot pass.
        let m = messages(&catalog_coverage_findings(&text, None));
        assert!(m.contains("cannot be read"), "{m}");
    }

    // -------------------------------------------------------------------------------------- F-23 margin

    #[test]
    fn t24_f23_print_margin_is_canonical_and_dataviz_points_here() {
        let text = fixture_document();
        let dataviz = fixtures::dataviz_document();
        assert!(
            print_margin_findings(&text, Some(&dataviz)).is_empty(),
            "{}",
            messages(&print_margin_findings(&text, Some(&dataviz)))
        );
        let fifteen = text.replace("12 mm margins", "15 mm margins");
        let m = messages(&print_margin_findings(&fifteen, Some(&dataviz)));
        assert!(m.contains("15") && m.contains("12"), "{m}");
        let no_margin = text.replace("12 mm margins, ", "");
        let m = messages(&print_margin_findings(&no_margin, Some(&dataviz)));
        assert!(m.contains("does not state the page margin"), "{m}");
        // DATAVIZ restating the same value is still its own number, not a pointer.
        let own = dataviz.replace(
            "The print page comes from RESPONSIVE.md, which owns the shared setup.",
            "A4 portrait with 12 mm margins.",
        );
        let m = messages(&print_margin_findings(&text, Some(&own)));
        assert!(m.contains("own margin number"), "{m}");
        // A different value is a disagreement.
        let differ = dataviz.replace(
            "The print page comes from RESPONSIVE.md, which owns the shared setup.",
            "A4 portrait with 16 mm margins, see RESPONSIVE.md.",
        );
        let m = messages(&print_margin_findings(&text, Some(&differ)));
        assert!(m.contains("16"), "{m}");
        // No pointer is a finding even without a number.
        let no_pointer = dataviz.replace("RESPONSIVE.md", "the print guide");
        let m = messages(&print_margin_findings(&text, Some(&no_pointer)));
        assert!(m.contains("point to RESPONSIVE.md"), "{m}");
    }

    // ------------------------------------------------------------------------- F-24 last breakpoint rule

    #[test]
    fn t24_f24_last_breakpoint_states_a_testable_card_rule() {
        let spec = fixture_spec();
        let text = fixture_document();
        assert!(
            breakpoint_findings(&text, &spec).is_empty(),
            "{}",
            messages(&breakpoint_findings(&text, &spec))
        );
        let vague = text.replace(
            "The app container is already at its 1280 px maximum, so the extra width becomes margin; auto-fit keeps the card at the 280 px minimum and the reading page at 1100 px.",
            "The card grid may show more cards per row and the reading page stays at 1100 px.",
        );
        assert_ne!(vague, text);
        let m = messages(&breakpoint_findings(&vague, &spec));
        assert!(m.contains("F-24") && m.contains("280"), "{m}");
        let no_cap = text.replace("already at its 1280 px maximum", "already at its maximum");
        let m = messages(&breakpoint_findings(&no_cap, &spec));
        assert!(m.contains("1280"), "{m}");
    }

    // ------------------------------------------------------------------------------------- device matrix

    #[test]
    fn t24_device_matrix_has_exactly_the_seven_viewports() {
        let text = fixture_document();
        assert!(
            device_matrix_findings(&text).is_empty(),
            "{}",
            messages(&device_matrix_findings(&text))
        );
        let wrong = text.replace("| 1920x1080 |", "| 2560x1440 |");
        let m = messages(&device_matrix_findings(&wrong));
        assert!(m.contains("1920x1080") && m.contains("2560x1440"), "{m}");
        let duplicate = text.replace("| 1920x1080 |", "| 1536x864 |");
        let m = messages(&device_matrix_findings(&duplicate));
        assert!(m.contains("1536x864"), "{m}");
        let no_dark = text.replacen("| light, dark |", "| light |", 1);
        let m = messages(&device_matrix_findings(&no_dark));
        assert!(m.contains("dark"), "{m}");
        let no_rtl = text.replacen("LTR, pseudo-RTL", "LTR", 1);
        let m = messages(&device_matrix_findings(&no_rtl));
        assert!(m.contains("pseudo-RTL"), "{m}");
        let no_tablet = text
            .replace("Tablet portrait", "Large phone")
            .replace("Tablet landscape", "Large phone");
        let m = messages(&device_matrix_findings(&no_tablet));
        assert!(m.contains("tablet"), "{m}");
        let no_matrix_use = text.replace(
            "The matrix is the input to T-0090;",
            "The matrix is the input to the harness;",
        );
        let m = messages(&device_matrix_findings(&no_matrix_use));
        assert!(m.contains("T-0090"), "{m}");
    }

    // ---------------------------------------------------------------------------------- input modalities

    #[test]
    fn t24_input_modalities_use_the_b11_4_targets() {
        let spec = fixture_spec();
        let text = fixture_document();
        assert!(
            input_modalities_findings(&text, &spec).is_empty(),
            "{}",
            messages(&input_modalities_findings(&text, &spec))
        );
        let wrong_touch = text.replace("44 px on touch", "40 px on touch");
        let m = messages(&input_modalities_findings(&wrong_touch, &spec));
        assert!(m.contains("44"), "{m}");
        let wrong_floor = text.replace("24 CSS px minimum", "40 CSS px minimum");
        let m = messages(&input_modalities_findings(&wrong_floor, &spec));
        assert!(m.contains("24"), "{m}");
        let no_hover = text.replace("| Hover | Hover adds detail, never the only path | The same tooltip shows on focus and on tap |", "");
        let m = messages(&input_modalities_findings(&no_hover, &spec));
        assert!(m.contains("hover"), "{m}");
        let no_landscape_phone = text
            .replace(
                "A landscape phone and a tablet in either orientation keep a usable layout.",
                "A small screen keeps a usable layout.",
            )
            .replace(
                "Portrait and landscape both work; no lock, so a landscape phone keeps the phone layout",
                "Portrait only; a narrow screen keeps the narrow layout",
            );
        let m = messages(&input_modalities_findings(&no_landscape_phone, &spec));
        assert!(m.contains("landscape phone") || m.contains("tablet"), "{m}");
    }

    // ----------------------------------------------------------------------------------- screen categories

    #[test]
    fn t24_each_screen_category_has_a_small_screen_behaviour() {
        let spec = fixture_spec();
        let text = fixture_document();
        assert!(
            screen_categories_findings(&text, &spec).is_empty(),
            "{}",
            messages(&screen_categories_findings(&text, &spec))
        );
        let missing = text.replace("| Live feed |", "| Event feed |");
        let m = messages(&screen_categories_findings(&missing, &spec));
        assert!(m.contains("Live feed"), "{m}");
        let wrong_screen = text.replace(
            "| Wizard | Single column with one step per view. | S-042, S-094, S-098 |",
            "| Wizard | Single column with one step per view. | S-073 |",
        );
        let m = messages(&screen_categories_findings(&wrong_screen, &spec));
        assert!(m.contains("Wizard"), "{m}");
        let unknown = text.replace("S-042, S-094, S-098", "S-999");
        let m = messages(&screen_categories_findings(&unknown, &spec));
        assert!(m.contains("S-999"), "{m}");
        let no_report_screen = text.replace("| S-073, S-074 |", "| S-073 |");
        let m = messages(&screen_categories_findings(&no_report_screen, &spec));
        assert!(m.contains("S-074"), "{m}");
    }

    // ------------------------------------------------------------------------------- security-critical

    #[test]
    fn t24_security_controls_are_named_and_never_hidden() {
        let spec = fixture_spec();
        let text = fixture_document();
        assert!(
            security_controls_findings(&text, &spec).is_empty(),
            "{}",
            messages(&security_controls_findings(&text, &spec))
        );
        let missing = text.replace("| Block mode switch |", "| WAF switch |");
        let m = messages(&security_controls_findings(&missing, &spec));
        assert!(m.contains("block mode"), "{m}");
        let hover = text.replace(
            "Visible in the settings header; the consequences list opens inline.",
            "Moves into the overflow menu on a phone.",
        );
        assert_ne!(hover, text);
        let m = messages(&security_controls_findings(&hover, &spec));
        assert!(m.contains("overflow") || m.contains("block mode"), "{m}");
        let wrong_screen = text.replace(
            "| Block mode switch | S-055 |",
            "| Block mode switch | S-001 |",
        );
        let m = messages(&security_controls_findings(&wrong_screen, &spec));
        assert!(m.contains("S-055") || m.contains("block mode"), "{m}");
        let no_rule = text.replace(
            "Security-critical controls are never hidden on a small screen; no security control moves into an overflow menu or a hover-only affordance.",
            "Small screens are designed with care.",
        );
        let m = messages(&security_controls_findings(&no_rule, &spec));
        assert!(m.contains("never") || m.contains("small screen"), "{m}");
    }

    // ------------------------------------------------------------------------------------ content priority

    #[test]
    fn t24_content_priority_covers_every_breakpoint_and_never_hides_security() {
        let spec = fixture_spec();
        let text = fixture_document();
        assert!(
            content_priority_findings(&text, &spec).is_empty(),
            "{}",
            messages(&content_priority_findings(&text, &spec))
        );
        let hidden = text.replace(
            "| Density, column visibility, saved views |",
            "| Density, Safe mode, saved views |",
        );
        let m = messages(&content_priority_findings(&hidden, &spec));
        assert!(m.contains("safe mode"), "{m}");
        let gap = text.replace("| 768 to 1023 px |", "| 700 to 1023 px |");
        let m = messages(&content_priority_findings(&gap, &spec));
        assert!(m.contains("768"), "{m}");
        let no_never = text.replace(
            "Safe mode; block mode switch; ban and unban; global ban; self-lockout warning; under attack; pause protection; access-list deny and allow; geo-block; origin lockdown; origin unlock; platform never-ban list; platform emergency controls",
            "Nothing",
        );
        assert_ne!(no_never, text);
        let m = messages(&content_priority_findings(&no_never, &spec));
        assert!(m.contains("never") || m.contains("security"), "{m}");
    }

    // ---------------------------------------------------------------------------------------- data dense

    #[test]
    fn t24_data_dense_screens_keep_real_columns() {
        let spec = fixture_spec();
        let text = fixture_document();
        assert!(
            data_dense_findings(&text, &spec).is_empty(),
            "{}",
            messages(&data_dense_findings(&text, &spec))
        );
        let invented = text.replace(
            "Time, IP, action, status",
            "Time, IP, action, status, Hostname",
        );
        let m = messages(&data_dense_findings(&invented, &spec));
        assert!(m.contains("Hostname"), "{m}");
        let no_monitor = text.replace(
            "| S-065 | Time, IP, action, status | Ray ID, category, rule, vector, payload | Rows become stacked cards below 640 px. |\n",
            "",
        );
        let m = messages(&data_dense_findings(&no_monitor, &spec));
        assert!(m.contains("S-065"), "{m}");
        let no_drawer = text.replace(
            "the event detail S-066 opens in a drawer",
            "the event detail opens elsewhere",
        );
        let m = messages(&data_dense_findings(&no_drawer, &spec));
        assert!(m.contains("S-066") || m.contains("drawer"), "{m}");
    }

    // ---------------------------------------------------------------------------------------- performance

    #[test]
    fn t24_performance_budgets_are_numeric_for_every_class() {
        let text = fixture_document();
        assert!(
            performance_findings(&text).is_empty(),
            "{}",
            messages(&performance_findings(&text))
        );
        let placeholder = text.replacen("| 2500 | 200 | 0.10 |", "| TBD | 200 | 0.10 |", 1);
        let m = messages(&performance_findings(&placeholder));
        assert!(m.contains("LCP"), "{m}");
        let missing_class = text.replace(
            "| Desktop | Cable, no throttling | 1800 | 150 | 0.05 | 200 | 60 | 60 |\n",
            "",
        );
        let m = messages(&performance_findings(&missing_class));
        assert!(m.contains("Desktop"), "{m}");
        let wrong_unit = text.replacen("| 2500 | 200 |", "| 2.5 | 200 |", 1);
        let m = messages(&performance_findings(&wrong_unit));
        assert!(m.contains("LCP"), "{m}");
        let no_budget_label = text.replace(
            "These are budgets, not measurements.",
            "These are reference values.",
        );
        let m = messages(&performance_findings(&no_budget_label));
        assert!(m.contains("budget") || m.contains("measurement"), "{m}");
    }

    // -------------------------------------------------------------------------------------------- print

    #[test]
    fn t24_print_rules_cover_reports_and_audit_exports() {
        let spec = fixture_spec();
        let text = fixture_document();
        assert!(
            print_findings(&text, &spec).is_empty(),
            "{}",
            messages(&print_findings(&text, &spec))
        );
        let wrong_row = text.replace(
            "| Audit exports | S-084 prints",
            "| Audit exports | S-073 prints",
        );
        let m = messages(&print_findings(&wrong_row, &spec));
        assert!(m.contains("S-084"), "{m}");
        let no_a4 = text
            .replace("A4 portrait at 210 x 297 mm", "portrait at 210 x 297 mm")
            .replace("on A4.", "on paper.");
        let m = messages(&print_findings(&no_a4, &spec));
        assert!(m.contains("A4"), "{m}");
        let no_interactive = text.replace(
            "A value that a tooltip or drawer shows is printed in full.",
            "",
        );
        let m = messages(&print_findings(&no_interactive, &spec));
        assert!(m.contains("tooltip") || m.contains("printed"), "{m}");
        let no_hidden = text.replace("Navigation is hidden in print.", "");
        assert!(
            print_findings(&no_hidden, &spec)
                .iter()
                .any(|finding| finding.message.contains("hidden")),
            "a print section that does not say what is hidden is a finding"
        );
    }

    // ------------------------------------------------------------------------------------ testing hooks

    #[test]
    fn t24_testing_hooks_pin_the_viewport_helper_and_naming() {
        let text = fixture_document();
        assert!(
            testing_hooks_findings(&text).is_empty(),
            "{}",
            messages(&testing_hooks_findings(&text))
        );
        let no_t0090 = text.replace("follow the T-0090 naming rule", "follow the naming rule");
        let m = messages(&testing_hooks_findings(&no_t0090));
        assert!(m.contains("T-0090"), "{m}");
        let no_pattern = text.replace("<state>-<theme>-<viewport>.png", "a file name");
        let m = messages(&testing_hooks_findings(&no_pattern));
        assert!(
            m.contains("<theme>-<viewport>.png") || m.contains("naming"),
            "{m}"
        );
        let no_screens_dir = text.replace("`acceptance-ui/screens/`", "a directory");
        let m = messages(&testing_hooks_findings(&no_screens_dir));
        assert!(m.contains("acceptance-ui/screens/"), "{m}");
    }

    // ------------------------------------------------------------------------------- screen references

    #[test]
    fn t24_every_cited_screen_exists_in_b12_1() {
        let spec = fixture_spec();
        let text = fixture_document();
        assert!(
            screen_reference_findings(&text, &spec).is_empty(),
            "{}",
            messages(&screen_reference_findings(&text, &spec))
        );
        let unknown = text.replace("S-063, S-131", "S-063, S-999");
        let m = messages(&screen_reference_findings(&unknown, &spec));
        assert!(m.contains("S-999"), "{m}");
    }

    // -------------------------------------------------------------------------------------- placeholders

    #[test]
    fn t24_placeholder_cells_are_rejected() {
        let text = fixture_document();
        assert!(
            placeholder_findings(&text).is_empty(),
            "{}",
            messages(&placeholder_findings(&text))
        );
        let tbd = text.replace("| 360 | 360 px |", "| 360 | TBD |");
        let m = messages(&placeholder_findings(&tbd));
        assert!(m.contains("TBD"), "{m}");
        let empty = text.replace("| 360 | 360 px |", "| 360 |  |");
        let m = messages(&placeholder_findings(&empty));
        assert!(m.contains("empty"), "{m}");
        let dash = text.replace("| 360 | 360 px |", "| 360 | - |");
        let m = messages(&placeholder_findings(&dash));
        assert!(m.contains("placeholder") || m.contains("-"), "{m}");
    }

    // ------------------------------------------------------------------------------------ whole check

    #[test]
    fn t24_a_complete_document_passes_the_whole_check() {
        let repo = Repo::new("complete");
        repo.put(DOC, &fixture_document());
        repo.put(CATALOG, &fixtures::catalog_document());
        repo.put(DATAVIZ, &fixtures::dataviz_document());
        repo.put(
            "docs/UX/journeys/J-16.md",
            "## Safeguards\n\n\
             | Step | Risky action | Safeguard | Kind | Copy key | Exact copy |\n\
             | --- | --- | --- | --- | --- | --- |\n\
             | 1 | Switching the protection mode. | A preview. | preview | fixture-copy | Review the change. |\n\
             | 2 | Reviewing the self-lockout warning. | A preview. | preview | fixture-copy | Review the change. |\n\
             | 3 | Banning the address. | A preview. | preview | fixture-copy | Review the change. |\n\
             | 4 | Unbanning an address. | A preview. | preview | fixture-copy | Review the change. |\n\
             | 5 | Enabling platform safe mode. | A preview. | preview | fixture-copy | Review the change. |\n",
        );
        let spec = fixture_spec();
        let findings = check_with_spec(repo.root(), &spec);
        assert!(findings.is_empty(), "{}", messages(&findings));
    }

    #[test]
    fn t24_a_missing_document_is_one_finding_not_a_panic() {
        let repo = Repo::new("missing");
        let findings = check_with_spec(repo.root(), &fixture_spec());
        assert_eq!(findings.len(), 1, "{}", messages(&findings));
        assert!(
            findings[0].message.contains("does not exist"),
            "{}",
            messages(&findings)
        );
    }

    #[test]
    fn t24_an_empty_document_is_findings_not_a_panic() {
        let repo = Repo::new("empty");
        repo.put(DOC, "");
        let findings = check_with_spec(repo.root(), &fixture_spec());
        assert!(!findings.is_empty());
        assert!(
            messages(&findings).contains("Breakpoints"),
            "{}",
            messages(&findings)
        );
    }
}
