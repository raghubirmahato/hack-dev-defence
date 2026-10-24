//! Journey-extension checks (T-0018): the `Stress cases` table of J-25 to J-34, the J-25 readiness score, the J-27
//! API-key lifecycle, the J-29 to J-31 platform-admin controls, the J-33 privacy timelines, the J-34 incident timeline
//! and the cross-journey dependency graph of `docs/UX/journey-dependencies.md`.
//!
//! Rules, stated so that a reader of a finding can see the rule it broke:
//!
//! - Every journey of T-0018 (J-25 to J-34) names exactly the three stress cases `low bandwidth`, `small screen` and
//!   `keyboard only`, each with a non-empty "what changes" and "what stays usable" cell.
//! - J-25 `Readiness score` has at least six checks, whole-number weights that sum to 100, each check names at least
//!   one of `Pass`, `Partial`, `Fail` or `Unknown`, at least one check allows `Unknown`, and every `Fix link` names an
//!   `S-nnn` screen of B12.1. The `Honesty footnote` quotes the exact footnote of section 4.4 of the specification and
//!   says where it is placed (S-044 or the readiness ring, plus a position such as below or always visible).
//! - J-27 `API key lifecycle` names the six stages create, secret reveal once, rotation, expiry, restrict by IP and
//!   revoke, each exactly once.
//! - J-29 to J-31 `Admin controls` names real `PERM-platform.` permissions of B4.2 and real `AUD-` events of B8; a row
//!   whose action has no B8 event says "B8 has no event" instead of inventing one. `Reason required` is `yes`, `no`
//!   or `typed`, `Step-up` is `yes` or `no`, and no action appears twice.
//! - J-33 `Timelines` has a data-export and a deletion row, each written as a configurable default with a number and a
//!   unit, and the section uses no promise a lawyer would not make.
//! - J-34 `Incident timeline` names detection, under-attack mode, analyst actions and de-escalation, with a real screen
//!   on every row; `Retrospective report outline` has at least eight numbered section titles.
//! - `journey-dependencies.md`: every journey has exactly one `Journey | Needs | Why` row, every dependency names a
//!   journey of B3, no journey depends on itself, the graph is acyclic (Kahn's algorithm) and the text `Graph` section
//!   names every journey and uses no diagram tool. A dependency may point to a later journey only when the `Why` cell
//!   says so as a whole-word `exception` (the rule is repeated in the document itself). The persona-journey matrix lists
//!   the journeys in B3 order, so "a later journey" is the same relation in the table and in the matrix.
//! - `Task dependencies` rows are checked against the real task graph parsed from `docs/SPEC.md`: the journey pair must
//!   be an edge of the dependency table, every task id must exist, `direct` means the dependent task names the
//!   prerequisite task in its `deps:` line, `earlier` means the stable topological order places the prerequisite first,
//!   and `none` means the specification names no task dependency and the row says so. When a mapped edge's prerequisite
//!   task comes after the dependent task in the stable order, the `Why the order agrees` cell must record that as a
//!   whole-word `exception` (T-0018 F-13).
//! - Journeys the specification presents as alternatives of the same choice (J-08 and J-09, `docs/spec/B1.md` line 248)
//!   must not depend on each other; the pair list and its specification line are the [`ALTERNATIVE_JOURNEYS`] constant.
//!
//! The dependency checks read the registries through the same parsers as the rest of `ux-docs`; nothing is copied from
//! memory.

use super::*;
use crate::tasks;

/// The cross-journey dependency document (T-0018 A2).
pub const JOURNEY_DEPENDENCIES: &str = "docs/UX/journey-dependencies.md";
/// Journey pairs the specification presents as alternatives of the same choice: neither may need the other.
/// The third element is the specification line that justifies the pair.
///
/// `docs/spec/B1.md` line 248: J-09 is "as J-08 but step 3 chooses" the CNAME mode, while line 245 makes full
/// nameserver delegation the J-08 choice. Both are reached from the same add-domain wizard entry (J-07), so an edge
/// between them would say one setup must happen before the other, which the specification does not say.
pub const ALTERNATIVE_JOURNEYS: [(&str, &str, &str); 1] = [(
    "J-08",
    "J-09",
    "docs/spec/B1.md line 248: J-09 is \"as J-08 but step 3 chooses\" the CNAME mode, while line 245 makes full nameserver delegation the J-08 choice; the two are alternative integration choices of the same add-domain wizard",
)];
/// The three stress cases every journey of T-0018 must name.
pub const STRESS_CASES: [&str; 3] = ["low bandwidth", "small screen", "keyboard only"];
/// Lower bound of the J-25 readiness checklist.
pub const MIN_READINESS_CHECKS: usize = 6;
/// The J-25 weights must sum to this value.
pub const READINESS_SUM: u32 = 100;
/// Status values B12.2 allows for a readiness check.
pub const READINESS_STATUSES: [&str; 4] = ["pass", "partial", "fail", "unknown"];
/// The six J-27 API-key lifecycle stages.
pub const API_KEY_STAGES: [&str; 6] = [
    "create",
    "secret reveal once",
    "rotation",
    "expiry",
    "restrict by ip",
    "revoke",
];
/// The platform-admin journeys that need an `Admin controls` table.
pub const ADMIN_JOURNEYS: [u32; 3] = [29, 30, 31];
/// Allowed values of the `Reason required` column.
pub const ADMIN_REASONS: [&str; 3] = ["yes", "no", "typed"];
/// Allowed values of the `Step-up` column.
pub const ADMIN_STEP_UP: [&str; 2] = ["yes", "no"];
/// Lower bound of the J-34 retrospective outline.
pub const MIN_RETROSPECTIVE: usize = 8;
/// Words a J-33 timeline may not use (legal-neutral wording, no promise).
pub const LEGAL_PROMISES: [&str; 8] = [
    "legal advice",
    "guarantee",
    "guaranteed",
    "we promise",
    "you have the right",
    "fully compliant",
    "compliant with the gdpr",
    "permanently deleted",
];

/// Registries the extension checks need from the master specification.
pub struct ExtContext<'a> {
    /// Screen ids of B12.1 (the fix links and the incident-timeline screens must exist).
    pub screens: &'a BTreeSet<String>,
    /// Permission ids of the B4.2 catalog.
    pub permissions: &'a BTreeSet<String>,
    /// Audit event ids of B8.
    pub audits: &'a BTreeSet<String>,
}

/// Values of `pattern` in `text`, in the order they occur (the ordered variant of [`tokens_in`], for `J-nn needs J-nn`).
fn ordered_tokens(text: &str, pattern: &str) -> Vec<String> {
    let Ok(re) = Regex::new(pattern) else {
        return Vec::new();
    };
    re.find_iter(text)
        .map(|found| found.as_str().to_owned())
        .collect()
}

/// Whether the raw text of the first `## <title>` section contains `needle` (case-insensitive), including fenced code
/// blocks, which [`section_body`] skips.
fn raw_section_contains(text: &str, title: &str, needle: &str) -> bool {
    let mut inside = false;
    for line in text.lines() {
        if let Some(heading) = heading_title(line) {
            if inside {
                break;
            }
            inside = heading.eq_ignore_ascii_case(title);
            continue;
        }
        if inside && line.to_lowercase().contains(needle) {
            return true;
        }
    }
    false
}

/// Number of a `J-nn` id.
fn journey_number(id: &str) -> Option<u32> {
    id.get(2..).and_then(|digits| digits.parse().ok())
}

/// The readiness statuses a cell names, as whole words.
fn named_statuses(cell: &str) -> BTreeSet<&'static str> {
    let words: BTreeSet<String> = cell
        .to_lowercase()
        .split(|c: char| !c.is_alphanumeric())
        .filter(|word| !word.is_empty())
        .map(str::to_owned)
        .collect();
    READINESS_STATUSES
        .iter()
        .filter(|status| words.contains(**status))
        .copied()
        .collect()
}

/// The T-0018 journey checks: stress cases plus the journey-specific sections of J-25, J-27, J-29 to J-31, J-33 and
/// J-34. Earlier journeys return no finding, because T-0016 and T-0017 own them.
pub fn ext_findings(text: &str, id: &str, ctx: &ExtContext<'_>) -> Vec<Finding> {
    let loc = format!("{JOURNEYS_DIR}/{id}.md");
    let Some(numeric) = journey_number(id) else {
        return Vec::new();
    };
    if numeric < 25 {
        return Vec::new();
    }
    let mut out = stress_case_findings(text, &loc);
    match numeric {
        25 => out.extend(readiness_findings(text, &loc, ctx.screens)),
        27 => out.extend(api_key_lifecycle_findings(text, &loc)),
        n if ADMIN_JOURNEYS.contains(&n) => {
            out.extend(admin_control_findings(
                text,
                &loc,
                ctx.permissions,
                ctx.audits,
            ));
        }
        33 => out.extend(timeline_findings(text, &loc)),
        34 => out.extend(incident_findings(text, &loc, ctx.screens)),
        _ => {}
    }
    out
}

/// The three stress cases of one journey (T-0018 step 7).
fn stress_case_findings(text: &str, loc: &str) -> Vec<Finding> {
    let wanted = ["case", "what changes", "what stays usable"];
    let Some(body) = section_body(text, "Stress cases") else {
        return vec![finding(loc, "no `## Stress cases` section (T-0018 step 7)")];
    };
    let tables = tables_in(&body);
    let Some(table) = table_with_header(&tables, &wanted) else {
        return vec![finding(
            loc,
            "the `Stress cases` section has no table with columns Case | What changes | What stays usable (T-0018 step 7)",
        )];
    };
    let mut out = Vec::new();
    let mut seen: BTreeMap<String, usize> = BTreeMap::new();
    for (n, row) in &table.rows {
        let at = format!("{loc}:{n}");
        if row.len() < 3 || row.iter().any(|cell| cell.trim().is_empty()) {
            out.push(finding(
                &at,
                "a stress-case row needs three non-empty cells (T-0018 step 7)",
            ));
            continue;
        }
        let case = normalize_keys(row.first().map_or("", |cell| cell.trim()));
        if !STRESS_CASES.contains(&case.as_str()) {
            out.push(finding(
                &at,
                format!(
                    "`{case}` is not one of the stress cases {} (T-0018 step 7)",
                    STRESS_CASES.join(", ")
                ),
            ));
            continue;
        }
        *seen.entry(case).or_default() += 1;
    }
    for case in STRESS_CASES {
        let count = seen.get(case).copied().unwrap_or(0);
        if count != 1 {
            out.push(finding(
                loc,
                format!(
                    "the stress case `{case}` must appear exactly once, found {count} (T-0018 step 7)"
                ),
            ));
        }
    }
    out
}

/// J-25: the readiness score table and the honesty footnote (T-0018 step 2).
fn readiness_findings(text: &str, loc: &str, screens: &BTreeSet<String>) -> Vec<Finding> {
    let mut out = Vec::new();
    let wanted = [
        "check",
        "weight",
        "status values",
        "why it matters",
        "fix link",
    ];
    match section_body(text, "Readiness score") {
        None => out.push(finding(
            loc,
            "no `## Readiness score` section (T-0018 step 2)",
        )),
        Some(body) => {
            let tables = tables_in(&body);
            match table_with_header(&tables, &wanted) {
                None => out.push(finding(
                    loc,
                    "the `Readiness score` section has no table with columns Check | Weight | Status values | Why it matters | Fix link (T-0018 step 2)",
                )),
                Some(table) => {
                    if table.rows.len() < MIN_READINESS_CHECKS {
                        out.push(finding(
                            loc,
                            format!(
                                "the readiness table has {} checks; at least six are required (T-0018 step 2)",
                                table.rows.len()
                            ),
                        ));
                    }
                    let mut names: BTreeSet<String> = BTreeSet::new();
                    let mut sum = 0_u32;
                    let mut allows_unknown = false;
                    for (n, row) in &table.rows {
                        let at = format!("{loc}:{n}");
                        if row.len() < 5 || row.iter().any(|cell| cell.trim().is_empty()) {
                            out.push(finding(
                                &at,
                                "a readiness row needs five non-empty cells (T-0018 step 2)",
                            ));
                            continue;
                        }
                        let name = normalize_keys(row.first().map_or("", |cell| cell.trim()));
                        if !names.insert(name.clone()) {
                            out.push(finding(
                                &at,
                                format!("the readiness check `{name}` appears twice (T-0018 step 2)"),
                            ));
                        }
                        match row.get(1).map_or("", |cell| cell.trim()).parse::<u32>() {
                            Ok(weight) => sum += weight,
                            Err(_) => out.push(finding(
                                &at,
                                "the `Weight` cell is not a whole number (T-0018 step 2)",
                            )),
                        }
                        let statuses = named_statuses(row.get(2).map_or("", |cell| cell.trim()));
                        if statuses.is_empty() {
                            out.push(finding(
                                &at,
                                format!(
                                    "the `Status values` cell names none of {} (T-0018 step 2)",
                                    READINESS_STATUSES.join(", ")
                                ),
                            ));
                        }
                        if statuses.contains("unknown") {
                            allows_unknown = true;
                        }
                        let links = tokens_in(row.get(4).map_or("", |cell| cell.trim()), r"\bS-\d{3}\b");
                        if links.is_empty() {
                            out.push(finding(
                                &at,
                                "the `Fix link` cell names no S-nnn screen (T-0018 step 2)",
                            ));
                        }
                        for link in links {
                            if !screens.contains(&link) {
                                out.push(finding(
                                    &at,
                                    format!(
                                        "the fix link `{link}` is not a screen of B12.1 (T-0018 step 2)"
                                    ),
                                ));
                            }
                        }
                    }
                    if sum != READINESS_SUM {
                        out.push(finding(
                            loc,
                            format!(
                                "the readiness weights sum to {sum}; they must sum to {READINESS_SUM} (T-0018 step 2)"
                            ),
                        ));
                    }
                    if !allows_unknown {
                        out.push(finding(
                            loc,
                            "no readiness check allows `Unknown`; unknown data must be possible and must never score as pass (T-0018 step 2)",
                        ));
                    }
                }
            }
        }
    }
    match section_body(text, "Honesty footnote") {
        None => out.push(finding(
            loc,
            "no `## Honesty footnote` section (T-0018 step 2)",
        )),
        Some(body) => {
            let joined = body
                .iter()
                .map(|(_, line)| line.as_str())
                .collect::<Vec<_>>()
                .join("\n");
            let lower = joined.to_lowercase();
            if !lower.contains("measures configuration completeness, not security") {
                out.push(finding(
                    loc,
                    "the Honesty footnote does not quote \"Measures configuration completeness, not security.\" (T-0018 step 2)",
                ));
            }
            let names_screen = joined.contains("S-044") || lower.contains("readiness ring");
            let names_place = [
                "below",
                "under",
                "beside",
                "next to",
                "always visible",
                "persistent",
            ]
            .iter()
            .any(|word| lower.contains(word));
            if !(names_screen && names_place) {
                out.push(finding(
                    loc,
                    "the footnote placement is not stated: name S-044 or the readiness ring and a position such as below or always visible (T-0018 step 2)",
                ));
            }
        }
    }
    out
}

/// J-27: the six stages of the API-key lifecycle (T-0018 step 3).
fn api_key_lifecycle_findings(text: &str, loc: &str) -> Vec<Finding> {
    let wanted = ["stage", "what happens", "control"];
    let Some(body) = section_body(text, "API key lifecycle") else {
        return vec![finding(
            loc,
            "no `## API key lifecycle` section (T-0018 step 3)",
        )];
    };
    let tables = tables_in(&body);
    let Some(table) = table_with_header(&tables, &wanted) else {
        return vec![finding(
            loc,
            "the `API key lifecycle` section has no table with columns Stage | What happens | Control (T-0018 step 3)",
        )];
    };
    let mut out = Vec::new();
    let mut seen: BTreeMap<String, usize> = BTreeMap::new();
    for (n, row) in &table.rows {
        let at = format!("{loc}:{n}");
        if row.len() < 3 || row.iter().any(|cell| cell.trim().is_empty()) {
            out.push(finding(
                &at,
                "an API-key lifecycle row needs three non-empty cells (T-0018 step 3)",
            ));
            continue;
        }
        let stage = normalize_keys(row.first().map_or("", |cell| cell.trim()));
        if !API_KEY_STAGES.contains(&stage.as_str()) {
            out.push(finding(
                &at,
                format!(
                    "`{stage}` is not one of the API-key stages {} (T-0018 step 3)",
                    API_KEY_STAGES.join(", ")
                ),
            ));
            continue;
        }
        *seen.entry(stage).or_default() += 1;
    }
    for stage in API_KEY_STAGES {
        let count = seen.get(stage).copied().unwrap_or(0);
        if count != 1 {
            out.push(finding(
                loc,
                format!(
                    "the API-key stage `{stage}` must appear exactly once, found {count} (T-0018 step 3)"
                ),
            ));
        }
    }
    out
}

/// J-29 to J-31: the platform-admin controls (T-0018 step 4, A3).
fn admin_control_findings(
    text: &str,
    loc: &str,
    permissions: &BTreeSet<String>,
    audits: &BTreeSet<String>,
) -> Vec<Finding> {
    let wanted = [
        "action",
        "permission",
        "audit event",
        "reason required",
        "step-up",
    ];
    let Some(body) = section_body(text, "Admin controls") else {
        return vec![finding(
            loc,
            "no `## Admin controls` section (T-0018 step 4)",
        )];
    };
    let tables = tables_in(&body);
    let Some(table) = table_with_header(&tables, &wanted) else {
        return vec![finding(
            loc,
            "the `Admin controls` section has no table with columns Action | Permission | Audit event | Reason required | Step-up (T-0018 step 4)",
        )];
    };
    let mut out = Vec::new();
    let mut actions: BTreeSet<String> = BTreeSet::new();
    let mut pairs: BTreeSet<String> = BTreeSet::new();
    for (n, row) in &table.rows {
        let at = format!("{loc}:{n}");
        if row.len() < 5 || row.iter().any(|cell| cell.trim().is_empty()) {
            out.push(finding(
                &at,
                "an admin-controls row needs five non-empty cells (T-0018 step 4)",
            ));
            continue;
        }
        let action = normalize_keys(row.first().map_or("", |cell| cell.trim()));
        if !actions.insert(action.clone()) {
            out.push(finding(
                &at,
                format!("duplicate action `{action}` in the admin-controls table (T-0018 step 4)"),
            ));
        }
        let permission_cell = row.get(1).map_or("", |cell| cell.trim());
        let permission_tokens = tokens_in(permission_cell, r"\bPERM-[a-z0-9_.]+\b");
        if permission_tokens.is_empty() {
            out.push(finding(
                &at,
                "the `Permission` cell names no PERM- id of B4.2 (T-0018 step 4)",
            ));
        }
        for permission in &permission_tokens {
            if !permissions.contains(permission) {
                out.push(finding(
                    &at,
                    format!("`{permission}` is not a permission of the B4.2 catalog (A3)"),
                ));
            }
            if !permission.starts_with("PERM-platform.") {
                out.push(finding(
                    &at,
                    format!(
                        "`{permission}` is not a platform permission; a platform-admin journey needs a PERM-platform. id (T-0018 step 4)"
                    ),
                ));
            }
        }
        let audit_cell = row.get(2).map_or("", |cell| cell.trim());
        let audit_tokens = tokens_in(audit_cell, r"\bAUD-[a-z0-9_.]+\b");
        if audit_tokens.is_empty() {
            let lower = audit_cell.to_lowercase();
            let says_absent =
                lower.contains("b8") && (lower.contains("no ") || lower.contains("not "));
            if !says_absent {
                out.push(finding(
                    &at,
                    "the `Audit event` cell names no AUD- id of B8 and does not say that B8 has no event (A3)",
                ));
            }
        }
        for audit in &audit_tokens {
            if !audits.contains(audit) {
                out.push(finding(
                    &at,
                    format!("`{audit}` is not an audit event of B8 (A3)"),
                ));
            }
        }
        let pair = format!(
            "{}|{}",
            normalize_keys(permission_cell),
            normalize_keys(audit_cell)
        );
        if !pairs.insert(pair) {
            out.push(finding(
                &at,
                "duplicate permission and audit-event pair in the admin-controls table (T-0018 step 4)",
            ));
        }
        let reason = normalize_keys(row.get(3).map_or("", |cell| cell.trim()));
        if !ADMIN_REASONS.contains(&reason.as_str()) {
            out.push(finding(
                &at,
                format!(
                    "the `Reason required` value `{reason}` is not one of {} (T-0018 step 4)",
                    ADMIN_REASONS.join(", ")
                ),
            ));
        }
        let step_up = normalize_keys(row.get(4).map_or("", |cell| cell.trim()));
        if !ADMIN_STEP_UP.contains(&step_up.as_str()) {
            out.push(finding(
                &at,
                format!(
                    "the `Step-up` value `{step_up}` is not one of {} (T-0018 step 4)",
                    ADMIN_STEP_UP.join(", ")
                ),
            ));
        }
    }
    out
}

/// J-33: the data-export and deletion timelines (T-0018 step 5).
fn timeline_findings(text: &str, loc: &str) -> Vec<Finding> {
    let wanted = ["request", "timeline", "user sees"];
    let Some(body) = section_body(text, "Timelines") else {
        return vec![finding(loc, "no `## Timelines` section (T-0018 step 5)")];
    };
    let tables = tables_in(&body);
    let Some(table) = table_with_header(&tables, &wanted) else {
        return vec![finding(
            loc,
            "the `Timelines` section has no table with columns Request | Timeline | User sees (T-0018 step 5)",
        )];
    };
    let mut out = Vec::new();
    let mut has_export = false;
    let mut has_deletion = false;
    let Ok(duration) = Regex::new(r"\d+\s*(?:minutes?|hours?|days?|weeks?|months?)") else {
        return out;
    };
    for (n, row) in &table.rows {
        let at = format!("{loc}:{n}");
        if row.len() < 3 || row.iter().any(|cell| cell.trim().is_empty()) {
            out.push(finding(
                &at,
                "a timeline row needs three non-empty cells (T-0018 step 5)",
            ));
            continue;
        }
        let request = row.first().map_or("", |cell| cell.trim()).to_lowercase();
        if request.contains("export") {
            has_export = true;
        }
        if request.contains("deletion") || request.contains("delete") {
            has_deletion = true;
        }
        let timeline = row.get(1).map_or("", |cell| cell.trim()).to_lowercase();
        if !duration.is_match(&timeline) {
            out.push(finding(
                &at,
                "the `Timeline` cell states no number and unit, such as hours or days (T-0018 step 5)",
            ));
        }
        if !(timeline.contains("default") && timeline.contains("configur")) {
            out.push(finding(
                &at,
                "the `Timeline` cell must state a configurable default (T-0018 step 5)",
            ));
        }
    }
    if !has_export {
        out.push(finding(
            loc,
            "the `Timelines` table has no data-export row (T-0018 step 5)",
        ));
    }
    if !has_deletion {
        out.push(finding(
            loc,
            "the `Timelines` table has no deletion row (T-0018 step 5)",
        ));
    }
    let joined = body
        .iter()
        .map(|(_, line)| line.as_str())
        .collect::<Vec<_>>()
        .join("\n")
        .to_lowercase();
    let states_default = body.iter().any(|(_, line)| {
        let t = line.trim();
        !t.starts_with('|') && t.contains("default") && t.contains("configur")
    });
    if !states_default {
        out.push(finding(
            loc,
            "the `Timelines` section must state in prose that the timelines are configurable defaults (T-0018 step 5)",
        ));
    }
    for phrase in LEGAL_PROMISES {
        if joined.contains(phrase) {
            out.push(finding(
                loc,
                format!(
                    "the `Timelines` section contains the promise `{phrase}`; use legal-neutral wording (T-0018 step 5)"
                ),
            ));
        }
    }
    out
}

/// J-34: the incident timeline and the retrospective outline (T-0018 step 6, A4).
fn incident_findings(text: &str, loc: &str, screens: &BTreeSet<String>) -> Vec<Finding> {
    let wanted = ["phase", "trigger", "who acts", "screen", "de-escalation"];
    let mut out = Vec::new();
    match section_body(text, "Incident timeline") {
        None => out.push(finding(
            loc,
            "no `## Incident timeline` section (T-0018 step 6)",
        )),
        Some(body) => {
            let tables = tables_in(&body);
            match table_with_header(&tables, &wanted) {
                None => out.push(finding(
                    loc,
                    "the `Incident timeline` section has no table with columns Phase | Trigger | Who acts | Screen | De-escalation (T-0018 step 6)",
                )),
                Some(table) => {
                    let mut detection = false;
                    let mut under_attack = false;
                    let mut analyst = false;
                    let mut de_escalation = false;
                    for (n, row) in &table.rows {
                        let at = format!("{loc}:{n}");
                        if row.len() < 5 || row.iter().any(|cell| cell.trim().is_empty()) {
                            out.push(finding(
                                &at,
                                "an incident-timeline row needs five non-empty cells (T-0018 step 6)",
                            ));
                            continue;
                        }
                        let phase = row.first().map_or("", |cell| cell.trim()).to_lowercase();
                        if phase.contains("detection") {
                            detection = true;
                        }
                        if phase.contains("under-attack") || phase.contains("under attack") {
                            under_attack = true;
                        }
                        if phase.contains("analyst") {
                            analyst = true;
                        }
                        if phase.contains("de-escalation") || phase.contains("deescalation") {
                            de_escalation = true;
                        }
                        let screen_cell = row.get(3).map_or("", |cell| cell.trim());
                        let screen_tokens = tokens_in(screen_cell, r"\bS-\d{3}\b");
                        if screen_tokens.is_empty() {
                            out.push(finding(
                                &at,
                                "the `Screen` cell names no S-nnn screen (T-0018 step 6)",
                            ));
                        }
                        for screen in screen_tokens {
                            if !screens.contains(&screen) {
                                out.push(finding(
                                    &at,
                                    format!(
                                        "`{screen}` is not a screen of B12.1 (T-0018 step 6)"
                                    ),
                                ));
                            }
                        }
                    }
                    for (named, found) in [
                        ("detection", detection),
                        ("under-attack mode", under_attack),
                        ("analyst actions", analyst),
                        ("de-escalation", de_escalation),
                    ] {
                        if !found {
                            out.push(finding(
                                loc,
                                format!(
                                    "the incident timeline does not name the `{named}` phase (T-0018 step 6)"
                                ),
                            ));
                        }
                    }
                }
            }
        }
    }
    match section_body(text, "Retrospective report outline") {
        None => out.push(finding(
            loc,
            "no `## Retrospective report outline` section (T-0018 step 6, A4)",
        )),
        Some(body) => {
            let items: Vec<&str> = body
                .iter()
                .map(|(_, line)| line.trim())
                .filter(|line| {
                    let digits = line.chars().take_while(char::is_ascii_digit).count();
                    digits > 0
                        && line
                            .get(digits..)
                            .is_some_and(|rest| rest.starts_with(". "))
                })
                .collect();
            if items.len() < MIN_RETROSPECTIVE {
                out.push(finding(
                    loc,
                    format!(
                        "the retrospective outline has {} numbered sections; at least eight are required (A4)",
                        items.len()
                    ),
                ));
            }
            for item in items {
                let digits = item.chars().take_while(char::is_ascii_digit).count();
                let title = item.get(digits + 2..).unwrap_or_default().trim();
                if title.split_whitespace().count() < 2 {
                    out.push(finding(
                        loc,
                        format!("the retrospective item `{item}` is not a section title (A4)"),
                    ));
                }
            }
        }
    }
    out
}

/// The cross-journey dependency graph checks (T-0018 step 8, A1 and A2).
pub fn dependencies_findings(
    text: &str,
    journeys: &BTreeSet<String>,
    model: &tasks::Model,
    order: &[String],
) -> Vec<Finding> {
    let loc = JOURNEY_DEPENDENCIES;
    let mut out = Vec::new();
    let wanted = ["journey", "needs", "why"];
    let mut edges: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    match section_body(text, "Dependency table") {
        None => out.push(finding(
            loc,
            "no `## Dependency table` section (T-0018 step 8)",
        )),
        Some(body) => {
            let tables = tables_in(&body);
            match table_with_header(&tables, &wanted) {
                None => out.push(finding(
                    loc,
                    "the `Dependency table` section has no table with columns Journey | Needs | Why (T-0018 step 8)",
                )),
                Some(table) => {
                    for (n, row) in &table.rows {
                        let at = format!("{loc}:{n}");
                        if row.len() < 3 || row.iter().any(|cell| cell.trim().is_empty()) {
                            out.push(finding(
                                &at,
                                "a dependency row needs three non-empty cells (T-0018 step 8)",
                            ));
                            continue;
                        }
                        let journey_tokens =
                            tokens_in(row.first().map_or("", |cell| cell.trim()), r"\bJ-\d{2}\b");
                        if journey_tokens.len() != 1 {
                            out.push(finding(
                                &at,
                                "the `Journey` cell must name exactly one J-nn journey (T-0018 step 8)",
                            ));
                            continue;
                        }
                        let journey = journey_tokens
                            .into_iter()
                            .next()
                            .unwrap_or_default();
                        if !journeys.contains(&journey) {
                            out.push(finding(
                                &at,
                                format!("`{journey}` is not a journey of spec B3 (T-0018 A1)"),
                            ));
                            continue;
                        }
                        if edges.contains_key(&journey) {
                            out.push(finding(
                                &at,
                                format!(
                                    "the journey `{journey}` has more than one dependency row (T-0018 step 8)"
                                ),
                            ));
                        }
                        let needs_cell = normalize_keys(row.get(1).map_or("", |cell| cell.trim()));
                        let mut needs: BTreeSet<String> = BTreeSet::new();
                        if needs_cell != "none" {
                            let tokens =
                                tokens_in(row.get(1).map_or("", |cell| cell.trim()), r"\bJ-\d{2}\b");
                            if tokens.is_empty() {
                                out.push(finding(
                                    &at,
                                    "the `Needs` cell must name a journey or say `none` (T-0018 step 8)",
                                ));
                            }
                            for need in tokens {
                                if !journeys.contains(&need) {
                                    out.push(finding(
                                        &at,
                                        format!(
                                            "`{need}` is not a journey of spec B3 (T-0018 A1)"
                                        ),
                                    ));
                                } else if need == journey {
                                    out.push(finding(
                                        &at,
                                        format!(
                                            "the journey `{journey}` depends on itself (T-0018 A2)"
                                        ),
                                    ));
                                } else {
                                    needs.insert(need);
                                }
                            }
                        }
                        let why = row.get(2).map_or("", |cell| cell.trim()).to_lowercase();
                        let exception = why
                            .split(|c: char| !c.is_alphanumeric())
                            .any(|word| word == "exception");
                        let own = journey_number(&journey).unwrap_or(0);
                        for need in &needs {
                            if journey_number(need).unwrap_or(0) > own && !exception {
                                out.push(finding(
                                    &at,
                                    format!(
                                        "`{journey}` depends on the later journey `{need}`; the `Why` cell must say exception (T-0018 step 8)"
                                    ),
                                ));
                            }
                        }
                        edges.insert(journey, needs);
                    }
                }
            }
        }
    }
    for journey in journeys {
        if !edges.contains_key(journey) {
            out.push(finding(
                loc,
                format!("no dependency row for journey `{journey}` (T-0018 A2)"),
            ));
        }
    }
    out.extend(alternative_edge_findings(&edges, journeys, loc));
    // Kahn's algorithm over the journey graph; the remaining nodes are a cycle.
    let mut indegree: BTreeMap<&str, usize> = journeys
        .iter()
        .map(|journey| (journey.as_str(), 0))
        .collect();
    let mut reverse: BTreeMap<&str, Vec<&str>> = BTreeMap::new();
    for (journey, needs) in &edges {
        if let Some(entry) = indegree.get_mut(journey.as_str()) {
            *entry += needs.len();
        }
        for need in needs {
            reverse
                .entry(need.as_str())
                .or_default()
                .push(journey.as_str());
        }
    }
    let mut ready: Vec<&str> = indegree
        .iter()
        .filter(|(_, count)| **count == 0)
        .map(|(journey, _)| *journey)
        .collect();
    ready.sort_unstable();
    let mut processed = 0_usize;
    while let Some(journey) = ready.pop() {
        processed += 1;
        for dependent in reverse.get(journey).map(Vec::as_slice).unwrap_or(&[]) {
            if let Some(count) = indegree.get_mut(dependent) {
                *count -= 1;
                if *count == 0 {
                    ready.push(dependent);
                }
            }
        }
    }
    if processed != journeys.len() {
        let mut stuck: Vec<String> = indegree
            .iter()
            .filter(|(_, count)| **count > 0)
            .map(|(journey, _)| (*journey).to_owned())
            .collect();
        stuck.sort();
        out.push(finding(
            loc,
            format!(
                "the dependency graph is not acyclic: a cycle leaves these journeys unresolved after the topological sort: {} (T-0018 A2)",
                stuck.join(", ")
            ),
        ));
    }
    // The text graph.
    match section_body(text, "Graph") {
        None => out.push(finding(loc, "no `## Graph` section (T-0018 step 8)")),
        Some(body) => {
            let joined = body
                .iter()
                .map(|(_, line)| line.as_str())
                .collect::<Vec<_>>()
                .join("\n");
            if joined.trim().is_empty() {
                out.push(finding(loc, "the `Graph` section is empty (T-0018 step 8)"));
            }
            // A fenced Mermaid block is outside the prose, so it is found on the raw document.
            if raw_section_contains(text, "Graph", "mermaid") {
                out.push(finding(
                    loc,
                    "the `Graph` section must not use Mermaid; write the graph as text (T-0018 step 8)",
                ));
            }
            if !(joined.contains("->") || joined.contains('→')) {
                out.push(finding(
                    loc,
                    "the text graph has no edges written as `A -> B` (T-0018 step 8)",
                ));
            }
            for journey in journeys {
                if !joined.contains(journey.as_str()) {
                    out.push(finding(
                        loc,
                        format!("the text graph does not mention `{journey}` (T-0018 A2)"),
                    ));
                }
            }
        }
    }
    out.extend(task_dependency_findings(text, &edges, model, order));
    out
}

/// The alternatives rule (T-0018 F-13): two journeys the specification presents as alternatives of the same choice
/// must not depend on each other, in either direction.
fn alternative_edge_findings(
    edges: &BTreeMap<String, BTreeSet<String>>,
    journeys: &BTreeSet<String>,
    loc: &str,
) -> Vec<Finding> {
    let mut out = Vec::new();
    for (left, right, justification) in ALTERNATIVE_JOURNEYS {
        if !journeys.contains(left) || !journeys.contains(right) {
            continue;
        }
        let left_needs_right = edges.get(left).is_some_and(|needs| needs.contains(right));
        let right_needs_left = edges.get(right).is_some_and(|needs| needs.contains(left));
        if left_needs_right || right_needs_left {
            out.push(finding(
                loc,
                format!(
                    "`{left}` and `{right}` are alternatives in the specification ({justification}), so neither may depend on the other (T-0018 F-13)"
                ),
            ));
        }
    }
    out
}

/// The `Task dependencies` section: every row is checked against the real spec task graph (T-0018 A2).
fn task_dependency_findings(
    text: &str,
    edges: &BTreeMap<String, BTreeSet<String>>,
    model: &tasks::Model,
    order: &[String],
) -> Vec<Finding> {
    let loc = JOURNEY_DEPENDENCIES;
    let wanted = [
        "journey dependency",
        "prerequisite task",
        "dependent task",
        "basis",
        "why the order agrees",
    ];
    let Some(body) = section_body(text, "Task dependencies") else {
        return vec![finding(
            loc,
            "no `## Task dependencies` section (T-0018 A2)",
        )];
    };
    let tables = tables_in(&body);
    let Some(table) = table_with_header(&tables, &wanted) else {
        return vec![finding(
            loc,
            "the `Task dependencies` section has no table with columns Journey dependency | Prerequisite task | Dependent task | Basis | Why the order agrees (T-0018 A2)",
        )];
    };
    let position: BTreeMap<&str, usize> = order
        .iter()
        .enumerate()
        .map(|(index, task)| (task.as_str(), index))
        .collect();
    let mut out = Vec::new();
    for (n, row) in &table.rows {
        let at = format!("{loc}:{n}");
        if row.len() < 5 || row.iter().any(|cell| cell.trim().is_empty()) {
            out.push(finding(
                &at,
                "a task-dependency row needs five non-empty cells (T-0018 A2)",
            ));
            continue;
        }
        let pair = ordered_tokens(row.first().map_or("", |cell| cell.trim()), r"\bJ-\d{2}\b");
        if pair.len() != 2 {
            out.push(finding(
                &at,
                "the `Journey dependency` cell must name two journeys, as `J-nn needs J-nn` (T-0018 A2)",
            ));
        } else {
            let mut pair = pair.into_iter();
            let dependent = pair.next().unwrap_or_default();
            let prerequisite = pair.next().unwrap_or_default();
            let known = edges
                .get(&dependent)
                .is_some_and(|needs| needs.contains(&prerequisite));
            if !known {
                out.push(finding(
                    &at,
                    format!(
                        "`{dependent} needs {prerequisite}` is not an edge of the dependency table (T-0018 A2)"
                    ),
                ));
            }
        }
        let prerequisite_cell = row.get(1).map_or("", |cell| cell.trim());
        let dependent_cell = row.get(2).map_or("", |cell| cell.trim());
        let prerequisites = tokens_in(prerequisite_cell, r"\bT-\d{4}\b");
        let dependents = tokens_in(dependent_cell, r"\bT-\d{4}\b");
        for task in prerequisites.iter().chain(dependents.iter()) {
            if model.task(task).is_none() {
                out.push(finding(
                    &at,
                    format!("`{task}` is not a task of the specification (T-0018 A2)"),
                ));
            }
        }
        if prerequisites.len() != 1 || dependents.len() != 1 {
            out.push(finding(
                &at,
                "the task cells must each name exactly one T-nnnn task (T-0018 A2)",
            ));
            continue;
        }
        let prerequisite = prerequisites.into_iter().next().unwrap_or_default();
        let dependent = dependents.into_iter().next().unwrap_or_default();
        let basis = normalize_keys(row.get(3).map_or("", |cell| cell.trim()));
        match basis.as_str() {
            "direct" => {
                let named = model
                    .task(&dependent)
                    .is_some_and(|task| task.deps.contains(&prerequisite));
                if !named {
                    out.push(finding(
                        &at,
                        format!(
                            "the `direct` basis is not true: `{dependent}` does not name `{prerequisite}` in its deps line (T-0018 A2)"
                        ),
                    ));
                }
            }
            "earlier" => {
                let before = position
                    .get(prerequisite.as_str())
                    .zip(position.get(dependent.as_str()))
                    .is_some_and(|(first, second)| first < second);
                if !before {
                    out.push(finding(
                        &at,
                        format!(
                            "the `earlier` basis is not true: the stable task order does not place `{prerequisite}` before `{dependent}` (T-0018 A2)"
                        ),
                    ));
                }
            }
            "none" => {
                let why = normalize_keys(row.get(4).map_or("", |cell| cell.trim()));
                if !why.contains("no task dependency") {
                    out.push(finding(
                        &at,
                        "a `none` row must say `no task dependency` in its `Why the order agrees` cell (T-0018 A2)",
                    ));
                }
            }
            other => out.push(finding(
                &at,
                format!("the `Basis` value `{other}` is not direct, earlier or none (T-0018 A2)"),
            )),
        }
        // F-13: a mapped edge whose prerequisite task comes after the dependent task contradicts the journey order
        // unless the row records that as a documented exception.
        let after = position
            .get(prerequisite.as_str())
            .zip(position.get(dependent.as_str()))
            .is_some_and(|(first, second)| first > second);
        if after {
            let why = row.get(4).map_or("", |cell| cell.trim()).to_lowercase();
            let exception = why
                .split(|c: char| !c.is_alphanumeric())
                .any(|word| word == "exception");
            if !exception {
                out.push(finding(
                    &at,
                    format!(
                        "the prerequisite task `{prerequisite}` comes after the dependent task `{dependent}` in the stable order; the `Why the order agrees` cell must say exception (T-0018 F-13)"
                    ),
                ));
            }
        }
    }
    out
}
