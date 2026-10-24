//! `ux-docs` checks for T-0025 (security UX: dangerous actions, self-lockout prevention, honest
//! warnings).
//!
//! The rules, stated here because this module enforces them:
//!
//! * the two documents `docs/UX/dangerous-actions.md` and `docs/UX/SECURITY-UX.md` and the copy file
//!   `i18n/en/security-ux.ftl` exist (T-0025 deliverables);
//! * the catalog has at least twenty rows, each with a non-empty risk, safeguard, undo path, audit
//!   event, permission and copy key, and each safeguard names at least one of preview, dry-run,
//!   typed confirmation, time box or step-up (T-0025 step 2, A1);
//! * the catalog names every action of T-0025 step 1 (domain removal, DNS delete, nameserver change,
//!   block-mode switch, ban, access-list deny, geo-block, a rule with a broad scope, safe mode,
//!   origin lockdown, API key creation, MFA removal, org deletion and a global change);
//! * every `AUD-` id cited exists in B8 and its area belongs to the permission family of its row
//!   (T-0025 step 2, A5); every `PERM-` id cited exists in B4.2;
//! * every catalog copy key is defined exactly once in the copy file with a non-empty, distinct,
//!   claim-free value, and the copy file has no key the catalog does not name (T-0025 A5, B13);
//! * the abuse cases cite real C5 `ATK-` ids drawn from ATK-285 to ATK-300 and cover at least
//!   clickjacking, CSRF, UI redress and the confused deputy in impersonation (T-0025 step 8, A4), each
//!   with the exact C5 attack name of the cited id; clickjacking and UI redress use the generic class
//!   ATK-171 (UI redress says that no exact C5 class exists) and CSRF uses ATK-296;
//! * typed confirmation is the decided set of B11.9 item 2, T-0068 A5 (spec line 6017) and the two
//!   recorded extensions: every row whose Safeguards require it has a `Type { $resource }` copy value
//!   naming the typed resource, exactly those rows are listed in TC-7, and a journey step that says
//!   `typed` has a catalog row on that screen with typed confirmation (T-0025 step 5);
//! * a `step-up` claim matches the B4.2 `S` cells of the row's permission: an `S` needs step-up, and a
//!   claim without any `S` must say `stronger than B4.2` (T-0025 step 2, B4.2, review F-15);
//! * every `(DA-nn)` reference in the catalog prose names a row whose Audit event is the event named
//!   next to it (review F-18);
//! * the self-lockout guard has numbered, testable requirements that name the acting IP, the
//!   session, the admin CIDR collision, where it runs, how it is displayed and the fail-safe
//!   behaviour (T-0025 step 3, A2, B11.9 item 3);
//! * the preview patterns cover DNS, rules, access lists and policies, each saying what it must show
//!   and what it must not hide (T-0025 step 4);
//! * the typed-confirmation rules state the exact resource name, case sensitivity, paste allowance
//!   and the ban on a checkbox substitute (T-0025 step 5);
//! * the time-box pattern states the visible countdown, explicit extend and the server-side revert
//!   when the browser closes (T-0025 step 6, A3);
//! * the honest limits name the shield, virtual patches, readiness and block-mode collateral and
//!   quote the B13 copy exactly (T-0025 step 7);
//! * the STRIDE delta exists and names the UI-abuse threats, the counter-requirement and the test
//!   (T-0025 step 8, `[SEC]` definition of done);
//! * no document or copy value contains a forbidden claims phrase (R-10).
//!
//! Whole-token matching is used for every id and key (the review-lesson rule). Malformed or missing
//! input produces a finding, never a panic: no indexing, no `unwrap`, no `expect` in this module.

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

use regex::Regex;

use crate::claims;
use crate::util::{Finding, read_text};

use super::{cells, column, prose_lines, s_tokens, section_body, section_table};

/// The catalog document (T-0025 deliverable).
pub const DANGEROUS_ACTIONS: &str = "docs/UX/dangerous-actions.md";
/// The guard and pattern document (T-0025 deliverable).
pub const SECURITY_UX: &str = "docs/UX/SECURITY-UX.md";
/// The confirmation copy (T-0025 A5).
pub const COPY: &str = "i18n/en/security-ux.ftl";
/// The threat-model deltas (the `[SEC]` definition of done).
pub const STRIDE: &str = "docs/STRIDE.md";

/// T-0025 A1: at least this many dangerous actions.
const MIN_ACTIONS: usize = 20;
/// T-0025 A4: at least this many UI abuse cases.
const MIN_ABUSE_CASES: usize = 4;
/// T-0025 A2: at least this many numbered guard requirements.
const MIN_GUARD_REQUIREMENTS: usize = 10;
/// T-0025 A4: the HDD-surface attack rows the abuse cases must draw from.
const ABUSE_FIRST: u16 = 285;
/// T-0025 A4: the last HDD-surface attack row.
const ABUSE_LAST: u16 = 300;
/// The catalog columns the rule requires (T-0025 step 2).
const CATALOG_COLUMNS: [&str; 6] = [
    "Action",
    "Risk",
    "Safeguards",
    "Undo path",
    "Audit event",
    "Copy key",
];
/// The safeguard kinds of T-0025 step 2.
const SAFEGUARD_KINDS: [&str; 5] = [
    "preview",
    "dry-run",
    "typed confirmation",
    "time box",
    "step-up",
];
/// Shape of a semantic hyphenated i18n key (B11.12).
const KEY_SHAPE: &str = r"^[a-z0-9]+(-[a-z0-9]+)*$";
/// The six STRIDE categories the delta must address.
const STRIDE_THREATS: [&str; 6] = [
    "Spoofing",
    "Tampering",
    "Repudiation",
    "Information disclosure",
    "Denial of service",
    "Elevation of privilege",
];
/// The UI-abuse categories of T-0025 step 8 and A4.
const ABUSE_CATEGORIES: [&str; 4] = ["clickjacking", "csrf", "ui redress", "confused deputy"];

/// A `ux-docs` finding.
fn at(location: impl Into<String>, message: impl Into<String>) -> Finding {
    Finding::new("ux-docs", location, message)
}

/// True when `text` contains `token` as a whole word (case-insensitive).
fn has_token(text: &str, token: &str) -> bool {
    Regex::new(&format!(r"(?i)\b{}\b", regex::escape(token))).is_ok_and(|re| re.is_match(text))
}

/// True when one of `tokens` is present as a whole word.
fn has_any(text: &str, tokens: &[&str]) -> bool {
    tokens.iter().any(|token| has_token(text, token))
}

/// True when every group of alternatives has at least one member present.
fn has_all(text: &str, groups: &[&[&str]]) -> bool {
    groups.iter().all(|group| has_any(text, group))
}

/// True when `phrase` appears in `text` as consecutive whole words, ignoring punctuation. A word is a
/// run of letters, digits and hyphens, so `(clickjacking).` and `` `Run as dry-run first` `` match.
fn mentions_words(text: &str, phrase: &str) -> bool {
    fn words(text: &str) -> Vec<String> {
        text.split(|c: char| !(c.is_alphanumeric() || c == '-'))
            .filter(|word| !word.is_empty())
            .map(str::to_lowercase)
            .collect()
    }
    let haystack = words(text);
    let needle = words(phrase);
    !needle.is_empty()
        && haystack
            .windows(needle.len())
            .any(|window| window == needle.as_slice())
}

/// The T-0025 step 1 actions the catalog must name. Every group needs a whole token; the action cell
/// matches when all groups match.
fn required_actions() -> Vec<(&'static str, Vec<Vec<&'static str>>)> {
    vec![
        (
            "domain removal",
            vec![
                vec!["domain"],
                vec!["removal", "remove", "removing", "decommission"],
            ],
        ),
        ("DNS delete", vec![vec!["dns"], vec!["delete", "deletion"]]),
        (
            "nameserver change guidance",
            vec![vec!["nameserver", "nameservers"]],
        ),
        ("block-mode switch", vec![vec!["block"], vec!["mode"]]),
        ("ban (manual or global)", vec![vec!["ban"]]),
        (
            "access-list deny",
            vec![vec!["access"], vec!["deny", "denies", "denial"]],
        ),
        ("geo-block", vec![vec!["geo"]]),
        (
            "rule with a broad scope",
            vec![vec!["rule"], vec!["scope", "broad"]],
        ),
        ("safe mode", vec![vec!["safe"], vec!["mode"]]),
        ("origin lockdown", vec![vec!["origin"], vec!["lockdown"]]),
        (
            "API key creation",
            vec![
                vec!["api"],
                vec!["key"],
                vec!["create", "creating", "creation"],
            ],
        ),
        ("MFA removal", vec![vec!["mfa"]]),
        (
            "org deletion",
            vec![
                vec!["org", "organisation", "organization"],
                vec!["delete", "deletion", "remove"],
            ],
        ),
        ("global changes", vec![vec!["global"]]),
    ]
}

/// The honest-limits placements, the tokens that identify each row, and the B13 key it must quote
/// (T-0025 step 7).
fn honest_limits_required() -> Vec<(&'static str, Vec<Vec<&'static str>>, &'static str)> {
    vec![
        ("shield", vec![vec!["shield"]], "shield-limit"),
        (
            "virtual patches",
            vec![vec!["virtual"], vec!["patch", "patches"]],
            "virtual-patch-banner",
        ),
        ("readiness", vec![vec!["readiness"]], "readiness-footnote"),
        (
            "block-mode collateral",
            vec![vec!["block"], vec!["collateral"]],
            "block-confirm-body",
        ),
    ]
}

/// The `AUD-` ids in `text`, trimmed of a trailing sentence stop. A token such as `AUD-ban.createdx`
/// stays one token and therefore fails the B8 lookup (whole-token rule).
fn audit_tokens(text: &str) -> Vec<String> {
    let mut out = Vec::new();
    let Ok(re) = Regex::new(r"\bAUD-[A-Za-z0-9_.]+") else {
        return out;
    };
    for found in re.find_iter(text) {
        let token = found.as_str().trim_end_matches('.');
        if !token.is_empty() {
            out.push(token.to_owned());
        }
    }
    out
}

/// The `PERM-` ids in `text`.
fn permission_tokens(text: &str) -> Vec<String> {
    let mut out = Vec::new();
    let Ok(re) = Regex::new(r"\bPERM-[A-Za-z0-9_.]+") else {
        return out;
    };
    for found in re.find_iter(text) {
        let token = found.as_str().trim_end_matches('.');
        if !token.is_empty() {
            out.push(token.to_owned());
        }
    }
    out
}

/// The `ATK-` ids in `text`, whole tokens only.
fn atk_tokens(text: &str) -> Vec<String> {
    let mut out = Vec::new();
    let Ok(re) = Regex::new(r"\bATK-\d{3}\b") else {
        return out;
    };
    for found in re.find_iter(text) {
        out.push(found.as_str().to_owned());
    }
    out
}

/// The numeric part of an `ATK-nnn` id.
fn atk_number(id: &str) -> Option<u16> {
    id.strip_prefix("ATK-").and_then(|n| n.parse().ok())
}

/// The Fluent variable that names each typed resource (review F-14). The key is the resource phrase the
/// Safeguards cell writes after `typed confirmation of`; the value is the variable the copy interpolates
/// in `Type { $variable }`.
const TYPED_RESOURCE_VARS: [(&str, &str); 8] = [
    ("domain name", "domain"),
    ("organisation slug", "org"),
    ("setting name", "setting"),
    ("address", "address"),
    ("pack name", "pack"),
    ("cidr", "cidr"),
    ("emergency control name", "control"),
    ("tenant name", "tenant"),
];

/// One row of the dangerous-action catalog, read from the columns the review rules use. Reading the
/// table once keeps the screen, typed, step-up and prose rules on the same cells.
struct CatalogRow {
    /// 1-based line number of the row.
    line: usize,
    /// The `ID` cell.
    id: String,
    /// The `Action` cell.
    action: String,
    /// The `S-nnn` ids of the `Screen` cell (a row may be reachable from more than one screen).
    screens: Vec<String>,
    /// The `PERM-` ids of the `Permission` cell.
    permissions: Vec<String>,
    /// The `Safeguards` cell.
    safeguards: String,
    /// The `AUD-` ids of the `Audit event` cell.
    audits: Vec<String>,
    /// The `Copy key` cell without its backticks.
    copy_key: String,
}

/// The value of one cell, or the empty string when the column or cell is absent.
fn cell(row: &[String], index: Option<usize>) -> String {
    index
        .and_then(|index| row.get(index))
        .map(|cell| cell.trim().to_owned())
        .unwrap_or_default()
}

/// The catalog rows with the cells the review rules read (review F-14 to F-18).
fn catalog_rows(text: &str) -> Vec<CatalogRow> {
    let mut out = Vec::new();
    let Some((header, rows)) = section_table(text, "Catalog") else {
        return out;
    };
    let id = column(&header, "ID");
    let action = column(&header, "Action");
    let screen = column(&header, "Screen");
    let permission = column(&header, "Permission");
    let safeguards = column(&header, "Safeguards");
    let audit = column(&header, "Audit event");
    let copy = column(&header, "Copy key");
    for (n, row) in rows {
        let id = cell(&row, id);
        if id.is_empty() {
            continue;
        }
        let screens = screen
            .and_then(|index| row.get(index))
            .map(|cell| s_tokens(cell))
            .unwrap_or_default();
        let permission_cell = cell(&row, permission);
        let safeguard_cell = cell(&row, safeguards);
        let audit_cell = cell(&row, audit);
        out.push(CatalogRow {
            line: n,
            id,
            action: cell(&row, action),
            screens,
            permissions: permission_tokens(&permission_cell),
            safeguards: safeguard_cell,
            audits: audit_tokens(&audit_cell),
            copy_key: cell(&row, copy)
                .trim_matches('`')
                .trim_matches('*')
                .trim()
                .to_owned(),
        });
    }
    out
}

/// True when the row's Safeguards require typed confirmation (whole phrase, review F-14).
fn is_typed_row(row: &CatalogRow) -> bool {
    mentions_words(&row.safeguards, "typed confirmation")
}

/// The resource phrase a row asks the user to type: the words after `typed confirmation of` up to the
/// next punctuation mark, without a leading article. `None` when the row does not say what to type.
fn typed_resource(safeguards: &str) -> Option<String> {
    let lower = safeguards.to_lowercase();
    let marker = "typed confirmation of";
    let start = lower.find(marker)? + marker.len();
    let rest = lower.get(start..)?;
    let end = rest.find([';', ',', '.']).unwrap_or(rest.len());
    let phrase = rest.get(..end).unwrap_or(rest).trim();
    let phrase = phrase.strip_prefix("the ").unwrap_or(phrase).trim();
    (!phrase.is_empty()).then(|| phrase.to_owned())
}

/// The Fluent variable a typed resource must interpolate (review F-14). A resource the table does not
/// map is a finding, so a row cannot name a resource the copy never mentions.
fn typed_variable(resource: &str) -> Option<&'static str> {
    TYPED_RESOURCE_VARS
        .iter()
        .find(|(phrase, _)| phrase.eq_ignore_ascii_case(resource))
        .map(|(_, variable)| *variable)
}

/// The `DA-nn` ids of the TC-7 item (review F-14: every typed row is listed in TC-7). The item starts
/// at a list bullet carrying `TC-7` and runs to the next bullet.
fn tc7_rows(security: &str) -> BTreeSet<String> {
    let mut out = BTreeSet::new();
    let Some(body) = section_body(security, "Typed-confirmation rules") else {
        return out;
    };
    let Ok(re) = Regex::new(r"\bDA-\d{2}\b") else {
        return out;
    };
    let mut inside = false;
    for (_, line) in &body {
        let trimmed = line.trim_start();
        if trimmed.starts_with("- ") || trimmed.starts_with("* ") {
            inside = trimmed.to_lowercase().contains("tc-7");
        }
        if inside {
            for found in re.find_iter(line) {
                out.insert(found.as_str().to_owned());
            }
        }
    }
    out
}

/// T-0025 step 5 (review F-14): every typed row's copy value names the typed resource as a `Type { }`
/// interpolation.
fn typed_copy_findings(actions: &str, ftl: &str) -> Vec<Finding> {
    let mut out = Vec::new();
    let messages = parse_ftl(ftl);
    let mut values: BTreeMap<&str, &str> = BTreeMap::new();
    for message in &messages {
        values
            .entry(message.key.as_str())
            .or_insert(message.value.as_str());
    }
    let Ok(type_re) = Regex::new(r"Type \{\s*\$([a-z][a-z0-9_]*)\s*\}") else {
        return out;
    };
    for row in catalog_rows(actions) {
        if !is_typed_row(&row) {
            continue;
        }
        let loc = format!("{DANGEROUS_ACTIONS}:{}", row.line);
        let Some(resource) = typed_resource(&row.safeguards) else {
            out.push(at(
                loc,
                format!(
                    "the typed confirmation of \"{}\" does not say what the user must type; write `typed confirmation of the <resource>` (T-0025 step 5, review F-14)",
                    row.action
                ),
            ));
            continue;
        };
        let Some(expected) = typed_variable(&resource) else {
            out.push(at(
                loc,
                format!(
                    "the typed resource \"{resource}\" has no Fluent variable mapping in TYPED_RESOURCE_VARS (T-0025 step 5, review F-14)"
                ),
            ));
            continue;
        };
        let Some(value) = values.get(row.copy_key.as_str()) else {
            out.push(at(
                loc,
                format!(
                    "the typed row names the copy key \"{}\", which the copy file does not define (T-0025 A5)",
                    row.copy_key
                ),
            ));
            continue;
        };
        match type_re.captures(value) {
            None => out.push(at(
                loc,
                format!(
                    "the value of \"{}\" has no `Type {{ $variable }}` shape, so it never asks the user to type (T-0025 step 5, review F-14)",
                    row.copy_key
                ),
            )),
            Some(found) => {
                let got = found.get(1).map(|m| m.as_str()).unwrap_or_default();
                if got != expected {
                    out.push(at(
                        loc,
                        format!(
                            "the value of \"{}\" types `{got}` but the row requires the {resource} (`${expected}`) (T-0025 step 5, review F-14)",
                            row.copy_key
                        ),
                    ));
                }
            }
        }
    }
    out
}

/// T-0025 step 5 (review F-14): exactly the typed rows are listed in TC-7, and TC-7 lists no other row.
fn typed_scope_findings(security: &str, actions: &str) -> Vec<Finding> {
    let mut out = Vec::new();
    let typed: BTreeSet<String> = catalog_rows(actions)
        .into_iter()
        .filter(is_typed_row)
        .map(|row| row.id)
        .collect();
    let listed = tc7_rows(security);
    for id in typed.difference(&listed) {
        out.push(at(
            format!("{SECURITY_UX} TC-7"),
            format!(
                "the row `{id}` requires typed confirmation but TC-7 does not list it (T-0025 step 5, review F-14)"
            ),
        ));
    }
    for id in listed.difference(&typed) {
        out.push(at(
            format!("{SECURITY_UX} TC-7"),
            format!(
                "TC-7 lists `{id}`, but the Safeguards of that catalog row do not require typed confirmation (T-0025 step 5, review F-14)"
            ),
        ));
    }
    out
}

/// The screens of each numbered step of a journey `## Steps` table.
fn journey_step_screens(text: &str) -> BTreeMap<usize, Vec<String>> {
    let mut out = BTreeMap::new();
    let Some((header, rows)) = section_table(text, "Steps") else {
        return out;
    };
    let (Some(step_index), Some(screen_index)) =
        (column(&header, "Step"), column(&header, "Screen"))
    else {
        return out;
    };
    for (_, row) in rows {
        let Some(step) = row
            .get(step_index)
            .and_then(|cell| cell.trim().parse::<usize>().ok())
        else {
            continue;
        };
        let screens = row
            .get(screen_index)
            .map(|cell| s_tokens(cell))
            .unwrap_or_default();
        out.entry(step).or_insert(screens);
    }
    out
}

/// The steps of a journey that say `typed` in its Safeguards or Accessibility tables, with the screens
/// of the step (review F-14: a journey that says typed for a risky step needs a catalog row that does).
fn typed_journey_steps(text: &str) -> Vec<(usize, Vec<String>)> {
    let mut out = Vec::new();
    let steps = journey_step_screens(text);
    let step_screens = |step_index: Option<usize>, row: &[String]| -> Vec<String> {
        step_index
            .and_then(|index| row.get(index))
            .and_then(|cell| cell.trim().parse::<usize>().ok())
            .and_then(|step| steps.get(&step).cloned())
            .unwrap_or_default()
    };
    if let Some((header, rows)) = section_table(text, "Safeguards") {
        let step_index = column(&header, "Step");
        let typed_columns = [
            column(&header, "Risky action"),
            column(&header, "Safeguard"),
            column(&header, "Kind"),
        ];
        for (n, row) in rows {
            let says = typed_columns
                .iter()
                .filter_map(|index| index.and_then(|index| row.get(index)))
                .any(|cell| has_token(cell, "typed"));
            if says {
                out.push((n, step_screens(step_index, &row)));
            }
        }
    }
    if let Some((header, rows)) = section_table(text, "Accessibility considerations") {
        let step_index = column(&header, "Step");
        for (n, row) in rows {
            if row.iter().any(|cell| has_token(cell, "typed")) {
                out.push((n, step_screens(step_index, &row)));
            }
        }
    }
    out
}

/// T-0025 step 5 (review F-14): a journey step that says `typed` needs a catalog row on that screen whose
/// Safeguards require typed confirmation.
fn typed_journey_findings(journeys: &[(String, String)], actions: &str) -> Vec<Finding> {
    let mut out = Vec::new();
    let typed: Vec<CatalogRow> = catalog_rows(actions)
        .into_iter()
        .filter(is_typed_row)
        .collect();
    for (path, text) in journeys {
        for (line, screens) in typed_journey_steps(text) {
            let covered = typed
                .iter()
                .any(|row| screens.iter().any(|screen| row.screens.contains(screen)));
            if covered {
                continue;
            }
            let named = if screens.is_empty() {
                "no step screen".to_owned()
            } else {
                screens.join(", ")
            };
            out.push(at(
                format!("{path}:{line}"),
                format!(
                    "the step says `typed` but no catalog row on {named} requires typed confirmation (T-0025 step 5, review F-14)"
                ),
            ));
        }
    }
    out
}

/// The `S` (step-up) state of every B4.2 permission, read from the role cells of the permission table
/// (review F-15). The description cell is skipped, so the word "step-up" in a description is not an `S`.
/// Every `B4.2` section of the text is read and a permission that has an `S` in any of them counts as
/// step-up: a fixture repository may carry a short permission table of its own before the T-0025 rows.
fn permission_stepup(spec: &str) -> BTreeMap<String, bool> {
    let mut out = BTreeMap::new();
    let mut inside = false;
    for line in spec.lines() {
        if let Some(title) = spec_heading(line) {
            inside = title.split_whitespace().next() == Some("B4.2");
            continue;
        }
        if !inside {
            continue;
        }
        let Some(row) = cells(line) else {
            continue;
        };
        let Some(first) = row.first() else {
            continue;
        };
        let id = first.trim();
        if !id.starts_with("PERM-") {
            continue;
        }
        let has_s = row.iter().skip(2).any(|cell| cell.trim() == "S");
        out.entry(id.to_owned())
            .and_modify(|value| *value = *value || has_s)
            .or_insert(has_s);
    }
    out
}

/// T-0025 step 2 and B4.2 (review F-15): a permission with an `S` role cell needs `step-up` in the
/// Safeguards, and a step-up claim on a permission without any `S` must say `stronger than B4.2`.
fn stepup_findings(actions: &str, spec: &str) -> Vec<Finding> {
    let mut out = Vec::new();
    let stepup = permission_stepup(spec);
    if stepup.is_empty() {
        out.push(at(
            "docs/SPEC.md",
            "the B4.2 permission catalog has no PERM rows, so the step-up claims cannot be checked (review F-15)",
        ));
        return out;
    }
    for row in catalog_rows(actions) {
        let known: Vec<bool> = row
            .permissions
            .iter()
            .filter_map(|permission| stepup.get(permission).copied())
            .collect();
        if known.is_empty() {
            continue;
        }
        let requires = known.iter().any(|has_s| *has_s);
        let claims = mentions_words(&row.safeguards, "step-up");
        let stronger = mentions_words(&row.safeguards, "stronger than B4.2");
        let loc = format!("{DANGEROUS_ACTIONS}:{}", row.line);
        if requires && !claims {
            out.push(at(
                loc.clone(),
                format!(
                    "a permission of \"{}\" has `S` in B4.2, so the Safeguards must name step-up (review F-15)",
                    row.action
                ),
            ));
        }
        if claims && !requires && !stronger {
            out.push(at(
                loc,
                format!(
                    "the step-up claim of \"{}\" has no B4.2 `S`; write `step-up (stronger than B4.2)` or remove it (review F-15)",
                    row.action
                ),
            ));
        }
    }
    out
}

/// The C5 attack name of every `ATK-nnn` row, copied from the `Attack` column of the master
/// specification's C5 matrix (review F-16). The matrix is split into `AG-` subsections, so the rows are
/// read the same way [`super::attack_registry`] reads the ids: every table row whose first cell is an
/// `ATK-nnn` id. The abuse table cites a name that is compared whole-string.
fn attack_names(spec: &str) -> BTreeMap<String, String> {
    let mut out = BTreeMap::new();
    let Ok(id_re) = Regex::new(r"^ATK-\d{3}$") else {
        return out;
    };
    for line in spec.lines() {
        let Some(row) = cells(line) else {
            continue;
        };
        let Some(id) = row.first() else {
            continue;
        };
        let id = id.trim();
        if !id_re.is_match(id) {
            continue;
        }
        if let Some(name) = row.get(1) {
            let name = name.trim();
            if !name.is_empty() {
                out.insert(id.to_owned(), name.to_owned());
            }
        }
    }
    out
}

/// Review F-18: every `(DA-nn)` reference in the catalog prose sits next to the audit event that row
/// writes. A reference to an unknown row is a finding too. Table rows are excluded (the prose rule).
fn audit_reference_findings(text: &str) -> Vec<Finding> {
    let mut out = Vec::new();
    let rows = catalog_rows(text);
    let by_id: BTreeMap<&str, &CatalogRow> =
        rows.iter().map(|row| (row.id.as_str(), row)).collect();
    let (Ok(da_re), Ok(aud_re)) = (
        Regex::new(r"\(DA-(\d{2})\)"),
        Regex::new(r"AUD-[A-Za-z0-9_.]+"),
    ) else {
        return out;
    };
    for (n, line) in prose_lines(text) {
        if cells(line).is_some() {
            continue;
        }
        let mut events: Vec<(usize, String)> = Vec::new();
        for found in aud_re.find_iter(line) {
            events.push((
                found.start(),
                found.as_str().trim_end_matches('.').to_owned(),
            ));
        }
        if events.is_empty() {
            continue;
        }
        for found in da_re.captures_iter(line) {
            let Some(whole) = found.get(0) else {
                continue;
            };
            let Some(number) = found.get(1) else {
                continue;
            };
            let id = format!("DA-{}", number.as_str());
            let Some(row) = by_id.get(id.as_str()) else {
                out.push(at(
                    format!("{DANGEROUS_ACTIONS}:{n}"),
                    format!(
                        "the prose reference `{id}` names no row of the dangerous-action catalog (review F-18)"
                    ),
                ));
                continue;
            };
            let nearest = events.iter().min_by_key(|(index, token)| {
                let start = *index;
                let mid = start + token.len() / 2;
                mid.abs_diff(whole.start())
            });
            let Some((_, nearest)) = nearest else {
                continue;
            };
            if row.audits.iter().any(|audit| audit == nearest) {
                continue;
            }
            let audit = if row.audits.is_empty() {
                "no audit event".to_owned()
            } else {
                row.audits.join(", ")
            };
            out.push(at(
                format!("{DANGEROUS_ACTIONS}:{n}"),
                format!(
                    "the prose reference `{id}` sits next to `{nearest}`, but that row's Audit event is `{audit}` (review F-18)"
                ),
            ));
        }
    }
    out
}

/// True when `key` is a semantic hyphenated i18n key.
fn key_shape_ok(key: &str) -> bool {
    Regex::new(KEY_SHAPE).is_ok_and(|re| re.is_match(key))
}

/// True when `text` contains an emoji or a decorative dingbat (the same ranges as the copy-deck rule).
fn has_emoji(text: &str) -> bool {
    text.chars().any(|c| {
        let u = c as u32;
        (0x1F000..=0x1FAFF).contains(&u)
            || (0x1F1E6..=0x1F1FF).contains(&u)
            || (0x2600..=0x27BF).contains(&u)
            || (0xFE00..=0xFE0F).contains(&u)
            || u == 0x2B50
            || u == 0x2B55
    })
}

/// One message of the Fluent file.
struct Message {
    /// 1-based line number.
    line: usize,
    /// The key on the left of `=`.
    key: String,
    /// The value on the right of `=`, trimmed.
    value: String,
}

/// Parse the messages of a Fluent file; comment and blank lines are skipped.
fn parse_ftl(text: &str) -> Vec<Message> {
    let mut out = Vec::new();
    for (n, line) in text.lines().enumerate() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        match trimmed.split_once('=') {
            Some((key, value)) => out.push(Message {
                line: n + 1,
                key: key.trim().to_owned(),
                value: value.trim().to_owned(),
            }),
            None => out.push(Message {
                line: n + 1,
                key: String::new(),
                value: trimmed.to_owned(),
            }),
        }
    }
    out
}

/// The copy keys of the catalog table, with their line numbers.
fn catalog_copy_keys(text: &str) -> Vec<(usize, String)> {
    let mut out = Vec::new();
    let Some((header, rows)) = section_table(text, "Catalog") else {
        return out;
    };
    let Some(index) = column(&header, "Copy key") else {
        return out;
    };
    for (n, row) in rows {
        let Some(cell) = row.get(index) else {
            continue;
        };
        let key = cell
            .trim()
            .trim_matches('`')
            .trim_matches('*')
            .trim()
            .to_owned();
        if !key.is_empty() {
            out.push((n, key));
        }
    }
    out
}

/// The B8 event ids of every `B8.` section in the specification, expanded through the parent helper so
/// the slash rows (for example `AUD-waf.safe_mode_on / off`) are read exactly as the rest of the crate
/// reads them.
fn b8_ids(spec: &str) -> BTreeSet<String> {
    let rows = section_lines(spec, "B8.");
    if rows.is_empty() {
        return BTreeSet::new();
    }
    super::audit_ids(&format!("## B8. audit events\n{rows}"))
}

/// The B4.2 permission ids of every `B4.2` section in the specification.
fn permission_catalog(spec: &str) -> BTreeSet<String> {
    let rows = section_lines(spec, "B4.2");
    if rows.is_empty() {
        return BTreeSet::new();
    }
    super::permission_ids(&format!("### B4.2 permission catalog\n{rows}"))
}

/// The B13 key-to-text rows of every `B13.` section in the specification.
fn b13_copy(spec: &str) -> BTreeMap<String, String> {
    let mut out = BTreeMap::new();
    let mut inside = false;
    for line in spec.lines() {
        if let Some(title) = spec_heading(line) {
            inside = title.split_whitespace().next() == Some("B13.");
            continue;
        }
        if !inside {
            continue;
        }
        let Some(row) = super::cells(line) else {
            continue;
        };
        let Some(key) = row.first() else {
            continue;
        };
        let key = key.trim().trim_matches('`');
        if key.is_empty()
            || key.eq_ignore_ascii_case("Key stem")
            || key.chars().all(|c| c == '-' || c == ':')
        {
            continue;
        }
        let text = row.get(1).cloned().unwrap_or_default();
        out.entry(key.to_owned()).or_insert(text);
    }
    out
}

/// The title of a specification heading line (`## ` or `### `).
fn spec_heading(line: &str) -> Option<&str> {
    let trimmed = line.trim_start();
    trimmed
        .strip_prefix("## ")
        .or_else(|| trimmed.strip_prefix("### "))
        .map(str::trim)
}

/// The body lines of every section whose heading's first token equals `token`.
fn section_lines(spec: &str, token: &str) -> String {
    let mut out = String::new();
    let mut inside = false;
    for line in spec.lines() {
        if let Some(title) = spec_heading(line) {
            inside = title.split_whitespace().next() == Some(token);
            continue;
        }
        if inside {
            out.push_str(line);
            out.push('\n');
        }
    }
    out
}

/// The body lines of the first level-2 section whose title starts with `prefix`.
fn section_starting_with(text: &str, prefix: &str) -> Option<Vec<(usize, String)>> {
    let mut inside = false;
    let mut found = false;
    let mut out = Vec::new();
    for (n, line) in text.lines().enumerate() {
        if let Some(title) = line.trim_start().strip_prefix("## ") {
            if inside {
                break;
            }
            if title.trim().starts_with(prefix) {
                inside = true;
                found = true;
            }
            continue;
        }
        if inside {
            out.push((n + 1, line.to_owned()));
        }
    }
    found.then_some(out)
}

/// Join body lines into text.
fn body_text(lines: &[(usize, String)]) -> String {
    lines
        .iter()
        .map(|(_, line)| line.as_str())
        .collect::<Vec<_>>()
        .join("\n")
}

/// Header cells and body rows of a Markdown table, as the parent parser returns them.
type ParsedTable = (Vec<String>, Vec<(usize, Vec<String>)>);

/// The first Markdown table among body lines, read through the parent table parser.
fn table_in_lines(lines: &[(usize, String)]) -> Option<ParsedTable> {
    let synthetic = format!("## Fixture table\n{}\n", body_text(lines));
    section_table(&synthetic, "Fixture table")
}

/// The audit-area families a permission may write. A mutation in one area may not record an event
/// from an unrelated area: that is how a real but borrowed `AUD-` id is caught (review lesson 3).
fn allowed_audit_areas(permission: &str) -> Option<&'static [&'static str]> {
    let family = permission
        .strip_prefix("PERM-")
        .unwrap_or(permission)
        .split('.')
        .next()
        .unwrap_or_default();
    Some(match family {
        "account" => &["auth"],
        "domain" => &["domain", "dns"],
        "dns" => &["dns"],
        "waf" => &["waf"],
        "ban" => &["ban"],
        "access" => &["access"],
        "apikey" => &["apikey"],
        "org" => &["org"],
        "member" => &["member"],
        "tls" => &["tls"],
        "platform" => &["platform", "ban", "waf", "vkb", "org"],
        "vkb" => &["vkb"],
        "origin" => &["origin", "bypass"],
        "bypass" => &["bypass"],
        "gate" => &["gate"],
        "sentinel" => &["sentinel"],
        "ratelimit" => &["ratelimit"],
        "flow" => &["flow"],
        "integration" => &["webhook", "notify"],
        "notify" => &["notify"],
        "report" => &["report", "export"],
        "audit" => &["export"],
        _ => return None,
    })
}

/// The audit area of an id (`AUD-waf.mode_changed` gives `waf`).
fn audit_area(id: &str) -> Option<&str> {
    let rest = id.strip_prefix("AUD-")?;
    rest.split('.').next()
}

/// Whole T-0025 check on the repository at `root`, reading the checksum-verified master specification.
pub fn check(root: &Path) -> Vec<Finding> {
    match crate::spec::load_master(root) {
        Ok(spec) => check_with_spec(root, &spec),
        Err(e) => vec![super::finding(
            "docs/SPEC.md",
            format!("cannot read the master specification: {}", e.0),
        )],
    }
}

/// T-0025 step 2: every `Safeguards` row of the journeys J-13 to J-24 maps to a reviewed catalog entry.
///
/// The mapping is maintained here, not guessed at run time: a pure verb heuristic produced false
/// positives on both sides (a "confirming" step matched nothing, while "opening an event" matched a
/// ban entry). Each entry is `(journey, risky action, target)`: an empty journey id matches every
/// journey, a concrete id (`J-20`) wins over the general entry, and the action is the normalised
/// `Risky action` cell of a journey safeguard. The target is either a catalog id (the reviewed
/// dangerous action that covers it) or `not-catalogued: <reason>` for a step that carries a safeguard
/// but is not a dangerous action (a read-only or acknowledgement step). A Safeguards row with no entry
/// is a finding, so a new risky step cannot be added without reviewing it against the catalog; a mapped
/// id that the catalog lacks is a finding too, and review F-17 adds the screen rule: the mapped row's
/// `Screen` cells must include the screen of that journey step, which is read from the step table.
const SAFEGUARD_MAP: [(&str, &str, &str); 37] = [
    (
        "",
        "acknowledging an unsupported record type",
        "not-catalogued: records a parity decision; no record or traffic changes",
    ),
    (
        "",
        "confirming parity is clean",
        "not-catalogued: acknowledges the DNS import review; the zone is not changed",
    ),
    ("", "changing a record value", "DA-35"),
    ("", "toggling the proxy state", "DA-32"),
    (
        "",
        "choosing the certificate plan",
        "not-catalogued: plan selection only; issuance is a separate step",
    ),
    (
        "",
        "requesting a certificate",
        "not-catalogued: ACME issuance is retryable and does not lock the operator out",
    ),
    ("", "enabling hsts", "DA-26"),
    ("", "switching the protection mode", "DA-05"),
    ("", "creating a scoped exception", "DA-36"),
    ("", "confirming the switch to block", "DA-05"),
    ("", "enabling the shield preset", "DA-33"),
    (
        "",
        "marking the authentication endpoints",
        "not-catalogued: configuration input for rate limits; no enforcement state changes here",
    ),
    ("", "changing the shield strictness", "DA-33"),
    ("", "enabling ban-on-first-hit", "DA-33"),
    (
        "",
        "opening an event from another tenant",
        "not-catalogued: read-only; tenant isolation is enforced by authorisation",
    ),
    ("", "banning the address", "DA-06"),
    ("", "unbanning an address", "DA-06"),
    ("", "setting the ban action", "DA-09"),
    ("", "saving the rule", "DA-09"),
    ("", "enabling the rule", "DA-09"),
    ("J-20", "enabling the rule", "DA-37"),
    ("", "applying the preset", "DA-37"),
    (
        "",
        "choosing the attack and certificate events",
        "not-catalogued: alert selection only; no enforcement state changes",
    ),
    (
        "",
        "creating a webhook secret",
        "not-catalogued: the secret is shown once and can be rotated; traffic is not affected",
    ),
    (
        "",
        "rotating the signing secret",
        "not-catalogued: the previous secret stays valid for the overlap window",
    ),
    (
        "",
        "setting the quiet hours",
        "not-catalogued: notification timing only",
    ),
    (
        "",
        "passing the proof-of-work check",
        "not-catalogued: a visitor proof step, not an operator action",
    ),
    (
        "",
        "submitting the appeal",
        "not-catalogued: the visitor writes one appeal; the owner reviews it",
    ),
    ("", "allowlisting an address for n days", "DA-07"),
    ("", "declining the appeal", "DA-34"),
    (
        "",
        "copying the firewall allowlist",
        "not-catalogued: a copy action with no change to any configuration",
    ),
    ("", "setting the secret origin header", "DA-11"),
    ("", "applying the snippet at the origin", "DA-11"),
    ("", "marking the lockdown applied", "DA-11"),
    ("", "rotating the secret", "DA-11"),
    (
        "",
        "changes the live setting",
        "not-catalogued: the fixture-tree placeholder step; the delivered journeys name each risky action",
    ),
    (
        "",
        "reviewing the self-lockout warning",
        "not-catalogued: the warning itself changes nothing; the action it precedes is the dangerous one",
    ),
];

/// T-0025 step 2: every journey `Safeguards` row has a reviewed dangerous-action mapping, every
/// mapped catalog id exists and the mapped row is reachable from the screen of that step (the
/// cross-check documented in [`SAFEGUARD_MAP`], review F-17).
pub fn safeguard_crosscheck_findings(catalog: &str, journeys: &[(String, String)]) -> Vec<Finding> {
    let rows = catalog_rows(catalog);
    let Some((header, _)) = section_table(catalog, "Catalog") else {
        return vec![at(
            DANGEROUS_ACTIONS,
            "no `## Catalog` table, so the journey safeguards cannot be cross-checked (T-0025 step 2)",
        )];
    };
    if column(&header, "ID").is_none() {
        return vec![at(
            DANGEROUS_ACTIONS,
            "the catalog has no `ID` column (T-0025 step 2)",
        )];
    }
    let by_id: BTreeMap<&str, &CatalogRow> =
        rows.iter().map(|row| (row.id.as_str(), row)).collect();
    let mut out = Vec::new();
    for (path, text) in journeys {
        let steps = journey_step_screens(text);
        let journey = journey_id(path);
        let Some((header, rows)) = section_table(text, "Safeguards") else {
            out.push(at(
                path,
                "no `## Safeguards` table, so the journey safeguards cannot be cross-checked (T-0025 step 2)",
            ));
            continue;
        };
        let Some(action_column) = column(&header, "Risky action") else {
            out.push(at(
                path,
                "the `## Safeguards` table has no `Risky action` column (T-0025 step 2)",
            ));
            continue;
        };
        let step_column = column(&header, "Step");
        for (line, row) in &rows {
            let Some(cell) = row.get(action_column) else {
                continue;
            };
            let Some(mapped) = mapped_target(journey, cell) else {
                out.push(at(
                    format!("{path}:{line}"),
                    format!(
                        "the safeguard row `{}` has no reviewed dangerous-action mapping in SAFEGUARD_MAP (T-0025 step 2)",
                        cell.trim()
                    ),
                ));
                continue;
            };
            if mapped.starts_with("not-catalogued:") {
                continue;
            }
            let Some(catalog_row) = by_id.get(mapped) else {
                out.push(at(
                    format!("{path}:{line}"),
                    format!(
                        "the safeguard row `{}` is mapped to `{mapped}`, which is not a row of the dangerous-action catalog (T-0025 step 2)",
                        cell.trim()
                    ),
                ));
                continue;
            };
            if steps.is_empty() {
                continue;
            }
            let Some(step) = step_column
                .and_then(|index| row.get(index))
                .and_then(|cell| cell.trim().parse::<usize>().ok())
            else {
                continue;
            };
            let Some(screens) = steps.get(&step) else {
                out.push(at(
                    format!("{path}:{line}"),
                    format!(
                        "the safeguard row names step {step}, which has no row in the journey's Steps table (review F-17)"
                    ),
                ));
                continue;
            };
            if catalog_row.screens.is_empty() {
                out.push(at(
                    format!("{path}:{line}"),
                    format!(
                        "the safeguard row is mapped to `{mapped}`, whose catalog row names no Screen, so the mapping cannot be checked (review F-17)"
                    ),
                ));
                continue;
            }
            if !screens
                .iter()
                .any(|screen| catalog_row.screens.contains(screen))
            {
                out.push(at(
                    format!("{path}:{line}"),
                    format!(
                        "the safeguard row `{}` is mapped to `{mapped}` on {} but step {step} runs on {}; the mapped row must be reachable from the step's screen (review F-17)",
                        cell.trim(),
                        catalog_row.screens.join(", "),
                        screens.join(", ")
                    ),
                ));
            }
        }
    }
    out
}

/// The journey id of a journey path (`docs/UX/journeys/J-16.md` gives `J-16`).
fn journey_id(path: &str) -> &str {
    Path::new(path)
        .file_stem()
        .and_then(|stem| stem.to_str())
        .unwrap_or_default()
}

/// The reviewed dangerous-action target of a journey safeguard row: a journey-specific entry wins over a
/// general entry for the same normalised risky action.
fn mapped_target(journey: &str, action_cell: &str) -> Option<&'static str> {
    let key = normalise_action(action_cell);
    SAFEGUARD_MAP
        .iter()
        .find(|(entry_journey, candidate, _)| {
            *entry_journey == journey && normalise_action(candidate) == key
        })
        .or_else(|| {
            SAFEGUARD_MAP.iter().find(|(entry_journey, candidate, _)| {
                entry_journey.is_empty() && normalise_action(candidate) == key
            })
        })
        .map(|(_, _, mapped)| *mapped)
}

/// Lowercase, trim, drop one trailing full stop and collapse whitespace inside a risky-action cell.
fn normalise_action(cell: &str) -> String {
    cell.trim()
        .trim_end_matches('.')
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
        .to_lowercase()
}

/// Whole T-0025 check on the repository at `root`, with the master specification text.
pub fn check_with_spec(root: &Path, spec: &str) -> Vec<Finding> {
    let mut out = documents_findings(root);
    let audits = b8_ids(spec);
    if audits.is_empty() {
        out.push(at(
            "docs/SPEC.md",
            "the B8 audit event taxonomy has no AUD rows, so catalog audit events cannot be checked (T-0025 step 2)",
        ));
    }
    let permissions = permission_catalog(spec);
    if permissions.is_empty() {
        out.push(at(
            "docs/SPEC.md",
            "the B4.2 permission catalog has no PERM rows, so catalog permissions cannot be checked (T-0025 step 2)",
        ));
    }
    let registry = super::attack_registry(spec);
    if registry.is_empty() {
        out.push(at(
            "docs/SPEC.md",
            "the C5 attack matrix has no ATK rows, so the UI abuse cases cannot be checked (T-0025 A4)",
        ));
    }
    let names = attack_names(spec);
    if names.is_empty() {
        out.push(at(
            "docs/SPEC.md",
            "the C5 attack matrix has no attack names, so the abuse table cannot be compared with it (review F-16)",
        ));
    }
    let claims_cfg = claims::load_config(root).ok();
    if let Ok(text) = read_text(&root.join(DANGEROUS_ACTIONS)) {
        out.extend(catalog_findings(&text));
        out.extend(required_action_findings(&text));
        out.extend(audit_event_findings(&text, &audits));
        out.extend(audit_area_findings(&text));
        out.extend(permission_findings(&text, &permissions));
        out.extend(atk_citations_findings(
            &[(DANGEROUS_ACTIONS, &text)],
            &registry,
        ));
        out.extend(audit_reference_findings(&text));
        out.extend(stepup_findings(&text, spec));
        let ftl = read_text(&root.join(COPY)).unwrap_or_default();
        out.extend(copy_key_findings(&text, &ftl, claims_cfg.as_ref()));
        out.extend(typed_copy_findings(&text, &ftl));
        if let Some(cfg) = claims_cfg.as_ref() {
            out.extend(claims_doc_findings(cfg, DANGEROUS_ACTIONS, &text));
        }
    }
    let mut journeys: Vec<(String, String)> = Vec::new();
    for number in 13..=24 {
        let path = format!("docs/UX/journeys/J-{number:02}.md");
        match read_text(&root.join(&path)) {
            Ok(text) => journeys.push((path, text)),
            Err(_) => out.push(at(
                &path,
                "the journey file does not exist, so its safeguard rows cannot be cross-checked (T-0025 step 2)",
            )),
        }
    }
    let mut typed_journeys = journeys.clone();
    for number in [29, 34] {
        let path = format!("docs/UX/journeys/J-{number:02}.md");
        match read_text(&root.join(&path)) {
            Ok(text) => typed_journeys.push((path, text)),
            Err(_) => out.push(at(
                &path,
                "the journey file does not exist, so its typed-confirmation claim cannot be checked (review F-14)",
            )),
        }
    }
    if let Ok(catalog) = read_text(&root.join(DANGEROUS_ACTIONS)) {
        out.extend(safeguard_crosscheck_findings(&catalog, &journeys));
        out.extend(typed_journey_findings(&typed_journeys, &catalog));
        if let Ok(security) = read_text(&root.join(SECURITY_UX)) {
            out.extend(typed_scope_findings(&security, &catalog));
        }
    }
    if let Ok(text) = read_text(&root.join(SECURITY_UX)) {
        out.extend(abuse_case_findings(&text, &registry, &names));
        out.extend(atk_citations_findings(&[(SECURITY_UX, &text)], &registry));
        out.extend(self_lockout_findings(&text));
        out.extend(preview_pattern_findings(&text));
        out.extend(typed_confirmation_findings(&text));
        out.extend(time_box_findings(&text));
        out.extend(honest_limits_findings(&text, spec));
        if let Some(cfg) = claims_cfg.as_ref() {
            out.extend(claims_doc_findings(cfg, SECURITY_UX, &text));
        }
    }
    if let Ok(text) = read_text(&root.join(STRIDE)) {
        out.extend(stride_findings(&text));
    }
    out
}

/// The two documents and the copy file exist (T-0025 deliverables).
fn documents_findings(root: &Path) -> Vec<Finding> {
    let mut out = Vec::new();
    for path in [DANGEROUS_ACTIONS, SECURITY_UX, COPY] {
        if !root.join(path).is_file() {
            out.push(at(
                path,
                "the document does not exist (T-0025 deliverables)",
            ));
        }
    }
    out
}

/// A1: at least twenty rows, the six required columns, non-empty cells and a named safeguard kind for
/// every row (T-0025 step 2).
fn catalog_findings(text: &str) -> Vec<Finding> {
    let mut out = Vec::new();
    let Some((header, rows)) = section_table(text, "Catalog") else {
        out.push(at(
            DANGEROUS_ACTIONS,
            "no `## Catalog` section with a table (T-0025 A1)",
        ));
        return out;
    };
    let mut usable = true;
    let mut indexes: Vec<(&str, usize)> = Vec::new();
    for name in CATALOG_COLUMNS {
        match column(&header, name) {
            Some(index) => indexes.push((name, index)),
            None => {
                usable = false;
                out.push(at(
                    DANGEROUS_ACTIONS,
                    format!("the catalog table has no `{name}` column (T-0025 step 2)"),
                ));
            }
        }
    }
    if !usable {
        return out;
    }
    if rows.len() < MIN_ACTIONS {
        out.push(at(
            DANGEROUS_ACTIONS,
            format!(
                "the catalog has {} rows; T-0025 A1 requires at least {MIN_ACTIONS} dangerous actions",
                rows.len()
            ),
        ));
    }
    let action_index = column(&header, "Action");
    let safeguard_index = column(&header, "Safeguards");
    for (n, row) in &rows {
        let loc = format!("{DANGEROUS_ACTIONS}:{n}");
        if row.len() != header.len() {
            out.push(at(
                loc.as_str(),
                format!(
                    "the row has {} cells but the header has {} (T-0025 A1)",
                    row.len(),
                    header.len()
                ),
            ));
            continue;
        }
        let action = action_index
            .and_then(|index| row.get(index))
            .cloned()
            .unwrap_or_default();
        for (name, index) in &indexes {
            if row.get(*index).is_none_or(|cell| cell.trim().is_empty()) {
                out.push(at(
                    loc.as_str(),
                    format!("the row \"{action}\" has an empty `{name}` cell (T-0025 A1)"),
                ));
            }
        }
        if let Some(cell) = safeguard_index.and_then(|index| row.get(index))
            && !cell.trim().is_empty()
            && !has_any(cell, &SAFEGUARD_KINDS)
        {
            out.push(at(
                loc.as_str(),
                format!(
                    "the safeguards of \"{action}\" name none of preview, dry-run, typed confirmation, time box or step-up (T-0025 step 2)"
                ),
            ));
        }
    }
    let mut seen: BTreeMap<String, usize> = BTreeMap::new();
    for (n, row) in &rows {
        if let Some(action) = action_index.and_then(|index| row.get(index)) {
            let key = action.trim().to_lowercase();
            if !key.is_empty()
                && let Some(first) = seen.insert(key.clone(), *n)
            {
                out.push(at(
                    format!("{DANGEROUS_ACTIONS}:{n}"),
                    format!("the action \"{action}\" repeats the row at line {first} (T-0025 A1)"),
                ));
            }
        }
    }
    out
}

/// T-0025 step 1: every named dangerous action appears in the action column.
fn required_action_findings(text: &str) -> Vec<Finding> {
    let mut out = Vec::new();
    let Some((header, rows)) = section_table(text, "Catalog") else {
        return out;
    };
    let Some(index) = column(&header, "Action") else {
        return out;
    };
    let actions: Vec<&str> = rows
        .iter()
        .filter_map(|(_, row)| row.get(index).map(String::as_str))
        .collect();
    for (label, groups) in required_actions() {
        let wanted: Vec<&[&str]> = groups.iter().map(|group| group.as_slice()).collect();
        if !actions.iter().any(|cell| has_all(cell, &wanted)) {
            out.push(at(
                DANGEROUS_ACTIONS,
                format!(
                    "the catalog does not name the required action \"{label}\" (T-0025 step 1)"
                ),
            ));
        }
    }
    out
}

/// Every `AUD-` id cited exists in B8 (T-0025 step 2, A5).
fn audit_event_findings(text: &str, known: &BTreeSet<String>) -> Vec<Finding> {
    let mut out = Vec::new();
    let Some((header, rows)) = section_table(text, "Catalog") else {
        return out;
    };
    let action_index = column(&header, "Action");
    if let Some(index) = column(&header, "Audit event") {
        for (n, row) in &rows {
            let action = action_index
                .and_then(|i| row.get(i))
                .cloned()
                .unwrap_or_default();
            let ids = row
                .get(index)
                .map(|cell| audit_tokens(cell))
                .unwrap_or_default();
            if ids.is_empty() {
                out.push(at(
                    format!("{DANGEROUS_ACTIONS}:{n}"),
                    format!("the audit cell of \"{action}\" names no AUD event (T-0025 step 2)"),
                ));
            }
        }
    }
    let mut reported: BTreeSet<String> = BTreeSet::new();
    for id in audit_tokens(text) {
        if known.contains(&id) {
            continue;
        }
        if reported.insert(id.clone()) {
            out.push(at(
                DANGEROUS_ACTIONS,
                format!(
                    "`{id}` is not a B8 audit event of the master specification (T-0025 step 2)"
                ),
            ));
        }
    }
    out
}

/// The audit event of a row belongs to the permission family of that row (T-0025 step 2).
fn audit_area_findings(text: &str) -> Vec<Finding> {
    let mut out = Vec::new();
    let Some((header, rows)) = section_table(text, "Catalog") else {
        return out;
    };
    let (Some(action_index), Some(permission_index), Some(audit_index)) = (
        column(&header, "Action"),
        column(&header, "Permission"),
        column(&header, "Audit event"),
    ) else {
        return out;
    };
    for (n, row) in &rows {
        let action = row
            .get(action_index)
            .map(String::as_str)
            .unwrap_or_default();
        let permissions = row
            .get(permission_index)
            .map(|cell| permission_tokens(cell))
            .unwrap_or_default();
        let audits = row
            .get(audit_index)
            .map(|cell| audit_tokens(cell))
            .unwrap_or_default();
        for id in &audits {
            let Some(area) = audit_area(id) else {
                continue;
            };
            for permission in &permissions {
                let Some(allowed) = allowed_audit_areas(permission) else {
                    continue;
                };
                if !allowed.contains(&area) {
                    out.push(at(
                        format!("{DANGEROUS_ACTIONS}:{n}"),
                        format!(
                            "`{id}` is a `{area}` event but \"{action}\" is a `{permission}` change; the event must belong to the permission family (T-0025 step 2)"
                        ),
                    ));
                }
            }
        }
    }
    out
}

/// Every `PERM-` id cited exists in B4.2 (T-0025 step 2).
fn permission_findings(text: &str, known: &BTreeSet<String>) -> Vec<Finding> {
    let mut out = Vec::new();
    let Some((header, rows)) = section_table(text, "Catalog") else {
        return out;
    };
    let Some(index) = column(&header, "Permission") else {
        out.push(at(
            DANGEROUS_ACTIONS,
            "the catalog table has no `Permission` column (T-0025 step 2)",
        ));
        return out;
    };
    let action_index = column(&header, "Action");
    for (n, row) in &rows {
        let action = action_index
            .and_then(|i| row.get(i))
            .cloned()
            .unwrap_or_default();
        let ids = row
            .get(index)
            .map(|cell| permission_tokens(cell))
            .unwrap_or_default();
        if ids.is_empty() {
            out.push(at(
                format!("{DANGEROUS_ACTIONS}:{n}"),
                format!("the row \"{action}\" names no PERM- permission (T-0025 step 2)"),
            ));
            continue;
        }
        for id in ids {
            if !known.contains(&id) {
                out.push(at(
                    format!("{DANGEROUS_ACTIONS}:{n}"),
                    format!(
                        "`{id}` is not a B4.2 permission of the master specification (T-0025 step 2)"
                    ),
                ));
            }
        }
    }
    out
}

/// A5: every catalog copy key is defined exactly once with a clean, claim-free value, and the copy
/// file has no unused key.
fn copy_key_findings(actions: &str, ftl: &str, cfg: Option<&claims::Config>) -> Vec<Finding> {
    let mut out = Vec::new();
    let Some((header, _rows)) = section_table(actions, "Catalog") else {
        out.push(at(
            DANGEROUS_ACTIONS,
            "no `## Catalog` table, so the copy keys cannot be checked (T-0025 A5)",
        ));
        return out;
    };
    if column(&header, "Copy key").is_none() {
        return out;
    }
    let catalog = catalog_copy_keys(actions);
    if catalog.is_empty() {
        out.push(at(
            DANGEROUS_ACTIONS,
            "the catalog names no copy key (T-0025 A5)",
        ));
    }
    let mut catalog_keys: BTreeSet<String> = BTreeSet::new();
    for (n, key) in &catalog {
        if !key_shape_ok(key) {
            out.push(at(
                format!("{DANGEROUS_ACTIONS}:{n}"),
                format!("the copy key \"{key}\" is not a semantic hyphenated key (B11.12)"),
            ));
        }
        if !catalog_keys.insert(key.clone()) {
            out.push(at(
                format!("{DANGEROUS_ACTIONS}:{n}"),
                format!(
                    "the copy key \"{key}\" is used by more than one catalog row; each confirmation needs its own text (T-0025 A5)"
                ),
            ));
        }
    }
    let messages = parse_ftl(ftl);
    let mut counts: BTreeMap<String, usize> = BTreeMap::new();
    let mut values: BTreeMap<String, Vec<String>> = BTreeMap::new();
    let mut ftl_keys: BTreeSet<String> = BTreeSet::new();
    for message in &messages {
        let loc = format!("{COPY}:{}", message.line);
        if message.key.is_empty() {
            out.push(at(
                loc.as_str(),
                "the line is not a `key = value` message (T-0025 A5)",
            ));
            continue;
        }
        *counts.entry(message.key.clone()).or_insert(0) += 1;
        ftl_keys.insert(message.key.clone());
        if !key_shape_ok(&message.key) {
            out.push(at(
                loc.as_str(),
                format!(
                    "the copy key \"{}\" is not a semantic hyphenated key (B11.12)",
                    message.key
                ),
            ));
        }
        if message.value.is_empty() {
            out.push(at(
                loc.as_str(),
                format!(
                    "the copy key \"{}\" has an empty value (T-0025 A5)",
                    message.key
                ),
            ));
            continue;
        }
        if has_emoji(&message.value) {
            out.push(at(
                loc.as_str(),
                format!(
                    "the value of \"{}\" contains an emoji (T-0025 A5)",
                    message.key
                ),
            ));
        }
        if message.value.contains('<') {
            out.push(at(
                loc.as_str(),
                format!(
                    "the value of \"{}\" contains `<` markup (T-0025 A5)",
                    message.key
                ),
            ));
        }
        if message.value.contains('!')
            && !(message.key.starts_with("success-") || message.key.ends_with("-success"))
        {
            out.push(at(
                loc.as_str(),
                format!(
                    "the exclamation mark in \"{}\" is only allowed in a `success-` key (B11.12)",
                    message.key
                ),
            ));
        }
        values
            .entry(message.value.clone())
            .or_default()
            .push(message.key.clone());
        if let Some(cfg) = cfg {
            for finding in claims::scan_text(cfg, COPY, &format!("{}\n", message.value)) {
                out.push(at(
                    loc.as_str(),
                    format!("the value of \"{}\": {}", message.key, finding.message),
                ));
            }
        }
    }
    for (key, count) in &counts {
        if *count > 1 {
            out.push(at(
                COPY,
                format!(
                    "the key \"{key}\" is defined {count} times; it must appear exactly once (T-0025 A5)"
                ),
            ));
        }
    }
    for (value, keys) in &values {
        if keys.len() > 1 {
            out.push(at(
                COPY,
                format!(
                    "the keys {} share the same value \"{value}\", so a translator cannot tell them apart (T-0025 A5)",
                    keys.join(", ")
                ),
            ));
        }
    }
    for key in &catalog_keys {
        if !counts.contains_key(key) {
            out.push(at(
                COPY,
                format!("the catalog key \"{key}\" is missing from the copy file (T-0025 A5)"),
            ));
        }
    }
    for key in &ftl_keys {
        if !catalog_keys.contains(key) {
            out.push(at(
                COPY,
                format!("the key \"{key}\" is not named by any catalog row (T-0025 A5)"),
            ));
        }
    }
    out
}

/// A4 and review F-16: the abuse-case table cites real C5 ids, copies the C5 attack name of each cited
/// id whole-string, uses ATK-171 for clickjacking and UI redress and ATK-296 for CSRF, keeps the other
/// rows inside ATK-285 to ATK-300, and covers the four required UI abuse categories (T-0025 step 8).
fn abuse_case_findings(
    text: &str,
    registry: &BTreeSet<String>,
    names: &BTreeMap<String, String>,
) -> Vec<Finding> {
    let mut out = Vec::new();
    let Some((header, rows)) = section_table(text, "Abuse cases of this UI") else {
        out.push(at(
            SECURITY_UX,
            "no `## Abuse cases of this UI` section with a table (T-0025 step 8, A4)",
        ));
        return out;
    };
    let (Some(case_index), Some(atk_index), Some(name_index), Some(counter_index)) = (
        column(&header, "Abuse case"),
        column(&header, "ATK"),
        column(&header, "C5 attack"),
        column(&header, "Counter-requirement"),
    ) else {
        out.push(at(
            SECURITY_UX,
            "the abuse-case table needs `Abuse case`, `ATK`, `C5 attack` and `Counter-requirement` columns (T-0025 A4, review F-16)",
        ));
        return out;
    };
    if rows.len() < MIN_ABUSE_CASES {
        out.push(at(
            SECURITY_UX,
            format!(
                "the abuse-case table has {} rows; at least {MIN_ABUSE_CASES} are required (T-0025 A4)",
                rows.len()
            ),
        ));
    }
    let mut cases: Vec<String> = Vec::new();
    let mut in_range = 0usize;
    for (n, row) in &rows {
        let loc = format!("{SECURITY_UX}:{n}");
        let case = row.get(case_index).map(String::as_str).unwrap_or_default();
        let counter = row
            .get(counter_index)
            .map(String::as_str)
            .unwrap_or_default();
        let named = row
            .get(name_index)
            .map(String::as_str)
            .unwrap_or_default()
            .trim()
            .to_owned();
        if case.trim().is_empty() || counter.trim().is_empty() {
            out.push(at(
                loc.clone(),
                "the abuse-case row has an empty case or counter-requirement cell (T-0025 A4)",
            ));
        }
        cases.push(case.to_lowercase());
        let lower = case.to_lowercase();
        let clickjacking = mentions_words(&lower, "clickjacking");
        let redress = mentions_words(&lower, "ui redress");
        let csrf = mentions_words(&lower, "csrf");
        let ids = row
            .get(atk_index)
            .map(|cell| atk_tokens(cell))
            .unwrap_or_default();
        if ids.len() != 1 {
            out.push(at(
                loc.clone(),
                format!(
                    "the abuse case \"{case}\" cites {} ATK ids; cite exactly one so its C5 attack name can be compared (review F-16)",
                    ids.len()
                ),
            ));
        }
        for id in ids {
            if clickjacking && id != "ATK-171" {
                out.push(at(
                    loc.clone(),
                    format!(
                        "the clickjacking row cites `{id}`; the clickjacking class of C5 is ATK-171 (review F-16)"
                    ),
                ));
            }
            if redress {
                if id != "ATK-171" {
                    out.push(at(
                        loc.clone(),
                        format!(
                            "UI redress has no exact C5 class; `{id}` is not the nearest class, ATK-171 is (review F-16)"
                        ),
                    ));
                }
                if !mentions_words(&lower, "no exact c5 class") {
                    out.push(at(
                        loc.clone(),
                        "the UI redress row must say that no exact C5 class exists and that ATK-171 is the nearest (review F-16)",
                    ));
                }
            }
            if csrf && id != "ATK-296" {
                out.push(at(
                    loc.clone(),
                    format!("the CSRF row cites `{id}`; the CSRF class is ATK-296 (review F-16)"),
                ));
            }
            let number = atk_number(&id);
            let in_range_row =
                number.is_some_and(|number| (ABUSE_FIRST..=ABUSE_LAST).contains(&number));
            if in_range_row {
                in_range += 1;
            } else if !clickjacking && !redress {
                out.push(at(
                    loc.clone(),
                    format!(
                        "`{id}` is outside ATK-{ABUSE_FIRST} to ATK-{ABUSE_LAST}; the UI abuse cases must draw from that range (T-0025 A4)"
                    ),
                ));
            }
            if !registry.contains(&id) {
                out.push(at(
                    loc.clone(),
                    format!(
                        "`{id}` is not a C5 attack row of the master specification (T-0025 A4)"
                    ),
                ));
            }
            match names.get(&id) {
                None => out.push(at(
                    loc.clone(),
                    format!(
                        "C5 has no attack name for `{id}`, so the `C5 attack` cell cannot be checked (review F-16)"
                    ),
                )),
                Some(expected) => {
                    if named != expected.trim() {
                        out.push(at(
                            loc.clone(),
                            format!(
                                "the `C5 attack` cell \"{named}\" is not the whole C5 attack name of `{id}` (\"{}\") (review F-16)",
                                expected.trim()
                            ),
                        ));
                    }
                }
            }
        }
    }
    if in_range < MIN_ABUSE_CASES {
        out.push(at(
            SECURITY_UX,
            format!(
                "only {in_range} abuse-case row(s) cite ATK-{ABUSE_FIRST} to ATK-{ABUSE_LAST}; at least {MIN_ABUSE_CASES} are required (T-0025 A4)"
            ),
        ));
    }
    let joined = cases.join(" ");
    for category in ABUSE_CATEGORIES {
        if !mentions_words(&joined, category) {
            out.push(at(
                SECURITY_UX,
                format!("the abuse cases do not cover \"{category}\" (T-0025 step 8, A4)"),
            ));
        }
    }
    out
}

/// Every `ATK-` id cited by the documents exists in C5 (whole-token match).
fn atk_citations_findings(docs: &[(&str, &str)], registry: &BTreeSet<String>) -> Vec<Finding> {
    let mut out = Vec::new();
    let mut reported: BTreeSet<(String, String)> = BTreeSet::new();
    for (path, text) in docs {
        for id in atk_tokens(text) {
            if registry.contains(&id) {
                continue;
            }
            if reported.insert(((*path).to_owned(), id.clone())) {
                out.push(at(
                    *path,
                    format!(
                        "`{id}` is not a C5 attack row of the master specification (T-0025 A4)"
                    ),
                ));
            }
        }
    }
    out
}

/// A2: the self-lockout guard requirements are numbered and name the acting IP, the session, the
/// admin CIDR collision, where the check runs, how it is displayed and the fail-safe behaviour
/// (T-0025 step 3, B11.9 item 3).
fn self_lockout_findings(text: &str) -> Vec<Finding> {
    let mut out = Vec::new();
    let Some(body) = section_body(text, "Self-lockout guard requirements") else {
        out.push(at(
            SECURITY_UX,
            "no `## Self-lockout guard requirements` section (T-0025 step 3, A2)",
        ));
        return out;
    };
    let content = body_text(&body);
    let mut ids: BTreeSet<String> = BTreeSet::new();
    if let Ok(re) = Regex::new(r"\bGL-\d+\b") {
        for found in re.find_iter(&content) {
            ids.insert(found.as_str().to_owned());
        }
    }
    if ids.len() < MIN_GUARD_REQUIREMENTS {
        out.push(at(
            SECURITY_UX,
            format!(
                "the self-lockout section has {} numbered GL- requirements; at least {MIN_GUARD_REQUIREMENTS} are required (T-0025 A2)",
                ids.len()
            ),
        ));
    }
    let wanted: [&[&str]; 17] = [
        &["acting"],
        &["ip"],
        &["session"],
        &["admin"],
        &["cidr"],
        &["server-side"],
        &["client"],
        &["blocking"],
        &["warning"],
        &["exact"],
        &["rule"],
        &["b11.9"],
        &["fail"],
        &["safe"],
        &["step-up"],
        &["detection"],
        &["unavailable"],
    ];
    for group in wanted {
        if !has_any(&content, group) {
            out.push(at(
                SECURITY_UX,
                format!(
                    "the self-lockout requirements do not mention \"{}\" (T-0025 step 3, A2)",
                    group.join(" ")
                ),
            ));
        }
    }
    if !mentions_words(&content, "Run as dry-run first") {
        out.push(at(
            SECURITY_UX,
            "the guard does not link `Run as dry-run first` (B11.9 item 3, T-0025 A2)",
        ));
    }
    out
}

/// T-0025 step 4: the preview patterns cover DNS, rules, access lists and policies, saying what each
/// must show and what it must not hide.
fn preview_pattern_findings(text: &str) -> Vec<Finding> {
    let mut out = Vec::new();
    let Some((header, rows)) = section_table(text, "Preview patterns") else {
        out.push(at(
            SECURITY_UX,
            "no `## Preview patterns` section with a table (T-0025 step 4)",
        ));
        return out;
    };
    let (Some(area_index), Some(show_index), Some(hide_index)) = (
        column(&header, "Area"),
        column(&header, "What the preview must show"),
        column(&header, "What it must not hide"),
    ) else {
        out.push(at(
            SECURITY_UX,
            "the preview table needs `Area`, `What the preview must show` and `What it must not hide` columns (T-0025 step 4)",
        ));
        return out;
    };
    let wanted: [(&str, &[&str]); 4] = [
        ("DNS", &["dns"]),
        ("Rules", &["rule", "rules"]),
        ("Access lists", &["access"]),
        ("Policies", &["policy", "policies"]),
    ];
    for (label, tokens) in wanted {
        let found = rows.iter().any(|(_, row)| {
            row.get(area_index)
                .is_some_and(|cell| has_any(cell, tokens))
        });
        if !found {
            out.push(at(
                SECURITY_UX,
                format!(
                    "the preview patterns do not cover the {} area (T-0025 step 4)",
                    label.to_lowercase()
                ),
            ));
        }
    }
    for (n, row) in &rows {
        for (name, index) in [
            ("Area", area_index),
            ("must show", show_index),
            ("must not hide", hide_index),
        ] {
            if row.get(index).is_none_or(|cell| cell.trim().is_empty()) {
                out.push(at(
                    format!("{SECURITY_UX}:{n}"),
                    format!("the preview row has an empty `{name}` cell (T-0025 step 4)"),
                ));
            }
        }
    }
    out
}

/// T-0025 step 5: the typed-confirmation rules state the exact resource name, case sensitivity,
/// paste allowance and the ban on a checkbox substitute.
fn typed_confirmation_findings(text: &str) -> Vec<Finding> {
    let mut out = Vec::new();
    let Some(body) = section_body(text, "Typed-confirmation rules") else {
        out.push(at(
            SECURITY_UX,
            "no `## Typed-confirmation rules` section (T-0025 step 5)",
        ));
        return out;
    };
    let content = body_text(&body);
    let wanted: [&[&str]; 12] = [
        &["exact"],
        &["resource"],
        &["name"],
        &["case-sensitive"],
        &["paste", "pasting"],
        &["checkbox"],
        &["confirmdialog"],
        &["safe"],
        &["action"],
        &["global"],
        &["changes"],
        &["disabled"],
    ];
    for group in wanted {
        if !has_any(&content, group) {
            out.push(at(
                SECURITY_UX,
                format!(
                    "the typed-confirmation rules do not state \"{}\" (T-0025 step 5)",
                    group.join(" ")
                ),
            ));
        }
    }
    out
}

/// A3: the time-box pattern states the visible countdown, explicit extend and the server-side revert
/// when the browser closes (T-0025 step 6).
fn time_box_findings(text: &str) -> Vec<Finding> {
    let mut out = Vec::new();
    let Some(body) = section_body(text, "Time box and auto-revert") else {
        out.push(at(
            SECURITY_UX,
            "no `## Time box and auto-revert` section (T-0025 step 6, A3)",
        ));
        return out;
    };
    let content = body_text(&body);
    if !(has_token(&content, "browser") && has_token(&content, "closes")) {
        out.push(at(
            SECURITY_UX,
            "the time-box pattern does not say what happens when the browser closes (T-0025 A3)",
        ));
    }
    for token in ["auto-revert", "countdown", "extend", "server-side", "audit"] {
        if !has_token(&content, token) {
            out.push(at(
                SECURITY_UX,
                format!("the time-box pattern does not state \"{token}\" (T-0025 step 6, A3)"),
            ));
        }
    }
    if !content.contains("AUD-") {
        out.push(at(
            SECURITY_UX,
            "the time-box pattern does not name an audit event for extend or revert (T-0025 A3)",
        ));
    }
    if !has_token(&content, "T-0235") {
        out.push(at(
            SECURITY_UX,
            "the time-box pattern does not name the test task T-0235 (T-0025 A3)",
        ));
    }
    out
}

/// T-0025 step 7: the honest limits name the shield, virtual patches, readiness and block-mode
/// collateral and quote the B13 copy exactly.
fn honest_limits_findings(text: &str, spec: &str) -> Vec<Finding> {
    let mut out = Vec::new();
    let Some((header, rows)) = section_table(text, "Honest limits") else {
        out.push(at(
            SECURITY_UX,
            "no `## Honest limits` section with a table (T-0025 step 7)",
        ));
        return out;
    };
    let (Some(placement), Some(screen), Some(key), Some(copy)) = (
        column(&header, "Placement"),
        column(&header, "Screen"),
        column(&header, "Copy key"),
        column(&header, "Exact copy"),
    ) else {
        out.push(at(
            SECURITY_UX,
            "the honest-limits table needs `Placement`, `Screen`, `Copy key` and `Exact copy` columns (T-0025 step 7)",
        ));
        return out;
    };
    let b13 = b13_copy(spec);
    if b13.is_empty() {
        out.push(at(
            "docs/SPEC.md",
            "the B13 copy deck has no key rows, so the honest-limit copy cannot be checked (T-0025 step 7)",
        ));
    }
    let screen_shape = Regex::new(r"\bS-\d{3}\b").ok();
    for (label, groups, expected_key) in honest_limits_required() {
        let wanted: Vec<&[&str]> = groups.iter().map(|group| group.as_slice()).collect();
        let found = rows.iter().find(|(_, row)| {
            row.get(placement)
                .is_some_and(|cell| has_all(cell, &wanted))
        });
        let Some((n, row)) = found else {
            out.push(at(
                SECURITY_UX,
                format!("the honest limits do not place the {label} limit (T-0025 step 7)"),
            ));
            continue;
        };
        let loc = format!("{SECURITY_UX}:{n}");
        let named = row
            .get(key)
            .map(|cell| cell.trim().trim_matches('`').to_owned())
            .unwrap_or_default();
        if named != expected_key {
            out.push(at(
                loc.clone(),
                format!(
                    "the {label} limit names `{named}` but must quote the B13 key `{expected_key}` (T-0025 step 7)"
                ),
            ));
        }
        match b13.get(expected_key) {
            None => out.push(at(
                "docs/SPEC.md",
                format!(
                    "B13 has no row for `{expected_key}`, so the {label} limit cannot be checked (T-0025 step 7)"
                ),
            )),
            Some(expected) => {
                let got = row.get(copy).map(|cell| cell.trim()).unwrap_or_default();
                if got != expected.trim() {
                    out.push(at(
                        loc.clone(),
                        format!(
                            "the {label} exact copy differs from B13 `{expected_key}` (T-0025 step 7)"
                        ),
                    ));
                }
            }
        }
        if screen_shape
            .as_ref()
            .is_some_and(|re| !row.get(screen).is_some_and(|cell| re.is_match(cell)))
        {
            out.push(at(
                loc,
                format!("the {label} limit names no B12.1 screen id (T-0025 step 7)"),
            ));
        }
    }
    out
}

/// The `## T-0025` STRIDE delta exists, addresses the six categories and names the UI-abuse threats
/// with a counter-requirement and an ATK or test id (T-0025 step 8, `[SEC]` definition of done).
fn stride_findings(text: &str) -> Vec<Finding> {
    let mut out = Vec::new();
    let Some(body) = section_starting_with(text, "T-0025") else {
        out.push(at(
            STRIDE,
            "no `## T-0025` STRIDE delta section (T-0025 step 8)",
        ));
        return out;
    };
    let Some((header, rows)) = table_in_lines(&body) else {
        out.push(at(
            STRIDE,
            "the T-0025 delta has no table with a header (T-0025 step 8)",
        ));
        return out;
    };
    let Some(stride_index) = column(&header, "STRIDE") else {
        out.push(at(
            STRIDE,
            "the T-0025 delta table has no `STRIDE` column (T-0025 step 8)",
        ));
        return out;
    };
    let categories: Vec<String> = rows
        .iter()
        .filter_map(|(_, row)| row.get(stride_index).cloned())
        .collect();
    for threat in STRIDE_THREATS {
        if !categories.iter().any(|cell| mentions_words(cell, threat)) {
            out.push(at(
                STRIDE,
                format!("the T-0025 delta does not address the STRIDE category \"{threat}\" (T-0025 step 8)"),
            ));
        }
    }
    let counter = column(&header, "Counter-requirement");
    let maps = column(&header, "ATK or test").or_else(|| column(&header, "Maps to"));
    let (Some(threat_index), Some(counter_index), Some(maps_index)) =
        (column(&header, "Threat"), counter, maps)
    else {
        out.push(at(
            STRIDE,
            "the T-0025 delta table needs `Threat`, `Counter-requirement` and `ATK or test` (or `Maps to`) columns (T-0025 step 8)",
        ));
        return out;
    };
    for (n, row) in &rows {
        let threat = row
            .get(threat_index)
            .map(String::as_str)
            .unwrap_or_default();
        let counter_cell = row
            .get(counter_index)
            .map(String::as_str)
            .unwrap_or_default();
        let maps_cell = row.get(maps_index).map(String::as_str).unwrap_or_default();
        if threat.trim().is_empty() || counter_cell.trim().is_empty() || maps_cell.trim().is_empty()
        {
            out.push(at(
                format!("{STRIDE}:{n}"),
                "the delta row has an empty threat, counter-requirement or mapping cell (T-0025 step 8)",
            ));
        }
        let has_id = !atk_tokens(maps_cell).is_empty()
            || has_token(maps_cell, "T-0327")
            || has_token(maps_cell, "T-0235")
            || has_token(maps_cell, "T-0094");
        if !has_id {
            out.push(at(
                format!("{STRIDE}:{n}"),
                format!("the delta row \"{threat}\" maps to no ATK or test id (T-0025 step 8)"),
            ));
        }
    }
    let content = body_text(&body);
    for category in ABUSE_CATEGORIES {
        if !mentions_words(&content, category) {
            out.push(at(
                STRIDE,
                format!(
                    "the T-0025 delta does not name the UI abuse \"{category}\" (T-0025 step 8)"
                ),
            ));
        }
    }
    for task in ["T-0327", "T-0235", "T-0094"] {
        if !has_token(&content, task) {
            out.push(at(
                STRIDE,
                format!(
                    "the T-0025 delta does not say which part is tested by {task} (T-0025 step 8)"
                ),
            ));
        }
    }
    if !has_token(&content, "design-only") {
        out.push(at(
            STRIDE,
            "the T-0025 delta does not distinguish design-only rows from tested rows (T-0025 step 8)",
        ));
    }
    out
}

/// No forbidden claims phrase appears in a document (R-10, section 4).
fn claims_doc_findings(cfg: &claims::Config, path: &str, text: &str) -> Vec<Finding> {
    claims::scan_text(cfg, path, text)
        .into_iter()
        .map(|finding| {
            at(
                finding.location,
                format!("forbidden claims phrase: {}", finding.message),
            )
        })
        .collect()
}

#[cfg(test)]
pub(crate) mod fixtures {
    //! Fixtures shared by the T-0025 tests and the `ux-docs` fixture tree.
    //!
    //! The Lead appends [`spec_section`] to the fixture specification and writes [`documents`] into the
    //! fixture tree. The section is self-contained: it carries its own B8, B4.2, B13 and C5 headings,
    //! because the parent readers stop at the first section of a file.

    /// The fixture catalog document.
    pub(crate) fn actions_document() -> String {
        String::from(
            r#"# Dangerous actions (fixture)

The fixture catalog for the T-0025 check. Every row names its own risk, safeguard, undo path, audit
event, permission and copy key.

## Catalog

| ID | Action | Screen | Permission | Risk | Safeguards | Undo path | Audit event | Copy key |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| DA-01 | Remove a domain | S-094 | PERM-domain.delete | The domain stops being served and its history is lost. | Preview of the records and the zone export; typed confirmation of the domain name; step-up re-authentication. | Re-add the domain and import the zone export. | AUD-domain.decommissioned | `fx-domain-remove` |
| DA-02 | Delete a DNS record | S-045 | PERM-dns.write | The name stops resolving for web or mail. | Preview of the record before and after; dry-run of the zone. | Undo toast, then a DNS version rollback. | AUD-dns.record_deleted | `fx-dns-delete` |
| DA-03 | Change the nameservers | S-042 | PERM-domain.update | The whole domain, including mail, changes delegation. | Preview of the old and new nameservers; rollback text kept open. | Set the nameservers back at the registrar. | AUD-domain.updated | `fx-ns-change` |
| DA-04 | Publish a rule pack | S-107 | PERM-platform.rules.publish | Every site inspects with the new pack. | Staged rollout preview; dry-run; step-up. | Roll back to the previous pack. | AUD-platform.rule_pack_published | `fx-rule-pack` |
| DA-05 | Switch protection to block mode | S-054, S-055 | PERM-waf.mode.update | Matching visitors are blocked and their address is banned. | Consequences preview; self-lockout preview; time box option. | Switch back to monitor at any time. | AUD-waf.mode_changed | `fx-block-mode` |
| DA-06 | Create a manual ban | S-065, S-067 | PERM-ban.create | An address or a whole network is refused. | Self-lockout preview; dry-run against recent traffic; time box on the TTL. | Unban from the jail list. | AUD-ban.created | `fx-ban-create` |
| DA-07 | Add an access-list deny entry | S-063 | PERM-access.write | A network or country is refused at the edge. | Preview of affected sessions; self-lockout preview; step-up (stronger than B4.2). | Remove the entry from the list. | AUD-access.entry_added | `fx-access-deny` |
| DA-08 | Create a rule with a broad scope | S-059 | PERM-waf.rules.write | A wide path match can refuse legitimate traffic. | Plain-language preview; dry-run replay. | Disable the rule or roll back the revision. | AUD-waf.rule_created | `fx-rule-broad` |
| DA-09 | Apply origin lockdown | S-098 | PERM-origin.lockdown | Requests that skip HDD are refused at the origin. | Preview of the allowlist; verification probes. | Restore the previous firewall state. | AUD-origin.lockdown_applied | `fx-origin-lockdown` |
| DA-10 | Enable safe mode | S-093 | PERM-waf.safe_mode | Inspection, jails and limits stop for the time box. | Step-up and a reason; time box; visible banner. | End it early or wait for the auto-revert. | AUD-waf.safe_mode_on | `fx-safe-mode` |
| DA-11 | Create an API key | S-080 | PERM-apikey.create | The key acts with the chosen scopes and is shown once. | Preview of the scopes; step-up. | Revoke the key. | AUD-apikey.created | `fx-api-key-create` |
| DA-12 | Remove an MFA second factor | S-088 | PERM-account.self | The account can be entered with one factor. | Step-up (stronger than B4.2); recovery-code check. | Enrol a new factor before the session ends. | AUD-auth.mfa_removed | `fx-mfa-remove` |
| DA-13 | Delete the organisation | S-086 | PERM-org.delete | Domains, members, keys and events are deleted. | Preview of the owned resources; typed confirmation of the organisation slug; step-up. | Re-create the organisation and import the export. | AUD-org.deleted | `fx-org-delete` |
| DA-14 | Change a global platform setting | S-119 | PERM-platform.settings.write | Every tenant and every email uses the new setting. | Preview of affected tenants; typed confirmation of the setting name; step-up. | Restore the previous value from the audit diff. | AUD-platform.settings_changed | `fx-global-setting` |
| DA-15 | Apply a geo-block | S-063 | PERM-access.write | Every visitor from a country or network is refused. | Preview of the visitor count; self-lockout preview. | Remove the geo entry. | AUD-access.entry_added | `fx-geo-block` |
| DA-16 | Push a virtual patch | S-126 | PERM-vkb.emergency | A wrong signature can refuse benign traffic. | Two-person approval; preview of the evidence; time box on the expiry; step-up. | Roll back the rule. | AUD-vkb.emergency_push | `fx-virtual-patch` |
| DA-17 | Start an impersonation session | S-118 | PERM-platform.impersonate | Support reads tenant data as the tenant sees it. | Reason and duration preview; read-only banner; step-up. | End the session at any time. | AUD-platform.impersonation_started | `fx-impersonation` |
| DA-18 | Remove a member | S-081 | PERM-member.remove | The member loses access to every domain. | Preview of the permissions lost; confirmation. | Invite the member again. | AUD-member.removed | `fx-member-remove` |
| DA-19 | Change the never-ban list | S-109 | PERM-platform.jail.write | A listed network can never be banned. | Preview of collisions; step-up. | Remove the entry; the audit keeps the change. | AUD-platform.never_ban_changed | `fx-never-ban` |
| DA-20 | Create a global ban | S-106 | PERM-platform.jail.write | An address is refused by every tenant. | Preview of affected sites; time box on the TTL; step-up. | Release the global ban. | AUD-ban.global_created | `fx-global-ban` |

## Audit-event notes

B8 groups some events in one row. The catalog names the branch that records the action and does not
invent a second id.
"#,
        )
    }

    /// The fixture security-UX document.
    pub(crate) fn security_document() -> String {
        String::from(
            r#"# Security UX (fixture)

The fixture guard and pattern rules for the T-0025 check.

## Self-lockout guard requirements

1. GL-1 The guard detects the acting IP from the same client address the data plane uses.
2. GL-2 It resolves the session identity: user, org, role and auth level.
3. GL-3 It compares the change with the admin CIDR list and the never-ban list.
4. GL-4 It evaluates the proposed change, not the form.
5. GL-5 It runs server-side in the mutation path; a client warning is only an enhancement.
6. GL-6 The response is a blocking warning that names the exact rule and its scope.
7. GL-7 The warning links `Run as dry-run first` (B11.9 item 3).
8. GL-8 Acknowledged self-affecting changes are audited.
9. GL-9 The check is fail safe when detection is unavailable: block the action or require step-up.
10. GL-10 It never removes the break-glass path.
11. GL-11 It applies to the API and the UI with the same decision (R-27).
12. GL-12 Tests cover IPv6 /64 equivalence and header spoofing (T-0327).

## Preview patterns

| Area | What the preview must show | What it must not hide |
| --- | --- | --- |
| DNS | Every record added, changed or removed with its old and new value. | Mail records that keep working, and the nameserver values. |
| Rules | The plain-language match sentence and the dry-run count. | The estimated false positives and the rule expiry. |
| Access lists | The exact value, its kind, the action and the expiry. | Overlapping entries and the recent sessions affected. |
| Policies | The before and after values and the affected categories. | The review window and the shared-address collateral. |

The API returns the same preview object as the UI (R-27), and a stale preview is refused.

## Typed-confirmation rules

The B11.8 ConfirmDialog lists the consequences and focuses the safe action by default (R-28).

- TC-1 The user types the exact resource name.
- TC-2 The comparison is case-sensitive.
- TC-3 Paste is allowed in the field.
- TC-4 A checkbox or a second click cannot substitute for typing.
- TC-5 The confirm control stays disabled until the value matches.
- TC-6 No prefill: the field starts empty.
- TC-7 Scope. Typed confirmation is required for the domain removal (DA-01), the organisation
  deletion (DA-13) and the global changes (DA-14); the fixture declares no extension.

Domain removal, organisation deletion and global changes use this rule (B11.9 item 2).

## Time box and auto-revert

- TB-1 Every time-boxed control shows a visible countdown.
- TB-2 The timer is a server-side timer, so a change reverts even if the browser closes.
- TB-3 Extend is an explicit action and it is audited.
- TB-4 The revert writes an audit event: AUD-waf.safe_mode_off, AUD-waf.under_attack_off and AUD-domain.resumed.
- TB-5 The auto-revert behaviour is tested with the test clock (T-0235).

## Honest limits

| Placement | Screen | Copy key | Exact copy |
| --- | --- | --- | --- |
| Shield | S-057 | `shield-limit` | Signature-based detection can miss new techniques. Keep your software updated. |
| Virtual patches | S-126 | `virtual-patch-banner` | A virtual patch is not a fix. The vulnerability remains open until the component is updated. |
| Readiness | S-044 | `readiness-footnote` | Measures configuration completeness, not security. |
| Block-mode collateral | S-055 | `block-confirm-body` | HDD will block matching requests and ban the sending IP address. Visitors sharing an address with an attacker can be affected. You can switch back at any time. |

The limit line stays visible where the action is taken.

## Abuse cases of this UI

| Abuse case | ATK | C5 attack | Counter-requirement | Test |
| --- | --- | --- | --- | --- |
| Clickjacking of a destructive control | ATK-171 | Clickjacking | Framing headers and a native dialog guard the confirm step. | design-only until T-0094 |
| CSRF on a confirmation request | ATK-296 | Session theft, fixation, CSRF on dashboard | A CSRF token and an origin check guard every mutation. | T-0327 |
| UI redress around the safe default (no exact C5 class; ATK-171 is the nearest) | ATK-171 | Clickjacking | The safe action is the default and the consequences are plain text. | design-only until T-0094 |
| Confused deputy in impersonation | ATK-298 | Impersonation misuse | Impersonation is read-only and writes return an error. | T-0327 |
| Stored XSS in the preview | ATK-297 | Stored XSS in dashboard via attacker-controlled event payloads | Evidence is escaped and the page loads no third-party script. | T-0094 |
| Privilege escalation through a hidden action | ATK-294 | Privilege escalation (role/scopes) | The permission is enforced on the server for every route. | T-0327 |
| Cross-tenant confirmation replay | ATK-293 | Cross-tenant data access (BOLA) | The confirmation binds the organisation and the resource id. | T-0327 |
| Ban poisoning through victim browsers | ATK-291 | Ban poisoning through victim browsers | A victim browser cannot trigger a ban of its own network. | T-0327 |
| Formula or markup injection in an export | ATK-300 | Formula or markup injection in exports and reports | Export cells are escaped for CSV and for HTML. | T-0094 |
| Admin panel access from an untrusted network | ATK-295 | Admin panel access from untrusted networks | CIDR, MFA and step-up guard the platform routes. | T-0327 |
| Tenant rules that DoS the engine (DA-08) | ATK-292 | Tenant rules that DoS the engine or evade others | Regex limits and per-site isolation bound the rule engine. | T-0327 |

## R-19 and R-28

R-19 is met by GL-1 to GL-12 and by every catalog row. R-28 is met by TC-1 to TC-5 and by the safe
default.
"#,
        )
    }

    /// The fixture confirmation copy, one key per catalog row.
    pub(crate) fn copy_document() -> String {
        String::from(
            r#"# T-0025 fixture copy. Keys are lowercase semantic words joined by hyphens.
fx-domain-remove = Type { $domain } to remove it. The zone export stays available after the removal.
fx-dns-delete = Delete this record? The DNS history keeps a rollback.
fx-ns-change = Check the old and new nameservers before the change.
fx-rule-pack = Publish the pack after the staged rollout preview.
fx-block-mode = Block matching requests and ban the sending address.
fx-ban-create = Ban this address for the time box you choose.
fx-access-deny = Deny this network and keep the entry for review.
fx-rule-broad = Save this rule after the dry-run shows the matches.
fx-origin-lockdown = Apply the lockdown and keep the revert text open.
fx-safe-mode = Safe mode stops inspection and jails until the time box ends.
fx-api-key-create = Create the key and copy the secret now.
fx-mfa-remove = Remove the second factor and keep the recovery codes.
fx-org-delete = Type { $org } to delete the organisation. The export stays downloadable.
fx-global-setting = Type { $setting } to change it for every tenant. The preview names them.
fx-geo-block = Refuse visitors from this country until the entry is removed.
fx-virtual-patch = Push this emergency rule for the stated window.
fx-impersonation = View this organisation as read-only support.
fx-member-remove = Remove the member and name the permissions they lose.
fx-never-ban = Add this network to the never-ban list.
fx-global-ban = Ban this address on every site until it is released.
"#,
        )
    }

    /// The fixture STRIDE delta.
    pub(crate) fn stride_document() -> String {
        String::from(
            r#"# STRIDE

Fixture deltas for the T-0025 check.

## T-0025: security UX dangerous actions

The guard rows are tests in T-0327 and T-0235; the framing and redress rows are design-only until
T-0094.

| STRIDE | Threat | Counter-requirement | Maps to |
| --- | --- | --- | --- |
| Spoofing | A hostile page frames the confirmation (clickjacking). | Framing headers and a native modal. | ATK-171, T-0094 |
| Tampering | A CSRF request changes a rule the user did not preview. | A CSRF token, an origin check and a preview nonce. | ATK-296, T-0327 |
| Repudiation | An extend or a revert leaves no trace. | Every change writes an audit event. | T-0327 |
| Information disclosure | A stored XSS payload in the preview reads the session. | Escaping and a strict content policy. | ATK-297, T-0094 |
| Denial of service | A broad ban or geo-block denies the admin surface. | The self-lockout guard blocks the change. | ATK-291, T-0327 |
| Elevation of privilege | A confused deputy in an impersonation session writes. | Writes return an error in impersonation. | ATK-298, T-0327 |
| UI redress | A misleading overlay makes the destructive control look safe. | The safe action is the default and text is not an image. | ATK-171, T-0094 |
"#,
        )
    }

    /// The fixture documents keyed by their repository path (the Lead writes them into the fixture tree).
    pub(crate) fn documents() -> Vec<(String, String)> {
        vec![
            (super::DANGEROUS_ACTIONS.to_owned(), actions_document()),
            (super::SECURITY_UX.to_owned(), security_document()),
            (super::COPY.to_owned(), copy_document()),
            (super::STRIDE.to_owned(), stride_document()),
        ]
    }

    /// Specification rows the T-0025 fixture needs that the fixture specification does not already
    /// have: the B8 audit rows, the B4.2 permissions, the B13 honest-limit strings and the C5 attack
    /// rows. The Lead appends this string at the end of the fixture specification, before the checksum
    /// is written (the section headings are part of the string on purpose).
    pub(crate) fn spec_section() -> String {
        String::from(
            r#"### B8. Audit event taxonomy (T-0025 fixture rows)

| Event | Trigger | Detail fields |
| --- | --- | --- |
| AUD-domain.created / updated / decommissioned | Domain lifecycle | hostname, mode |
| AUD-domain.paused / resumed | Domain pause | mode |
| AUD-dns.record_created / deleted / imported | DNS changes | record id, before/after hash |
| AUD-waf.mode_changed | WAF mode | from, to |
| AUD-waf.rule_created | Custom rules | rule id, priority |
| AUD-waf.safe_mode_on / off | Safe mode | duration, by |
| AUD-waf.under_attack_on / off | Under attack | trigger |
| AUD-waf.auto_rolled_back | Config revisions | revision, reason |
| AUD-ban.created / released | Ban | ip_key, reason, ttl_step |
| AUD-ban.global_created / released | Platform-wide ban | reason |
| AUD-access.entry_added / removed | Access lists | kind, action |
| AUD-origin.lockdown_applied | Origin | pins, mode |
| AUD-bypass.state_changed | Lockdown state transition | site, from, to |
| AUD-apikey.created / revoked | API keys | prefix, scopes |
| AUD-auth.mfa_enrolled / removed | TOTP lifecycle | factor |
| AUD-org.created / deleted / transferred | Org lifecycle | fields changed |
| AUD-member.invited / removed | Membership | email_hmac, role |
| AUD-tls.cert_issued / deleted | Certificates | names, serial |
| AUD-platform.settings_changed | SMTP/branding/legal | keys changed |
| AUD-platform.rule_pack_published / rolled_back | Rule packs | pack, version |
| AUD-platform.impersonation_started / ended | Impersonation | org, reason |
| AUD-platform.never_ban_changed | Never-ban list | cidr |
| AUD-vkb.emergency_push | Emergency rule pushed | rule id, approvers |

### B4.2 Permission catalog (T-0025 fixture rows)

| Permission ID | Description | Ow | Ad |
| --- | --- | --- | --- |
| PERM-domain.delete | Remove domain | S | S |
| PERM-dns.write | Create/edit/delete records | Y | Y |
| PERM-domain.update | Edit domain settings | Y | Y |
| PERM-domain.pause | Pause/resume protection | Y | Y |
| PERM-waf.mode.update | Change WAF mode | Y | Y |
| PERM-waf.policy.update | Change categories/thresholds/shield | Y | Y |
| PERM-waf.rules.write | Create/edit/delete rules | Y | Y |
| PERM-waf.safe_mode | Toggle domain safe mode | Y | S |
| PERM-ban.create | Create manual ban | Y | Y |
| PERM-access.write | Edit access lists | Y | Y |
| PERM-origin.lockdown | Manage lockdown wizard/secret header | Y | Y |
| PERM-apikey.create | Create API keys | Y | S |
| PERM-apikey.revoke | Revoke API keys | Y | Y |
| PERM-account.self | Manage own profile, MFA, sessions | Y | Y |
| PERM-org.delete | Delete org | S | - |
| PERM-org.transfer | Transfer ownership | S | - |
| PERM-member.remove | Remove members | Y | Y |
| PERM-member.role.update | Change roles | Y | S |
| PERM-tls.write | Change TLS mode/HSTS | Y | Y |
| PERM-tls.cert.write | Upload/delete custom cert | Y | S |
| PERM-platform.settings.write | SMTP, branding, signup policy, legal | S | - |
| PERM-platform.jail.write | Global ban/unban, never-ban list | S | S |
| PERM-platform.rules.publish | Publish/rollback rule packs | S | S |
| PERM-platform.impersonate | Read-only view-as | S | S |
| PERM-vkb.emergency | Approve an emergency rule push | - | S |

## B13. Copy deck (T-0025 fixture rows)

| Key stem | Text |
| --- | --- |
| `shield-limit` | Signature-based detection can miss new techniques. Keep your software updated. |
| `virtual-patch-banner` | A virtual patch is not a fix. The vulnerability remains open until the component is updated. |
| `readiness-footnote` | Measures configuration completeness, not security. |
| `block-confirm-body` | HDD will block matching requests and ban the sending IP address. Visitors sharing an address with an attacker can be affected. You can switch back at any time. |

## C5. Attack coverage matrix (T-0025 fixture rows)

| ID | Attack | Surface | Detection | Act | PL | Ref |
| --- | --- | --- | --- | --- | --- | --- |
| ATK-171 | Clickjacking | response | framing headers | P | 1 | CWE-1021 |
| ATK-172 | CSRF | state-changing requests | origin enforcement | B | 2 | CWE-352 |
| ATK-285 | Brute force and stuffing against HDD login | HDD app | rate limits, lockout | Q + ban | 1 | CWE-307 |
| ATK-286 | Mass signup and verification-email bombing | HDD app | per-IP limits, PoW | Q/C | 1 | CWE-799 |
| ATK-287 | Password-reset abuse and enumeration | HDD app | limits, uniform responses | Q | 1 | CWE-204 |
| ATK-288 | Webhook SSRF through tenant URLs | HDD worker | SSRF guard | R | 1 | CWE-918 |
| ATK-289 | Origin SSRF through tenant origins | HDD proxy | SSRF guard at connect time | R | 1 | CWE-918 |
| ATK-290 | Domain-claim hijacking and dangling records | HDD app | ownership proof | B | 1 | CWE-346 |
| ATK-291 | Ban poisoning through victim browsers | HDD data plane | cross-site context rule | B (no ban) | 1 | CWE-346 |
| ATK-292 | Tenant rules that DoS the engine or evade others | HDD rules | regex limits, isolation | R | 1 | CWE-1333 |
| ATK-293 | Cross-tenant data access (BOLA) | HDD API | RLS and permission checks | R | 1 | API1 A01 |
| ATK-294 | Privilege escalation (role/scopes) | HDD API | permission matrix tests | R | 1 | CWE-269 |
| ATK-295 | Admin panel access from untrusted networks | admin | CIDR, MFA, step-up | R | 1 | CWE-284 |
| ATK-296 | Session theft, fixation, CSRF on dashboard | HDD app | cookie flags, rotation, CSRF tokens | R | 1 | CWE-352 |
| ATK-297 | Stored XSS in dashboard via attacker-controlled event payloads | HDD app | output escaping, CSP | R | 1 | CWE-79 |
| ATK-298 | Impersonation misuse | HDD admin | read-only enforcement, audit | R | 1 | CWE-269 |
| ATK-299 | Compromised dependency or update | HDD supply chain | deny, audit, vet, signatures | P | 1 | CWE-1357 |
| ATK-300 | Formula or markup injection in exports and reports | HDD exports | CSV and HTML escaping | R | 1 | CWE-1236 |
"#,
        )
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used, clippy::unwrap_used, reason = "tests")]

    use super::fixtures::{
        actions_document, copy_document, security_document, spec_section, stride_document,
    };
    use super::*;

    /// The findings joined for assertion messages.
    fn joined(findings: &[Finding]) -> String {
        findings
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>()
            .join("\n")
    }

    /// The fixture specification (self-contained: B8, B4.2, B13 and C5 rows).
    fn fixture_spec() -> String {
        spec_section()
    }

    /// The fixture audit ids.
    fn audits() -> BTreeSet<String> {
        b8_ids(&fixture_spec())
    }

    /// The fixture permissions.
    fn permissions() -> BTreeSet<String> {
        permission_catalog(&fixture_spec())
    }

    /// The fixture attack registry.
    fn registry() -> BTreeSet<String> {
        super::super::attack_registry(&fixture_spec())
    }

    /// The fixture C5 attack names.
    fn names() -> BTreeMap<String, String> {
        attack_names(&fixture_spec())
    }

    /// A small claims configuration for the copy and document rules.
    fn claims_cfg() -> claims::Config {
        toml::from_str(
            "phrases = [{ text = \"absolute protection\" }]\n\
             include = [\"docs/UX/**\", \"i18n/en/**\"]\n\
             exclude = []\n\
             extensions = [\"md\", \"ftl\"]\n",
        )
        .expect("fixture claims configuration")
    }

    #[test]
    fn t25_a_complete_fixture_passes_every_rule() {
        let spec = fixture_spec();
        let actions = actions_document();
        let security = security_document();
        let copy = copy_document();
        let stride = stride_document();
        let all = [
            ("catalog", catalog_findings(&actions)),
            ("required actions", required_action_findings(&actions)),
            ("audit events", audit_event_findings(&actions, &audits())),
            ("audit areas", audit_area_findings(&actions)),
            ("permissions", permission_findings(&actions, &permissions())),
            (
                "copy keys",
                copy_key_findings(&actions, &copy, Some(&claims_cfg())),
            ),
            (
                "abuse cases",
                abuse_case_findings(&security, &registry(), &names()),
            ),
            (
                "ATK citations",
                atk_citations_findings(
                    &[
                        (DANGEROUS_ACTIONS, actions.as_str()),
                        (SECURITY_UX, security.as_str()),
                        (STRIDE, stride.as_str()),
                    ],
                    &registry(),
                ),
            ),
            ("self-lockout", self_lockout_findings(&security)),
            ("previews", preview_pattern_findings(&security)),
            ("typed confirmation", typed_confirmation_findings(&security)),
            ("typed copy", typed_copy_findings(&actions, &copy)),
            ("typed scope", typed_scope_findings(&security, &actions)),
            ("step-up", stepup_findings(&actions, &spec)),
            ("audit references", audit_reference_findings(&actions)),
            ("time box", time_box_findings(&security)),
            ("honest limits", honest_limits_findings(&security, &spec)),
            ("STRIDE", stride_findings(&stride)),
            (
                "document claims",
                claims_doc_findings(&claims_cfg(), DANGEROUS_ACTIONS, &actions),
            ),
        ];
        for (rule, findings) in all {
            assert!(findings.is_empty(), "{rule}:\n{}", joined(&findings));
        }
    }

    #[test]
    fn t25_missing_documents_are_findings() {
        let findings = documents_findings(Path::new("hdd-no-such-root-for-t25"));
        assert_eq!(findings.len(), 3, "{}", joined(&findings));
    }

    #[test]
    fn t25_documents_rule_accepts_existing_files() {
        let dir = std::env::temp_dir().join(format!("hdd-t0025-docs-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        for path in [DANGEROUS_ACTIONS, SECURITY_UX, COPY] {
            let full = dir.join(path);
            std::fs::create_dir_all(full.parent().expect("parent")).expect("mkdir");
            std::fs::write(&full, "x").expect("write");
        }
        let findings = documents_findings(&dir);
        assert!(findings.is_empty(), "{}", joined(&findings));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn t25_fixture_documents_cover_the_required_paths() {
        let docs = super::fixtures::documents();
        assert_eq!(
            docs.len(),
            4,
            "the fixture tree needs two documents, the copy and STRIDE"
        );
        let paths: Vec<&str> = docs.iter().map(|(path, _)| path.as_str()).collect();
        for wanted in [DANGEROUS_ACTIONS, SECURITY_UX, COPY, STRIDE] {
            assert!(paths.contains(&wanted), "{wanted} is missing");
        }
        for (path, text) in &docs {
            assert!(!text.is_empty(), "{path} is empty");
        }
    }

    #[test]
    fn t25_catalog_needs_twenty_rows_and_full_cells() {
        let text = actions_document();
        assert!(catalog_findings(&text).is_empty());
        let short = text
            .lines()
            .filter(|line| !line.starts_with("| DA-20 |"))
            .collect::<Vec<_>>()
            .join("\n");
        let message = joined(&catalog_findings(&short));
        assert!(message.contains("20"), "{message}");
        let empty_risk = text.replace("| An address is refused by every tenant. |", "|  |");
        let message = joined(&catalog_findings(&empty_risk));
        assert!(
            message.contains("Risk") || message.contains("risk"),
            "{message}"
        );
    }

    #[test]
    fn t25_every_safeguard_names_a_kind() {
        let text = actions_document().replace(
            "Self-lockout preview; dry-run against recent traffic; time box on the TTL.",
            "A clear warning about the change.",
        );
        let message = joined(&catalog_findings(&text));
        assert!(message.contains("safeguard"), "{message}");
    }

    #[test]
    fn t25_required_actions_are_named() {
        let mut text = actions_document();
        assert!(
            required_action_findings(&text).is_empty(),
            "{}",
            joined(&required_action_findings(&text))
        );
        text = text.replace("| Apply a geo-block |", "| Apply a country rule |");
        let message = joined(&required_action_findings(&text));
        assert!(message.contains("geo-block"), "{message}");
        let without_mfa = actions_document()
            .lines()
            .filter(|line| !line.starts_with("| DA-12 |"))
            .collect::<Vec<_>>()
            .join("\n");
        let message = joined(&required_action_findings(&without_mfa));
        assert!(message.contains("MFA"), "{message}");
        let without_key_creation = actions_document()
            .lines()
            .filter(|line| !line.starts_with("| DA-11 |"))
            .collect::<Vec<_>>()
            .join("\n");
        let message = joined(&required_action_findings(&without_key_creation));
        assert!(message.contains("API key creation"), "{message}");
    }

    #[test]
    fn t25_audit_events_must_exist_in_b8_as_whole_tokens() {
        let text = actions_document();
        assert!(audit_event_findings(&text, &audits()).is_empty());
        let bad = text.replace("AUD-ban.created", "AUD-ban.createdx");
        let message = joined(&audit_event_findings(&bad, &audits()));
        assert!(message.contains("AUD-ban.createdx"), "{message}");
        let unknown = text.replace("AUD-ban.created", "AUD-organisation.deleted");
        let message = joined(&audit_event_findings(&unknown, &audits()));
        assert!(message.contains("AUD-organisation.deleted"), "{message}");
    }

    #[test]
    fn t25_a_real_audit_id_in_the_wrong_row_is_caught() {
        let text = actions_document();
        assert!(audit_area_findings(&text).is_empty());
        let wrong = text.replace(
            "| The name stops resolving for web or mail. | Preview of the record before and after; dry-run of the zone. | Undo toast, then a DNS version rollback. | AUD-dns.record_deleted |",
            "| The name stops resolving for web or mail. | Preview of the record before and after; dry-run of the zone. | Undo toast, then a DNS version rollback. | AUD-ban.created |",
        );
        let message = joined(&audit_area_findings(&wrong));
        assert!(message.contains("AUD-ban.created"), "{message}");
        let cross_area = text.replace("AUD-origin.lockdown_applied", "AUD-bypass.state_changed");
        assert!(audit_area_findings(&cross_area).is_empty());
    }

    #[test]
    fn t25_permissions_must_exist_in_b4_2() {
        let text = actions_document();
        assert!(permission_findings(&text, &permissions()).is_empty());
        let bad = text.replace("PERM-dns.write", "PERM-dns.writes");
        let message = joined(&permission_findings(&bad, &permissions()));
        assert!(message.contains("PERM-dns.writes"), "{message}");
    }

    #[test]
    fn t25_copy_keys_must_match_the_copy_file() {
        let actions = actions_document();
        let copy = copy_document();
        assert!(copy_key_findings(&actions, &copy, None).is_empty());
        let missing = copy.replace(
            "fx-ban-create = Ban this address for the time box you choose.\n",
            "",
        );
        let message = joined(&copy_key_findings(&actions, &missing, None));
        assert!(message.contains("fx-ban-create"), "{message}");
        let unused = format!("{copy}fx-unused = An unused value.\n");
        let message = joined(&copy_key_findings(&actions, &unused, None));
        assert!(message.contains("fx-unused"), "{message}");
        let twice = format!("{copy}fx-ban-create = A second definition of the same key.\n");
        let message = joined(&copy_key_findings(&actions, &twice, None));
        assert!(
            message.contains("more than once") || message.contains("once"),
            "{message}"
        );
    }

    #[test]
    fn t25_copy_values_are_clean_and_claim_free() {
        let actions = actions_document();
        let copy = copy_document();
        let markup = copy.replace(
            "fx-dns-delete = Delete this record? The DNS history keeps a rollback.",
            "fx-dns-delete = Delete <b>this</b> record?",
        );
        let message = joined(&copy_key_findings(&actions, &markup, None));
        assert!(
            message.contains('<') || message.contains("markup"),
            "{message}"
        );
        let duplicate = copy.replace(
            "fx-geo-block = Refuse visitors from this country until the entry is removed.",
            "fx-geo-block = Delete this record? The DNS history keeps a rollback.",
        );
        let message = joined(&copy_key_findings(&actions, &duplicate, None));
        assert!(
            message.contains("same value") || message.contains("duplicate"),
            "{message}"
        );
        let claim = copy.replace(
            "fx-never-ban = Add this network to the never-ban list.",
            "fx-never-ban = A rule with absolute protection.",
        );
        let message = joined(&copy_key_findings(&actions, &claim, Some(&claims_cfg())));
        assert!(message.contains("absolute protection"), "{message}");
    }

    #[test]
    fn t25_abuse_cases_stay_inside_the_hdd_attack_range() {
        let text = security_document();
        assert!(
            abuse_case_findings(&text, &registry(), &names()).is_empty(),
            "{}",
            joined(&abuse_case_findings(&text, &registry(), &names()))
        );
        let outside = text.replace(
            "| CSRF on a confirmation request | ATK-296 |",
            "| CSRF on a confirmation request | ATK-171 |",
        );
        let message = joined(&abuse_case_findings(&outside, &registry(), &names()));
        assert!(message.contains("285"), "{message}");
        let unknown = text.replace(
            "| CSRF on a confirmation request | ATK-296 |",
            "| CSRF on a confirmation request | ATK-999 |",
        );
        let message = joined(&abuse_case_findings(&unknown, &registry(), &names()));
        assert!(message.contains("ATK-999"), "{message}");
    }

    #[test]
    fn t25_abuse_cases_name_the_c5_class_and_use_the_right_generic_id() {
        let text = security_document();
        let wrong_name = text.replace(
            "| Clickjacking of a destructive control | ATK-171 | Clickjacking |",
            "| Clickjacking of a destructive control | ATK-171 | UI redress |",
        );
        let message = joined(&abuse_case_findings(&wrong_name, &registry(), &names()));
        assert!(message.contains("whole C5 attack name"), "{message}");
        let clickjacking_wrong = text.replace(
            "| Clickjacking of a destructive control | ATK-171 | Clickjacking |",
            "| Clickjacking of a destructive control | ATK-296 | Session theft, fixation, CSRF on dashboard |",
        );
        let message = joined(&abuse_case_findings(
            &clickjacking_wrong,
            &registry(),
            &names(),
        ));
        assert!(message.contains("ATK-171"), "{message}");
        let redress_wrong = text.replace(
            "| UI redress around the safe default (no exact C5 class; ATK-171 is the nearest) | ATK-171 | Clickjacking |",
            "| UI redress around the safe default | ATK-291 | Ban poisoning through victim browsers |",
        );
        let message = joined(&abuse_case_findings(&redress_wrong, &registry(), &names()));
        assert!(
            message.contains("no exact C5 class") || message.contains("nearest"),
            "{message}"
        );
        let csrf_wrong = text.replace(
            "| CSRF on a confirmation request | ATK-296 | Session theft, fixation, CSRF on dashboard |",
            "| CSRF on a confirmation request | ATK-171 | Clickjacking |",
        );
        let message = joined(&abuse_case_findings(&csrf_wrong, &registry(), &names()));
        assert!(message.contains("CSRF"), "{message}");
    }

    #[test]
    fn t25_typed_rows_have_type_copy_and_are_listed_in_tc7() {
        let actions = actions_document();
        let security = security_document();
        let copy = copy_document();
        assert!(
            typed_copy_findings(&actions, &copy).is_empty(),
            "{}",
            joined(&typed_copy_findings(&actions, &copy))
        );
        assert_eq!(
            tc7_rows(&security),
            BTreeSet::from(["DA-01".to_owned(), "DA-13".to_owned(), "DA-14".to_owned(),])
        );
        let no_type = copy.replace(
            "fx-org-delete = Type { $org } to delete the organisation. The export stays downloadable.",
            "fx-org-delete = Delete the organisation. The export stays downloadable.",
        );
        let message = joined(&typed_copy_findings(&actions, &no_type));
        assert!(message.contains("fx-org-delete"), "{message}");
        let wrong_variable = copy.replace(
            "fx-global-setting = Type { $setting } to change it for every tenant. The preview names them.",
            "fx-global-setting = Type { $domain } to change it for every tenant. The preview names them.",
        );
        let message = joined(&typed_copy_findings(&actions, &wrong_variable));
        assert!(message.contains("global-setting"), "{message}");
        let unlisted = security.replace("the global changes (DA-14)", "the global changes");
        let message = joined(&typed_scope_findings(&unlisted, &actions));
        assert!(message.contains("DA-14"), "{message}");
        let extra = security.replace(
            "the fixture declares no extension.",
            "the fixture declares no extension; the member removal (DA-18) is a deliberate extension.",
        );
        let message = joined(&typed_scope_findings(&extra, &actions));
        assert!(message.contains("DA-18"), "{message}");
        let untitled = actions.replace(
            "typed confirmation of the domain name",
            "typed confirmation",
        );
        let message = joined(&typed_copy_findings(&untitled, &copy));
        assert!(
            message.contains("does not say what the user must type"),
            "{message}"
        );
    }

    #[test]
    fn t25_step_up_matches_the_b4_2_s_cells() {
        let actions = actions_document();
        let spec = fixture_spec();
        assert!(
            stepup_findings(&actions, &spec).is_empty(),
            "{}",
            joined(&stepup_findings(&actions, &spec))
        );
        let missing = actions.replace(
            "Step-up and a reason; time box; visible banner.",
            "Reason and time box; visible banner.",
        );
        let message = joined(&stepup_findings(&missing, &spec));
        assert!(
            message.contains("DA-10") || message.contains("safe mode"),
            "{message}"
        );
        let unsupported = actions.replace(
            "Preview of affected sessions; self-lockout preview; step-up (stronger than B4.2).",
            "Preview of affected sessions; self-lockout preview; step-up.",
        );
        let message = joined(&stepup_findings(&unsupported, &spec));
        assert!(message.contains("stronger than B4.2"), "{message}");
        assert!(
            permission_stepup(&spec)
                .get("PERM-vkb.emergency")
                .copied()
                .unwrap_or(false)
        );
        assert!(
            !permission_stepup(&spec)
                .get("PERM-dns.write")
                .copied()
                .unwrap_or(true)
        );
    }

    #[test]
    fn t25_a_typed_journey_step_needs_a_typed_catalog_row_on_that_screen() {
        let actions = actions_document();
        let journey = |step_screen: &str, typed_cell: &str| {
            format!(
                "## Steps\n\n\
                 | Step | User action | System response | Screen |\n\
                 | --- | --- | --- | --- |\n\
                 | 1 | Opens the page. | The page loads. | S-099 |\n\
                 | 2 | Deletes the organisation. | The dialog opens. | {step_screen} |\n\n\
                 ## Safeguards\n\n\
                 | Step | Risky action | Safeguard | Kind | Copy key | Exact copy |\n\
                 | --- | --- | --- | --- | --- | --- |\n\
                 | 2 | Deleting the organisation. | {typed_cell} | confirmation | fx-org-delete | Type the organisation slug. |\n"
            )
        };
        let typed = journey("S-086", "The dialog requires the organisation slug typed.");
        let covering = [("docs/UX/journeys/J-29.md".to_owned(), typed.clone())];
        assert!(
            typed_journey_findings(&covering, &actions).is_empty(),
            "{}",
            joined(&typed_journey_findings(&covering, &actions))
        );
        let wrong_screen = journey("S-099", "The dialog requires the organisation slug typed.");
        let uncovered = [("docs/UX/journeys/J-29.md".to_owned(), wrong_screen)];
        let message = joined(&typed_journey_findings(&uncovered, &actions));
        assert!(message.contains("no catalog row"), "{message}");
        let untyped = journey("S-086", "The preview shows the organisation resources.");
        let quiet = [("docs/UX/journeys/J-29.md".to_owned(), untyped)];
        assert!(typed_journey_findings(&quiet, &actions).is_empty());
    }

    #[test]
    fn t25_the_screen_of_a_mapped_row_is_one_of_the_step_screens() {
        let catalog = actions_document();
        let journey = |screen: &str| {
            format!(
                "## Steps\n\n\
                 | Step | User action | System response | Screen |\n\
                 | --- | --- | --- | --- |\n\
                 | 1 | Switches the protection mode. | The page shows the preset. | {screen} |\n\n\
                 ## Safeguards\n\n\
                 | Step | Risky action | Safeguard | Kind | Copy key | Exact copy |\n\
                 | --- | --- | --- | --- | --- | --- |\n\
                 | 1 | Switching the protection mode. | The page states the consequence. | preview | fx-block-mode | Read the consequence first. |\n"
            )
        };
        let matching = [("docs/UX/journeys/J-16.md".to_owned(), journey("S-055"))];
        assert!(
            safeguard_crosscheck_findings(&catalog, &matching).is_empty(),
            "{}",
            joined(&safeguard_crosscheck_findings(&catalog, &matching))
        );
        let wrong = [("docs/UX/journeys/J-16.md".to_owned(), journey("S-099"))];
        let message = joined(&safeguard_crosscheck_findings(&catalog, &wrong));
        assert!(
            message.contains("reachable from the step's screen"),
            "{message}"
        );
    }

    #[test]
    fn t25_audit_references_in_the_prose_name_the_rows_event() {
        let good = format!(
            "{}\n\nThe domain branch is `AUD-domain.decommissioned` (DA-01) and the organisation is `AUD-org.deleted` (DA-13).\n",
            actions_document()
        );
        assert!(
            audit_reference_findings(&good).is_empty(),
            "{}",
            joined(&audit_reference_findings(&good))
        );
        let bad = good.replace(
            "`AUD-domain.decommissioned` (DA-01)",
            "`AUD-tls.cert_deleted` (DA-01)",
        );
        let message = joined(&audit_reference_findings(&bad));
        assert!(message.contains("AUD-tls.cert_deleted"), "{message}");
        let unknown = good.replace("(DA-13)", "(DA-99)");
        let message = joined(&audit_reference_findings(&unknown));
        assert!(message.contains("DA-99"), "{message}");
    }

    #[test]
    fn t25_abuse_categories_and_atk_citations_are_required() {
        let text = security_document();
        let no_deputy = text
            .lines()
            .filter(|line| !line.contains("Confused deputy in impersonation"))
            .collect::<Vec<_>>()
            .join("\n");
        let message = joined(&abuse_case_findings(&no_deputy, &registry(), &names()));
        assert!(message.contains("confused deputy"), "{message}");
        assert!(atk_citations_findings(&[(SECURITY_UX, text.as_str())], &registry()).is_empty());
        let bad = text.replace("ATK-297", "ATK-097");
        let message = joined(&atk_citations_findings(
            &[(SECURITY_UX, bad.as_str())],
            &registry(),
        ));
        assert!(message.contains("ATK-097"), "{message}");
    }

    #[test]
    fn t25_self_lockout_requirements_are_numbered_and_complete() {
        let text = security_document();
        assert!(
            self_lockout_findings(&text).is_empty(),
            "{}",
            joined(&self_lockout_findings(&text))
        );
        let no_server = text.replace("server-side", "in the page");
        let message = joined(&self_lockout_findings(&no_server));
        assert!(message.contains("server-side"), "{message}");
        let too_few = text.replace("GL-", "G-");
        let message = joined(&self_lockout_findings(&too_few));
        assert!(
            message.contains("10") || message.contains("numbered"),
            "{message}"
        );
    }

    #[test]
    fn t25_preview_patterns_cover_the_four_areas() {
        let text = security_document();
        assert!(preview_pattern_findings(&text).is_empty());
        let no_access = text
            .lines()
            .filter(|line| !line.starts_with("| Access lists |"))
            .collect::<Vec<_>>()
            .join("\n");
        let message = joined(&preview_pattern_findings(&no_access));
        assert!(message.contains("access"), "{message}");
    }

    #[test]
    fn t25_typed_confirmation_rules_are_stated() {
        let text = security_document();
        assert!(typed_confirmation_findings(&text).is_empty());
        let no_case = text.replace("case-sensitive", "case-insensitive");
        let message = joined(&typed_confirmation_findings(&no_case));
        assert!(
            message.contains("case-sensitive") || message.contains("case sensitive"),
            "{message}"
        );
        let no_paste = text.replace("Paste is allowed in the field.", "Typing is required.");
        let message = joined(&typed_confirmation_findings(&no_paste));
        assert!(message.contains("paste"), "{message}");
    }

    #[test]
    fn t25_time_box_states_the_browser_close_revert() {
        let text = security_document();
        assert!(time_box_findings(&text).is_empty());
        let no_close = text.replace("even if the browser closes", "while the page is open");
        let message = joined(&time_box_findings(&no_close));
        assert!(message.contains("browser closes"), "{message}");
        let no_server = text.replace("server-side timer", "page timer");
        let message = joined(&time_box_findings(&no_server));
        assert!(message.contains("server-side"), "{message}");
    }

    #[test]
    fn t25_honest_limits_quote_b13_exactly() {
        let text = security_document();
        assert!(honest_limits_findings(&text, &fixture_spec()).is_empty());
        let wrong_key = text.replace(
            "| Shield | S-057 | `shield-limit` |",
            "| Shield | S-057 | `block-confirm-body` |",
        );
        let message = joined(&honest_limits_findings(&wrong_key, &fixture_spec()));
        assert!(message.contains("shield-limit"), "{message}");
        let wrong_copy = text.replace(
            "| Readiness | S-044 | `readiness-footnote` | Measures configuration completeness, not security. |",
            "| Readiness | S-044 | `readiness-footnote` | Measures configuration, not security. |",
        );
        let message = joined(&honest_limits_findings(&wrong_copy, &fixture_spec()));
        assert!(
            message.contains("readiness-footnote") || message.contains("differs"),
            "{message}"
        );
    }

    #[test]
    fn t25_stride_delta_names_the_ui_abuse_threats() {
        let text = stride_document();
        assert!(
            stride_findings(&text).is_empty(),
            "{}",
            joined(&stride_findings(&text))
        );
        let no_tampering = text
            .lines()
            .filter(|line| !line.contains("Tampering"))
            .collect::<Vec<_>>()
            .join("\n");
        let message = joined(&stride_findings(&no_tampering));
        assert!(message.contains("Tampering"), "{message}");
        let no_deputy = text.replace(
            "A confused deputy in an impersonation session writes.",
            "A write in an impersonation session.",
        );
        let message = joined(&stride_findings(&no_deputy));
        assert!(message.contains("confused deputy"), "{message}");
    }

    #[test]
    fn t25_forbidden_claims_are_rejected() {
        let cfg = claims_cfg();
        let text = format!("{}\nA rule with absolute protection.\n", actions_document());
        let message = joined(&claims_doc_findings(&cfg, DANGEROUS_ACTIONS, &text));
        assert!(message.contains("absolute protection"), "{message}");
    }

    #[test]
    fn t25_journey_safeguards_cross_check_the_catalog() {
        let catalog = actions_document();
        let row = |action: &str| {
            format!(
                "## Safeguards\n\n\
                 | Step | Risky action | Safeguard | Kind | Copy key | Exact copy |\n\
                 | --- | --- | --- | --- | --- | --- |\n\
                 | 1 | {action} | The preview shows the change before it applies. | preview | fixture-copy | Review the change before it applies. |\n"
            )
        };
        let journeys = vec![(
            "docs/UX/journeys/J-16.md".to_owned(),
            row("Switching the protection mode."),
        )];
        assert!(
            safeguard_crosscheck_findings(&catalog, &journeys).is_empty(),
            "{}",
            joined(&safeguard_crosscheck_findings(&catalog, &journeys))
        );
        let unmapped = vec![(
            "docs/UX/journeys/J-16.md".to_owned(),
            row("Polishing the dashboard colours."),
        )];
        let message = joined(&safeguard_crosscheck_findings(&catalog, &unmapped));
        assert!(
            message.contains("no reviewed dangerous-action mapping"),
            "{message}"
        );
        let without = catalog
            .lines()
            .filter(|line| !line.contains("| DA-05 |"))
            .collect::<Vec<_>>()
            .join("\n");
        let message = joined(&safeguard_crosscheck_findings(&without, &journeys));
        assert!(
            message.contains("not a row of the dangerous-action catalog"),
            "{message}"
        );
    }

    #[test]
    fn t25_malformed_input_is_a_finding_not_a_panic() {
        let spec = fixture_spec();
        let audits = audits();
        let permissions = permissions();
        let registry = registry();
        let owning = [
            ("catalog", catalog_findings("")),
            ("copy keys", copy_key_findings("", "", None)),
            ("abuse cases", abuse_case_findings("", &registry, &names())),
            ("self-lockout", self_lockout_findings("")),
            ("previews", preview_pattern_findings("")),
            ("typed confirmation", typed_confirmation_findings("")),
            ("time box", time_box_findings("")),
            ("honest limits", honest_limits_findings("", &spec)),
            ("STRIDE", stride_findings("")),
            (
                "safeguard cross-check",
                safeguard_crosscheck_findings("", &[]),
            ),
        ];
        for (rule, findings) in owning {
            assert!(!findings.is_empty(), "{rule} accepted an empty document");
        }
        let derived = [
            required_action_findings(""),
            audit_event_findings("", &audits),
            audit_area_findings(""),
            permission_findings("", &permissions),
            atk_citations_findings(&[(SECURITY_UX, "")], &registry),
            typed_copy_findings("", ""),
            typed_scope_findings("", ""),
            stepup_findings("", &spec),
            audit_reference_findings(""),
            typed_journey_findings(&[], ""),
        ];
        for findings in derived {
            assert!(findings.is_empty(), "{}", joined(&findings));
        }
    }
}
