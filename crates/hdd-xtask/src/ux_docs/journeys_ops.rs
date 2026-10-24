//! Journey safeguarding and decision-support checks (T-0017): the `Safeguards`, `What could go wrong`,
//! `Decision support`, ATK-family and operator-question rules that extend the T-0016 journey checks.
//!
//! The risky-step rule is a documented heuristic: a step is risky when its `User action` or `System response` mentions
//! a protected object (DNS, TLS, certificate, protection mode, rule, ban, appeal, firewall, origin lockdown) **and** a
//! mutating verb (change, save, switch, delete, remove, enable, disable, apply, issue, rotate, revoke, decline,
//! allowlist, rollback, publish, create, add, set, confirm). The ATK-family rule is also a heuristic: the C5 table has
//! no category column, so the family is inferred from the C5 attack text and compared with the family implied by the
//! step text; when either side is unknown the rule is skipped. Both heuristics are stated in the module documentation
//! of the parent check as well.

use super::*;

/// Whether a step changes a protected object, by the documented risky-step heuristic.
///
/// Objects and verbs are matched as whole tokens with their regular inflections (`set`/`sets`, `save`/`saved`,
/// `switch`/`switches`), never as substrings: the earlier substring form matched `preset` as `set` and `addresses` as
/// `add`, which produced safeguards for steps that change nothing.
pub fn risky_step(action: &str, system: &str) -> bool {
    let text = format!("{action} {system}").to_lowercase();
    let objects = [
        "dns",
        "tls",
        "certificate",
        "hsts",
        "protection mode",
        "waf mode",
        "rule",
        "ban",
        "appeal",
        "firewall",
        "lockdown",
        "origin",
        "proxy",
        "preset",
    ];
    let verbs = [
        "change",
        "save",
        "switch",
        "delete",
        "remove",
        "enable",
        "disable",
        "apply",
        "issue",
        "rotate",
        "revoke",
        "decline",
        "allowlist",
        "rollback",
        "publish",
        "create",
        "add",
        "set",
        "confirm",
        "toggle",
    ];
    let tokens: BTreeSet<String> = text
        .split(|c: char| !c.is_alphanumeric())
        .filter(|token| !token.is_empty())
        .map(str::to_owned)
        .collect();
    let mentions = |needle: &str| {
        if needle.contains(' ') {
            text.contains(needle)
        } else {
            let forms = [
                needle.to_owned(),
                format!("{needle}s"),
                format!("{needle}es"),
                format!("{needle}ed"),
                format!("{needle}d"),
                format!("{needle}ing"),
            ];
            forms.iter().any(|form| tokens.contains(form))
        }
    };
    objects.iter().any(|object| mentions(object)) && verbs.iter().any(|verb| mentions(verb))
}

/// The inferred family of a C5 attack id from its attack text (heuristic; the C5 table has no category column).
fn attack_family(spec_atk_text: &str) -> Option<&'static str> {
    let text = spec_atk_text.to_lowercase();
    let families: [(&'static str, &'static [&'static str]); 7] = [
        (
            "injection",
            &["sql", "union", "tautology", "injection", "query", "stacked"],
        ),
        ("xss", &["script", "xss", "svg", "html", "markup"]),
        (
            "dns",
            &[
                "dns",
                "zone",
                "nameserver",
                "axfr",
                "delegation",
                "subdomain",
            ],
        ),
        (
            "auth",
            &[
                "credential",
                "brute",
                "enumeration",
                "password",
                "mfa",
                "otp",
                "session",
                "token",
            ],
        ),
        ("ssrf", &["ssrf", "rebinding", "loopback", "metadata"]),
        ("redirect", &["redirect"]),
        ("csrf", &["forgery", "csrf"]),
    ];
    for (family, words) in families {
        if words.iter().any(|word| text.contains(word)) {
            return Some(family);
        }
    }
    None
}

/// The family implied by a step's text, if any.
fn step_family(action: &str, system: &str) -> Option<&'static str> {
    let text = format!("{action} {system}").to_lowercase();
    let families: [(&'static str, &'static [&'static str]); 7] = [
        (
            "injection",
            &["sql", "union", "injection", "query", "tautology", "stacked"],
        ),
        (
            "xss",
            &["script", "xss", "svg", "markup", "html", "injection"],
        ),
        (
            "dns",
            &[
                "dns",
                "zone",
                "nameserver",
                "delegation",
                "record",
                "subdomain",
            ],
        ),
        (
            "auth",
            &[
                "credential",
                "brute",
                "enumeration",
                "password",
                "mfa",
                "otp",
                "session",
                "token",
            ],
        ),
        (
            "ssrf",
            &["ssrf", "rebinding", "loopback", "metadata", "origin"],
        ),
        ("redirect", &["redirect", "return url"]),
        ("csrf", &["csrf", "forgery"]),
    ];
    for (family, words) in families {
        if words.iter().any(|word| text.contains(word)) {
            return Some(family);
        }
    }
    None
}

/// The T-0017 journey checks: `Safeguards`, `What could go wrong`, `Decision support`, the ATK row count for the
/// protection journeys and the C5/step family heuristic.
pub fn ops_findings(text: &str, id: &str, atk_text: &BTreeMap<String, String>) -> Vec<Finding> {
    let loc = format!("{JOURNEYS_DIR}/{id}.md");
    let mut out = Vec::new();
    let Ok(numeric) = id.trim_start_matches("J-").parse::<u32>() else {
        return out;
    };
    if numeric < 13 {
        return out;
    }
    let mut steps: BTreeMap<String, (String, String)> = BTreeMap::new();
    if let Some(body) = section_body(text, "Steps") {
        let tables = tables_in(&body);
        let wanted = [
            "step",
            "user action",
            "system response",
            "screen",
            "data collected",
            "error path",
            "emotional state",
            "copy key",
            "metric",
        ];
        if let Some(table) = table_with_header(&tables, &wanted) {
            for (_, row) in &table.rows {
                let step = row.first().map_or("", |cell| cell.trim()).to_owned();
                let action = row.get(1).map_or("", |cell| cell.trim()).to_owned();
                let system = row.get(2).map_or("", |cell| cell.trim()).to_owned();
                steps.insert(step, (action, system));
            }
        }
    }
    let copy_re = Regex::new(r"^[a-z0-9]+(-[a-z0-9]+)*$").ok();
    match section_body(text, "Safeguards") {
        None => out.push(finding(&loc, "no `## Safeguards` section (T-0017 pass 1)")),
        Some(body) => {
            let tables = tables_in(&body);
            let wanted = [
                "step",
                "risky action",
                "safeguard",
                "kind",
                "copy key",
                "exact copy",
            ];
            match table_with_header(&tables, &wanted) {
                None => out.push(finding(
                    &loc,
                    "the `Safeguards` section has no table with columns Step | Risky action | Safeguard | Kind | Copy key | Exact copy (T-0017)",
                )),
                Some(table) => {
                    let mut covered: BTreeSet<String> = BTreeSet::new();
                    for (n, row) in &table.rows {
                        let at = format!("{loc}:{n}");
                        if row.len() < 6 || row.iter().any(|cell| cell.trim().is_empty()) {
                            out.push(finding(&at, "a safeguard row needs six non-empty cells (T-0017)"));
                            continue;
                        }
                        let step = row.first().map_or("", |cell| cell.trim());
                        if !steps.contains_key(step) {
                            out.push(finding(&at, format!("safeguard row names step `{step}`, which is not in the steps table")));
                        }
                        covered.insert(step.to_owned());
                        let kind = row.get(3).map_or("", |cell| cell.trim()).to_lowercase();
                        if !SAFEGUARD_KINDS.contains(&kind.as_str()) {
                            out.push(finding(&at, format!("`Kind` value `{kind}` is not one of {}", SAFEGUARD_KINDS.join(", "))));
                        }
                        let copy_key = row.get(4).map_or("", |cell| cell.trim());
                        if !copy_re.as_ref().is_some_and(|re| re.is_match(copy_key)) {
                            out.push(finding(&at, format!("copy key `{copy_key}` is not a hyphenated lowercase stem")));
                        }
                        let copy = row.get(5).map_or("", |cell| cell.trim());
                        let words = copy.split_whitespace().count();
                        if words > 25 {
                            out.push(finding(&at, format!("the `Exact copy` has {words} words; at most 25 are allowed (T-0017)")));
                        }
                        let lower = copy.to_lowercase();
                        if FORBIDDEN_CLAIMS.iter().any(|phrase| lower.contains(phrase)) {
                            out.push(finding(&at, "the `Exact copy` contains a forbidden claims phrase (T-0017)"));
                        }
                    }
                    for (step, (action, system)) in &steps {
                        if risky_step(action, system) && !covered.contains(step) {
                            out.push(finding(&loc, format!("risky step {step} changes a protected object but has no `Safeguards` row (T-0017)")));
                        }
                    }
                }
            }
        }
    }
    match section_body(text, "What could go wrong") {
        None => out.push(finding(
            &loc,
            "no `## What could go wrong` section (T-0017)",
        )),
        Some(body) => {
            let tables = tables_in(&body);
            let wanted = ["step", "what goes wrong", "recovery action"];
            match table_with_header(&tables, &wanted) {
                None => out.push(finding(&loc, "the `What could go wrong` section has no table with columns Step | What goes wrong | Recovery action (T-0017)")),
                Some(table) => {
                    if table.rows.len() < 3 {
                        out.push(finding(&loc, format!("the `What could go wrong` table has {} rows; at least three are required (T-0017)", table.rows.len())));
                    }
                    for (n, row) in &table.rows {
                        if row.len() < 3 || row.iter().any(|cell| cell.trim().is_empty()) {
                            out.push(finding(format!("{loc}:{n}"), "a `What could go wrong` row needs three non-empty cells (T-0017)"));
                        }
                    }
                }
            }
        }
    }
    out.extend(protection_atk_row_findings(text, numeric, &loc));
    out.extend(atk_family_findings(text, &steps, atk_text, &loc));
    out.extend(journey_specific_findings(text, numeric, &loc, atk_text));
    if numeric == 16 || numeric == 17 {
        match section_body(text, "Decision support") {
            None => out.push(finding(
                &loc,
                "no `## Decision support` section (T-0017 A2)",
            )),
            Some(body) => {
                let items = body
                    .iter()
                    .filter(|(_, line)| line.trim_start().starts_with("- "))
                    .count();
                if items < 5 {
                    out.push(finding(
                        &loc,
                        format!(
                            "`Decision support` has {items} items; at least five are required (A2)"
                        ),
                    ));
                }
            }
        }
    }
    out
}

/// The protection journeys (J-16 to J-21) need at least three `ATK-` rows in `Security considerations` (A5).
fn protection_atk_row_findings(text: &str, numeric: u32, loc: &str) -> Vec<Finding> {
    if !(16..=21).contains(&numeric) {
        return Vec::new();
    }
    let Some(body) = section_body(text, "Security considerations") else {
        return Vec::new();
    };
    let tables = tables_in(&body);
    let wanted = ["step", "risk", "control", "atk"];
    let Some(table) = table_with_header(&tables, &wanted) else {
        return Vec::new();
    };
    let atk_rows = table
        .rows
        .iter()
        .filter(|(_, row)| !tokens_in(row.get(3).map_or("", |cell| cell), r"ATK-\d{3}").is_empty())
        .count();
    if atk_rows < 3 {
        vec![finding(
            loc,
            format!("the protection journey needs at least three ATK- rows, found {atk_rows} (A5)"),
        )]
    } else {
        Vec::new()
    }
}

/// The C5-text family heuristic: an `ATK-` id on a security row must belong to the family implied by its step.
fn atk_family_findings(
    text: &str,
    steps: &BTreeMap<String, (String, String)>,
    atk_text: &BTreeMap<String, String>,
    loc: &str,
) -> Vec<Finding> {
    let mut out = Vec::new();
    let Some(body) = section_body(text, "Security considerations") else {
        return out;
    };
    let tables = tables_in(&body);
    let wanted = ["step", "risk", "control", "atk"];
    let Some(table) = table_with_header(&tables, &wanted) else {
        return out;
    };
    for (n, row) in &table.rows {
        let step = row.first().map_or("", |cell| cell.trim());
        let Some((action, system)) = steps.get(step) else {
            continue;
        };
        let Some(expected) = step_family(action, system) else {
            continue;
        };
        for atk in tokens_in(row.get(3).map_or("", |cell| cell), r"ATK-\d{3}") {
            let Some(family) = atk_text.get(&atk).and_then(|text| attack_family(text)) else {
                continue;
            };
            if family != expected {
                out.push(finding(format!("{loc}:{n}"), format!("`{atk}` belongs to the `{family}` family but step {step} implies `{expected}`; the family check is a C5-text heuristic (T-0017)")));
            }
        }
    }
    out
}

/// The journey-specific checks of pass 2: the rule-builder error taxonomy (J-19), the appeal abuse cases (J-22), the
/// owner outcomes (J-23) and the origin-lockdown stacks and verification probes (J-24).
fn journey_specific_findings(
    text: &str,
    numeric: u32,
    loc: &str,
    atk_text: &BTreeMap<String, String>,
) -> Vec<Finding> {
    match numeric {
        19 => rule_builder_taxonomy_findings(text, loc),
        22 => abuse_cases_findings(text, loc, atk_text),
        23 => owner_outcomes_findings(text, loc),
        24 => {
            let mut out = stacks_findings(text, loc);
            out.extend(verification_probe_findings(text, loc));
            out
        }
        _ => Vec::new(),
    }
}

/// J-19: the `Rule builder error taxonomy` table has the three classes, at least two rows each, and valid copy.
fn rule_builder_taxonomy_findings(text: &str, loc: &str) -> Vec<Finding> {
    const CLASSES: [&str; 3] = ["syntax", "semantic", "performance"];
    let mut out = Vec::new();
    let Some(body) = section_body(text, "Rule builder error taxonomy") else {
        return vec![finding(
            loc,
            "no `## Rule builder error taxonomy` section (T-0017 J-19)",
        )];
    };
    let tables = tables_in(&body);
    let wanted = ["class", "example", "message copy key", "exact copy"];
    let Some(table) = table_with_header(&tables, &wanted) else {
        return vec![finding(
            loc,
            "the `Rule builder error taxonomy` section has no table with columns Class | Example | Message copy key | Exact copy (T-0017 J-19)",
        )];
    };
    let copy_re = Regex::new(r"^[a-z0-9]+(-[a-z0-9]+)*$").ok();
    let mut counts: BTreeMap<&'static str, usize> = BTreeMap::new();
    for (n, row) in &table.rows {
        let at = format!("{loc}:{n}");
        if row.len() < 4 || row.iter().any(|cell| cell.trim().is_empty()) {
            out.push(finding(
                &at,
                "a rule-taxonomy row needs four non-empty cells (T-0017 J-19)",
            ));
            continue;
        }
        let class = row.first().map_or("", |cell| cell.trim()).to_lowercase();
        let Some(class) = CLASSES.iter().find(|known| **known == class) else {
            out.push(finding(
                &at,
                format!("class `{class}` is not one of {}", CLASSES.join(", ")),
            ));
            continue;
        };
        *counts.entry(class).or_default() += 1;
        let copy_key = row.get(2).map_or("", |cell| cell.trim());
        if !copy_re.as_ref().is_some_and(|re| re.is_match(copy_key)) {
            out.push(finding(
                &at,
                format!("copy key `{copy_key}` is not a hyphenated lowercase stem"),
            ));
        }
        let copy = row.get(3).map_or("", |cell| cell.trim());
        let words = copy.split_whitespace().count();
        if words > 25 {
            out.push(finding(
                &at,
                format!("the `Exact copy` has {words} words; at most 25 are allowed (T-0017 J-19)"),
            ));
        }
        let lower = copy.to_lowercase();
        if FORBIDDEN_CLAIMS.iter().any(|phrase| lower.contains(phrase)) {
            out.push(finding(
                &at,
                "the `Exact copy` contains a forbidden claims phrase (T-0017 J-19)",
            ));
        }
    }
    for class in CLASSES {
        let rows = counts.get(class).copied().unwrap_or(0);
        if rows < 2 {
            out.push(finding(
                loc,
                format!("class `{class}` has {rows} rows; at least two are required (T-0017 J-19)"),
            ));
        }
    }
    out
}

/// J-22: the `Abuse cases` table has at least five rows and every `ATK` id is a C5 registry entry.
fn abuse_cases_findings(
    text: &str,
    loc: &str,
    atk_text: &BTreeMap<String, String>,
) -> Vec<Finding> {
    let mut out = Vec::new();
    let Some(body) = section_body(text, "Abuse cases") else {
        return vec![finding(loc, "no `## Abuse cases` section (T-0017 J-22)")];
    };
    let tables = tables_in(&body);
    let wanted = ["abuse case", "defense", "atk"];
    let Some(table) = table_with_header(&tables, &wanted) else {
        return vec![finding(
            loc,
            "the `Abuse cases` section has no table with columns Abuse case | Defense | ATK (T-0017 J-22)",
        )];
    };
    if table.rows.len() < 5 {
        out.push(finding(
            loc,
            format!(
                "the `Abuse cases` table has {} rows; at least five are required (T-0017 J-22)",
                table.rows.len()
            ),
        ));
    }
    for (n, row) in &table.rows {
        let at = format!("{loc}:{n}");
        if row.len() < 3 || row.iter().any(|cell| cell.trim().is_empty()) {
            out.push(finding(
                &at,
                "an abuse-case row needs three non-empty cells (T-0017 J-22)",
            ));
            continue;
        }
        for atk in tokens_in(row.get(2).map_or("", |cell| cell), r"ATK-\d{3}") {
            if !atk_text.contains_key(&atk) {
                out.push(finding(
                    &at,
                    format!("`{atk}` is not an id of the C5 attack matrix (T-0017 J-22)"),
                ));
            }
        }
    }
    out
}

/// J-23: the `Owner outcomes` section lists the four resolutions of an appeal.
fn owner_outcomes_findings(text: &str, loc: &str) -> Vec<Finding> {
    const OUTCOMES: [(&str, &[&str]); 4] = [
        ("unban", &["unban"]),
        ("allowlist for N days", &["allowlist", "days"]),
        ("scoped exception", &["scoped", "exception"]),
        ("decline with reason", &["decline", "reason"]),
    ];
    let Some(body) = section_body(text, "Owner outcomes") else {
        return vec![finding(loc, "no `## Owner outcomes` section (T-0017 J-23)")];
    };
    let joined = body
        .iter()
        .map(|(_, line)| line.as_str())
        .collect::<Vec<_>>()
        .join("\n")
        .to_lowercase();
    let mut out = Vec::new();
    for (label, needles) in OUTCOMES {
        if !needles.iter().all(|needle| joined.contains(needle)) {
            out.push(finding(
                loc,
                format!("`Owner outcomes` does not name the outcome `{label}` (T-0017 J-23)"),
            ));
        }
    }
    out
}

/// J-24: the `Stacks` section names every stack, says the steps are conceptual and contains no real command line.
fn stacks_findings(text: &str, loc: &str) -> Vec<Finding> {
    let Some(body) = section_body(text, "Stacks") else {
        return vec![finding(loc, "no `## Stacks` section (T-0017 J-24)")];
    };
    let joined = body
        .iter()
        .map(|(_, line)| line.as_str())
        .collect::<Vec<_>>()
        .join("\n")
        .to_lowercase();
    let mut out = Vec::new();
    for stack in ["ufw", "iptables", "nftables", "cloud security group"] {
        if !joined.contains(stack) {
            out.push(finding(
                loc,
                format!("`Stacks` does not name `{stack}` (T-0017 J-24)"),
            ));
        }
    }
    if !(joined.contains("nginx") || joined.contains("apache")) {
        out.push(finding(
            loc,
            "`Stacks` does not name an `nginx` or `apache` snippet (T-0017 J-24)",
        ));
    }
    if !joined.contains("conceptual") {
        out.push(finding(
            loc,
            "`Stacks` must say the steps are conceptual (T-0017 J-24)",
        ));
    }
    let no_command = [
        "never a real command line",
        "not a real command line",
        "no real command line",
    ];
    if !no_command.iter().any(|phrase| joined.contains(phrase)) {
        out.push(finding(
            loc,
            "`Stacks` must say the steps are never a real command line (T-0017 J-24)",
        ));
    }
    if stacks_section_has_fence(text) {
        out.push(finding(
            loc,
            "the `Stacks` section must stay conceptual and contain no fenced command block (T-0017 J-24)",
        ));
    }
    out
}

/// Whether the raw text of the `Stacks` section contains a fenced code block. `section_body` reads prose lines only, so
/// the fence lines have to be found on the raw document.
fn stacks_section_has_fence(text: &str) -> bool {
    let mut inside = false;
    for line in text.lines() {
        let t = line.trim_start();
        if let Some(title) = t.strip_prefix("## ") {
            if inside {
                break;
            }
            inside = title.trim().eq_ignore_ascii_case("Stacks");
            continue;
        }
        if inside && (t.starts_with("```") || t.starts_with("~~~")) {
            return true;
        }
    }
    false
}

/// J-24: the `Verification probes` table has at least four probes, each with what it proves and what it cannot prove.
fn verification_probe_findings(text: &str, loc: &str) -> Vec<Finding> {
    let Some(body) = section_body(text, "Verification probes") else {
        return vec![finding(
            loc,
            "no `## Verification probes` section (T-0017 J-24)",
        )];
    };
    let tables = tables_in(&body);
    let wanted = ["probe", "what it proves", "what it cannot prove"];
    let Some(table) = table_with_header(&tables, &wanted) else {
        return vec![finding(
            loc,
            "the `Verification probes` section has no table with columns Probe | What it proves | What it cannot prove (T-0017 J-24)",
        )];
    };
    let mut out = Vec::new();
    if table.rows.len() < 4 {
        out.push(finding(
            loc,
            format!(
                "the `Verification probes` table has {} rows; at least four are required (T-0017 J-24)",
                table.rows.len()
            ),
        ));
    }
    for (n, row) in &table.rows {
        if row.len() < 3 || row.iter().any(|cell| cell.trim().is_empty()) {
            out.push(finding(
                format!("{loc}:{n}"),
                "a `Verification probes` row needs a probe, what it proves and what it cannot prove (T-0017 J-24)",
            ));
        }
    }
    out
}

/// The kinds a safeguard may have.
pub const SAFEGUARD_KINDS: [&str; 4] = ["preview", "confirmation", "undo", "time box"];

/// Forbidden claims phrases (a subset of `docs/claims-lint.toml`) for the safeguard copy rule.
const FORBIDDEN_CLAIMS: [&str; 16] = [
    "absolute protection",
    "absolute defence",
    "absolute defense",
    "absolute security",
    "complete protection",
    "total protection",
    "fully secure",
    "completely secure",
    "guaranteed protection",
    "100% secure",
    "100% protection",
    "unhackable",
    "unbreakable",
    "cannot be bypassed",
    "impossible to bypass",
    "stops all attacks",
];
/// The `## Questions added by T-0017` register section: every row is OPEN and is cited by a journey in scope.
pub fn operator_questions_findings(register: &str, journeys: &[(String, String)]) -> Vec<Finding> {
    let loc = "docs/OPERATOR-QUESTIONS.md";
    let mut out = Vec::new();
    let Some(body) = section_body(register, "Questions added by T-0017") else {
        out.push(finding(
            loc,
            "no `## Questions added by T-0017` section (T-0017)",
        ));
        return out;
    };
    let tables = tables_in(&body);
    let Some(table) = table_with_header(&tables, &["question", "default", "state"]) else {
        out.push(finding(loc, "no `## Questions added by T-0017` table with columns Question | Default | State (T-0017)"));
        return out;
    };
    if table.rows.is_empty() {
        out.push(finding(
            loc,
            "the T-0017 question table has no rows (T-0017)",
        ));
    }
    for (n, row) in &table.rows {
        let at = format!("{loc}:{n}");
        if row.len() < 3 || row.iter().any(|cell| cell.trim().is_empty()) {
            out.push(finding(
                &at,
                "a T-0017 question row needs three non-empty cells (T-0017)",
            ));
            continue;
        }
        let question = row.first().map_or("", |cell| cell.trim());
        let state = row.get(2).map_or("", |cell| cell.trim());
        if !state.eq_ignore_ascii_case("OPEN") {
            out.push(finding(
                &at,
                format!("the question state `{state}` must be OPEN (T-0017)"),
            ));
        }
        if !journeys.iter().any(|(_, text)| text.contains(question)) {
            out.push(finding(
                &at,
                "the question is not cited by any journey in scope (T-0017)",
            ));
        }
    }
    out
}

/// C5 attack id to the attack text, for the family heuristic.
pub fn attack_texts(spec: &str) -> BTreeMap<String, String> {
    let mut out = BTreeMap::new();
    for line in spec.lines() {
        let Some(row) = cells(line) else { continue };
        let Some(id) = row.first() else { continue };
        let id = id.trim();
        if !id.starts_with("ATK-") {
            continue;
        }
        let text = row.get(1).map_or("", |cell| cell.trim());
        out.insert(id.to_owned(), text.to_owned());
    }
    out
}
