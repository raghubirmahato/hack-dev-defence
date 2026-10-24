//! `ux-docs` check (T-0011, extended by T-0012, T-0013 and T-0014): the UX documents are structured, honest and linked.
//!
//! * every relative link in `docs/UX/**/*.md` and `AGENTS.md` resolves to a file inside the repository, and a `#fragment`
//!   on a Markdown target names a real heading;
//! * `docs/UX/CHARTER.md` has seven principles each with a "we will", a "we will not" and an enforcement mechanism, five
//!   honesty tests phrased as yes/no questions, and fits four printed pages (a word budget, R-29);
//! * `docs/UX/MEASURES.md` names every experience measure with its definition, data source and privacy treatment;
//! * `docs/UX/decisions/UXD-001..003.md` follow the decision-record format;
//! * T-0012: the seven persona files (`docs/UX/personas/{maya,dan,sara,omar,vi,alex,adversary}.md`) exist; every one says
//!   in its header that it is a fictional composite, has the five context-of-use rows, at least three scenarios in the
//!   "When ..., I want to ..., so I can ..." form with a measurable outcome, and names anti-goals, accessibility needs
//!   mapped to B11.11 and cross-links to journeys and screens; the adversary file maps at least ten abuse stories to
//!   `ATK-nnn` ids that exist as rows of the attack coverage matrix (C5) in the master specification;
//!   `docs/UX/persona-journey-matrix.md` links every journey J-01 to J-34 to at least one persona file; every key
//!   journey the B1.1 to B1.6 tables of the master specification declare for a persona appears in that persona's
//!   `Journeys and screens` list and in the matrix row of the journey, and a persona file's own journey list is a
//!   subset of the matrix links (F-7); and the primary-persona question is recorded OPEN with default Maya in
//!   `docs/OPERATOR-QUESTIONS.md` and linked from the matrix or the Maya file (A2, A5).
//! * T-0013: `docs/UX/PATTERNS.md` has a valid status line (`PASS` or `UNVERIFIED(<reason>)`), at least twelve topics with
//!   the five labeled parts and an allowed `Source:` value, `PASS` is rejected while every topic is first principles, and
//!   the `Honesty-test review` table has five rows whose answers are `Yes` or `No` with a reason each (a `No` blocks the
//!   document); `docs/UX/design-requirements.md` has DR-01 to DR-20 once each, each with a rationale, a PATTERNS.md topic
//!   anchor that exists and an existing S-nnn screen (spec B12.1) or B11.8 component matched as a whole token; and no
//!   sentence longer than twelve words is copied verbatim between UX documents (the self-copy guard).
//! * T-0014: `docs/UX/routes.toml` parses and holds one route per B2.2 path and per B12.1 screen (visitor responses are
//!   marked data-plane by note, and the eight screens B2.2 serves at two paths are allowed exactly two rows); every route
//!   has a valid surface, permission, method set and B6.1 rate-limit class; patterns obey the URL and token rules; the
//!   keys are consistent with each other (no `public` on the admin or api surface or on a session app route, platform
//!   permissions only on admin, and a rate class that fits the methods unless listed in `Rate-class exceptions`); and
//!   `docs/UX/IA.md` has the ten required sections, one `Test:` line per URL rule, and an identifier regex that matches
//!   its worked example.
//! * T-0015: `docs/UX/NAVIGATION.md` has the ten required sections; its elements table lists the 13 org-sidebar items,
//!   the 9 domain tabs and the 7 top-bar controls with a keyboard path and an ARIA role each, and every route cell names a
//!   `routes.toml` pattern whose permission it repeats exactly; its shortcut map covers the B2.3 shortcuts, has no
//!   duplicate and no reserved key, the reserved list has at least ten rows, and every bound key with a browser or
//!   screen-reader default is recorded in `Documented conflicts` with an effect and a mitigation that names a real
//!   element and the shortcut-off setting; permission-hidden and plan-limited are distinguished, focus is specified for
//!   full loads and swaps, the 360/480/768 px layouts are specified, no table row depends on hover, and at least three
//!   ASCII wireframes exist.
//! * T-0016: the delivered journey maps (`docs/UX/journeys/J-01.md` to `J-06.md`) carry the spec B3 title, the
//!   persona links of the persona-journey matrix, at least eight steps with a screen, a B7 error code, an emotional
//!   state and a copy key, trust moments, C5-backed security rows, an accessibility row for every screen-changing step,
//!   B8 audit sources, the AC checks the spec text names, and every screen the spec text mentions;
//!   `docs/UX/spec-patches.md` proposes only screens that B12.1 lacks and that a delivered journey needs. The
//!   error-path step-fit rule compares content words and is a heuristic that catches blatant mismatches; the
//!   reviewer's reading covers the rest.
//!
//! The check is deliberately a document linter, not a spec parser: it reads the registry rows it needs (C5), the B11.11
//! criterion table, the `Key journeys` rows (B1.1 to B1.6), the B12.1 screen table, the B11.8 component inventory, the
//! B4.2 permission catalog and the B6.1 rate-limit classes from the master specification, verified against
//! `docs/SPEC.sha256` by [`crate::spec::load_master`], and the journey ids from the fixed range of B3. This is the
//! precursor of `xtask ux check` (T-0028), which adds the screen and journey registries.
//!
//! Limits of the link check: inline links on one line only (no reference-style definitions, no link text spanning lines),
//! no parentheses inside a target, and anchors follow GitHub's slug rule.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Component, Path, PathBuf};

use regex::Regex;
use serde::Deserialize;

use crate::util::{Finding, read_text, rel, walk_files};

const CHECK: &str = "ux-docs";

/// Header cells and body rows (with line numbers) of a Markdown table.
type Table = (Vec<String>, Vec<(usize, Vec<String>)>);

/// A structural check of one document's text.
type Checker = fn(&str) -> Vec<Finding>;

/// Four printed pages at about 600 words each (a table-heavy page holds fewer words than prose).
pub const CHARTER_WORD_BUDGET: usize = 2400;

/// The principles of B11.1, in order.
const PRINCIPLES: usize = 7;
/// The honesty tests of T-0011 step 3.
const HONESTY_TESTS: usize = 5;
/// Measures the task names, matched case-insensitively against the first cell of a row.
const MEASURES: [(&str, &str); 6] = [
    (
        "time to first domain",
        "Time to first domain in monitor mode",
    ),
    (
        "completion rate",
        "Completion rate of the add-domain wizard",
    ),
    (
        "support-worthy errors",
        "Support-worthy errors per 100 sessions",
    ),
    ("false-positive appeal", "False-positive appeal rate"),
    ("time to unban", "Time to unban"),
    ("accessibility defects", "Accessibility defects open"),
];
/// Statuses a decision record may carry.
const STATUSES: [&str; 4] = ["proposed", "accepted", "superseded", "rejected"];
/// Decision records that must exist.
const DECISIONS: [&str; 3] = ["UXD-001", "UXD-002", "UXD-003"];

/// The seven personas of B1.1 to B1.7, as file stems; the last one is the adversary.
pub const PERSONAS: [&str; 7] = ["maya", "dan", "sara", "omar", "vi", "alex", "adversary"];
/// The adversary persona, the only file that carries abuse stories.
pub const ADVERSARY: &str = "adversary";
/// Journeys of B3: J-01 to J-34.
pub const JOURNEYS: usize = 34;
/// At least three scenarios per persona (T-0012 A1).
pub const MIN_SCENARIOS: usize = 3;
/// At least ten abuse stories mapped to attack-registry ids in the adversary file (T-0012 A4).
pub const MIN_ABUSE_STORIES: usize = 10;
/// Rows the context-of-use table must have (T-0012 step 1).
pub const CONTEXT_ROWS: [&str; 5] = [
    "Device",
    "Connectivity",
    "Interruptions",
    "Vocabulary",
    "First check of the day",
];
/// The persona-journey matrix.
pub const MATRIX: &str = "docs/UX/persona-journey-matrix.md";
/// Needle that finds a link to the primary-persona question (A5).
pub const PRIMARY_PERSONA_LINK: &str = "OPERATOR-QUESTIONS.md#primary-persona";
/// The spec heading of each persona that has a `Key journeys` row. B1.7 (the adversary) has no row and is exempt.
pub const PERSONA_HEADINGS: [(&str, &str); 6] = [
    ("maya", "B1.1"),
    ("dan", "B1.2"),
    ("sara", "B1.3"),
    ("omar", "B1.4"),
    ("vi", "B1.5"),
    ("alex", "B1.6"),
];

/// At least twelve topics have a pattern entry (T-0013 A1).
pub const MIN_PATTERN_TOPICS: usize = 12;
/// The five labeled parts every pattern topic carries (T-0013 steps 3 and 4).
pub const TOPIC_PARTS: [&str; 5] = [
    "Source:",
    "Problem:",
    "Common solutions:",
    "Pitfalls:",
    "Accessibility and clarity pitfalls:",
];
/// Allowed values of a topic's `Source:` line (T-0013 A2).
pub const SOURCE_VALUES: [&str; 3] = [
    "first principles",
    "operator-supplied",
    "allowlisted public documentation",
];
/// Design requirements DR-01 to DR-20 (T-0013 step 5, A4).
pub const DESIGN_REQUIREMENTS: usize = 20;
/// A duplicated sentence must be longer than this many words (T-0013 copy guard).
pub const COPY_GUARD_WORDS: usize = 12;
/// The pattern review document.
pub const PATTERNS: &str = "docs/UX/PATTERNS.md";
/// The design requirements document.
pub const DESIGN_REQUIREMENTS_FILE: &str = "docs/UX/design-requirements.md";
/// The information architecture document (T-0014).
pub const IA: &str = "docs/UX/IA.md";
/// The machine-readable route table (T-0014).
pub const ROUTES: &str = "docs/UX/routes.toml";
/// Surface values a route may use (spec B2.1).
pub const SURFACES: [&str; 6] = ["public", "app", "admin", "api", "status", "data-plane"];
/// HTTP methods a route may declare.
pub const METHODS: [&str; 6] = ["GET", "HEAD", "POST", "PUT", "PATCH", "DELETE"];
/// Level-2 sections `IA.md` must contain (T-0014 deliverable).
pub const IA_SECTIONS: [&str; 10] = [
    "Surfaces and hosts",
    "URL rules",
    "Identifier format",
    "Deep linking",
    "Redirects",
    "Not found and forbidden",
    "Titles and headings",
    "Token routes",
    "Permission rule",
    "Assumptions",
];
/// Visitor-facing screens that B2.2 marks as data-plane responses rather than URL routes.
pub const DATA_PLANE_SCREENS: [&str; 9] = [
    "S-140", "S-141", "S-142", "S-143", "S-144", "S-145", "S-146", "S-147", "S-148",
];
/// Screens that B2.2 serves at two paths; each needs one route row per path (A1).
pub const SHARED_SCREENS: [&str; 8] = [
    "S-046", "S-059", "S-065", "S-067", "S-070", "S-074", "S-134", "S-136",
];
/// The reserved data-plane prefix; its underscores are allowed in a pattern (spec B2.2).
pub const RESERVED_PREFIX: &str = "/__hdd/";
/// The navigation document (T-0015).
pub const NAVIGATION: &str = "docs/UX/NAVIGATION.md";
/// The journey-map directory (T-0016).
pub const JOURNEYS_DIR: &str = "docs/UX/journeys";
/// The proposed-screens document (T-0016 A5).
pub const SPEC_PATCHES: &str = "docs/UX/spec-patches.md";
/// The journeys this delivery covers (T-0016: J-01 to J-12; T-0017: J-13 to J-24; T-0018: J-25 to J-34).
pub const JOURNEYS_IN_SCOPE: [&str; 34] = [
    "J-01", "J-02", "J-03", "J-04", "J-05", "J-06", "J-07", "J-08", "J-09", "J-10", "J-11", "J-12",
    "J-13", "J-14", "J-15", "J-16", "J-17", "J-18", "J-19", "J-20", "J-21", "J-22", "J-23", "J-24",
    "J-25", "J-26", "J-27", "J-28", "J-29", "J-30", "J-31", "J-32", "J-33", "J-34",
];
/// Level-2 sections every journey map must contain (T-0016 deliverable).
pub const JOURNEY_SECTIONS: [&str; 7] = [
    "Steps",
    "Trust moments",
    "Security considerations",
    "Accessibility considerations",
    "Instrumentation",
    "Success and checks",
    "Missing screens",
];
/// The emotional states allowed in a steps row.
pub const EMOTIONAL_STATES: [&str; 3] = ["calm", "unsure", "anxious"];
/// Org-sidebar items of spec B2.3.
pub const SIDEBAR_ITEMS: [&str; 13] = [
    "Overview",
    "Domains",
    "Live events",
    "Bans",
    "Analytics",
    "Reports",
    "Notifications",
    "Integrations",
    "Team",
    "API keys",
    "Audit log",
    "Plan and usage",
    "Settings",
];
/// Domain tabs of spec B2.3.
pub const DOMAIN_TABS: [&str; 9] = [
    "Overview",
    "DNS",
    "SSL/TLS",
    "Security",
    "Origin",
    "Events",
    "Bans",
    "Analytics",
    "Settings",
];
/// Top-bar controls of spec B2.3.
pub const TOP_BAR_CONTROLS: [&str; 7] = [
    "Org switcher",
    "Domain switcher",
    "Search / command palette",
    "Notification bell",
    "Theme toggle",
    "Help menu",
    "User menu",
];
/// Level-2 sections `NAVIGATION.md` must contain (T-0015 deliverable).
pub const NAV_SECTIONS: [&str; 10] = [
    "Navigation elements",
    "Org and domain switchers",
    "Breadcrumbs",
    "Command palette and shortcuts",
    "Documented conflicts",
    "Restricted items",
    "Admin surface",
    "Focus management",
    "Mobile",
    "Review checklist",
];
/// Subsections of `## Focus management` (A2).
pub const NAV_FOCUS_SUBSECTIONS: [&str; 2] = ["Full page loads", "Partial swaps"];
/// Subsections of `## Mobile` (A4).
pub const NAV_MOBILE_WIDTHS: [&str; 3] = ["360 px", "480 px", "768 px"];

fn finding(location: impl Into<String>, message: impl Into<String>) -> Finding {
    Finding::new(CHECK, location, message)
}

/// GitHub-style heading slug: lower case, letters, digits, `-` and `_` kept, spaces become `-`, the rest dropped.
pub fn slug(heading: &str) -> String {
    heading
        .trim()
        .to_lowercase()
        .chars()
        .filter_map(|c| {
            if c.is_alphanumeric() || c == '-' || c == '_' {
                Some(c)
            } else if c == ' ' {
                Some('-')
            } else {
                None
            }
        })
        .collect()
}

/// Lines of `text` that are outside fenced code blocks, with their 1-based numbers.
fn prose_lines(text: &str) -> Vec<(usize, &str)> {
    let mut out = Vec::new();
    let mut fence: Option<char> = None;
    for (i, line) in text.lines().enumerate() {
        let t = line.trim_start();
        let marker = if t.starts_with("```") {
            Some('`')
        } else if t.starts_with("~~~") {
            Some('~')
        } else {
            None
        };
        match (fence, marker) {
            (None, Some(m)) => fence = Some(m),
            (Some(f), Some(m)) if f == m => fence = None,
            (None, None) => out.push((i + 1, line)),
            _ => {}
        }
    }
    out
}

/// Anchors a Markdown text offers: one per heading outside code blocks, with GitHub's `-1`, `-2` suffix for repeats.
fn anchors(text: &str) -> BTreeSet<String> {
    let mut seen = BTreeSet::new();
    let mut counts = std::collections::BTreeMap::<String, usize>::new();
    for (_, line) in prose_lines(text) {
        let t = line.trim_start();
        let hashes = t.chars().take_while(|c| *c == '#').count();
        if hashes == 0 || hashes > 6 {
            continue;
        }
        let rest = t.get(hashes..).unwrap_or("");
        if !rest.starts_with(' ') {
            continue;
        }
        let base = slug(rest.trim().trim_end_matches('#'));
        let n = counts.entry(base.clone()).or_insert(0);
        let name = if *n == 0 {
            base.clone()
        } else {
            format!("{base}-{n}")
        };
        *n += 1;
        seen.insert(name);
    }
    seen
}

/// Remove inline code spans so that an example link inside backticks is not read as a link.
fn without_code_spans(line: &str) -> String {
    let mut out = String::with_capacity(line.len());
    let mut in_code = false;
    for c in line.chars() {
        if c == '`' {
            in_code = !in_code;
            out.push(' ');
        } else if in_code {
            out.push(' ');
        } else {
            out.push(c);
        }
    }
    out
}

/// Resolve `target` against the directory of `file` without touching the file system. `None` when the path leaves `root`.
fn resolve(file: &Path, target: &str) -> Option<PathBuf> {
    let base = file.parent().unwrap_or_else(|| Path::new(""));
    let mut parts: Vec<std::ffi::OsString> = Vec::new();
    let joined = if target.starts_with('/') {
        PathBuf::from(target.trim_start_matches('/'))
    } else {
        base.join(target)
    };
    for c in joined.components() {
        match c {
            Component::Normal(p) => parts.push(p.to_os_string()),
            Component::ParentDir => {
                parts.pop()?;
            }
            Component::CurDir => {}
            Component::RootDir | Component::Prefix(_) => return None,
        }
    }
    Some(parts.iter().collect())
}

/// Relative links in one Markdown text that do not resolve. `file` is repository-relative.
pub fn broken_links(root: &Path, file: &Path, text: &str) -> Vec<Finding> {
    let mut out = Vec::new();
    let Ok(link) = Regex::new(r#"\[[^\]]*\]\(\s*<?([^)\s>]+)>?(?:\s+"[^"]*")?\s*\)"#) else {
        return out;
    };
    let name = rel(root, file);
    let own_anchors = anchors(text);
    for (n, line) in prose_lines(text) {
        let visible = without_code_spans(line);
        for cap in link.captures_iter(&visible) {
            let Some(raw) = cap.get(1).map(|m| m.as_str()) else {
                continue;
            };
            let loc = format!("{name}:{n}");
            let lower = raw.to_lowercase();
            if lower.starts_with("http://")
                || lower.starts_with("https://")
                || lower.starts_with("mailto:")
                || lower.starts_with("tel:")
            {
                continue;
            }
            let (path_part, fragment) = match raw.split_once('#') {
                Some((p, f)) => (p, Some(f)),
                None => (raw, None),
            };
            if path_part.is_empty() {
                if let Some(f) = fragment
                    && !own_anchors.contains(&f.to_lowercase())
                {
                    out.push(finding(
                        &loc,
                        format!("`#{f}` is not a heading of this document"),
                    ));
                }
                continue;
            }
            let decoded = path_part.replace("%20", " ");
            let Some(resolved) = resolve(file, &decoded) else {
                out.push(finding(
                    &loc,
                    format!("`{raw}` points outside the repository"),
                ));
                continue;
            };
            let full = root.join(&resolved);
            if !full.exists() {
                out.push(finding(
                    &loc,
                    format!("`{raw}` does not exist (looked for {})", rel(root, &full)),
                ));
                continue;
            }
            let is_md = full.is_file()
                && full
                    .extension()
                    .is_some_and(|e| e.eq_ignore_ascii_case("md"));
            if let (Some(f), true) = (fragment, is_md) {
                match read_text(&full) {
                    Ok(t) if anchors(&t).contains(&f.to_lowercase()) => {}
                    Ok(_) => out.push(finding(
                        &loc,
                        format!("`{raw}`: `#{f}` is not a heading of {}", rel(root, &full)),
                    )),
                    Err(e) => out.push(finding(&loc, e.to_string())),
                }
            }
        }
    }
    out
}

/// Cells of a table row (`| a | b |`), trimmed; `None` when the line is not a table row.
fn cells(line: &str) -> Option<Vec<String>> {
    let t = line.trim();
    if !t.starts_with('|') || !t.ends_with('|') || t.len() < 2 {
        return None;
    }
    let inner = t.get(1..t.len() - 1)?;
    let mut out = Vec::new();
    let mut cur = String::new();
    let mut chars = inner.chars().peekable();
    while let Some(c) = chars.next() {
        if c == '\\' && chars.peek() == Some(&'|') {
            cur.push('|');
            chars.next();
        } else if c == '|' {
            out.push(cur.trim().to_owned());
            cur.clear();
        } else {
            cur.push(c);
        }
    }
    out.push(cur.trim().to_owned());
    Some(out)
}

/// Body rows of the first table under the heading `## <title>` (header and separator removed), with line numbers and
/// the header cells. `None` when the section or its table is missing.
fn section_table(text: &str, title: &str) -> Option<Table> {
    let mut in_section = false;
    let mut header: Option<Vec<String>> = None;
    let mut rows = Vec::new();
    for (n, line) in prose_lines(text) {
        let t = line.trim();
        if t.starts_with("## ") {
            if in_section && header.is_some() {
                break;
            }
            in_section = t.trim_start_matches('#').trim().eq_ignore_ascii_case(title);
            continue;
        }
        if !in_section {
            continue;
        }
        let Some(c) = cells(line) else {
            if header.is_some() && !t.is_empty() {
                break;
            }
            continue;
        };
        if header.is_none() {
            header = Some(c);
        } else if c
            .iter()
            .all(|x| !x.is_empty() && x.chars().all(|ch| ch == '-' || ch == ':'))
        {
            continue;
        } else {
            rows.push((n, c));
        }
    }
    header.map(|h| (h, rows))
}

fn column(header: &[String], name: &str) -> Option<usize> {
    header.iter().position(|h| h.eq_ignore_ascii_case(name))
}

/// Structure of `docs/UX/CHARTER.md`.
pub fn charter_findings(text: &str) -> Vec<Finding> {
    let loc = "docs/UX/CHARTER.md";
    let mut out = Vec::new();
    match section_table(text, "Principles") {
        None => out.push(finding(loc, "no `## Principles` section with a table")),
        Some((header, rows)) => {
            let cols = [
                ("Principle", column(&header, "Principle")),
                ("We will", column(&header, "We will")),
                ("We will not", column(&header, "We will not")),
                ("Enforced by", column(&header, "Enforced by")),
            ];
            let mut usable = true;
            for (name, idx) in &cols {
                if idx.is_none() {
                    out.push(finding(
                        loc,
                        format!("the principles table has no `{name}` column"),
                    ));
                    usable = false;
                }
            }
            if rows.len() != PRINCIPLES {
                out.push(finding(
                    loc,
                    format!(
                        "the principles table has {} rows; B11.1 defines seven principles",
                        rows.len()
                    ),
                ));
            }
            if usable {
                for (n, row) in &rows {
                    let who = cols
                        .first()
                        .and_then(|(_, i)| *i)
                        .and_then(|i| row.get(i))
                        .cloned()
                        .unwrap_or_default();
                    for (name, idx) in &cols {
                        let empty = idx.and_then(|i| row.get(i)).is_none_or(|c| c.is_empty());
                        if empty {
                            out.push(finding(
                                format!("{loc}:{n}"),
                                format!("principle `{who}` has an empty `{name}` cell"),
                            ));
                        }
                    }
                }
            }
        }
    }
    let honesty = honesty_tests(text);
    match honesty {
        None => out.push(finding(loc, "no `## Honesty tests` section")),
        Some(list) => {
            if list.len() != HONESTY_TESTS {
                out.push(finding(
                    loc,
                    format!(
                        "the honesty tests are {} items; there must be five",
                        list.len()
                    ),
                ));
            }
            for (n, q) in list {
                if !q.trim_end().ends_with('?') {
                    out.push(finding(
                        format!("{loc}:{n}"),
                        "an honesty test must be phrased as a yes/no question ending in `?`",
                    ));
                }
            }
        }
    }
    let words = text.split_whitespace().count();
    if words > CHARTER_WORD_BUDGET {
        out.push(finding(
            loc,
            format!(
                "{words} words; the charter must fit four printed pages ({CHARTER_WORD_BUDGET} words)"
            ),
        ));
    }
    out
}

/// Numbered items of the `## Honesty tests` section, with line numbers.
fn honesty_tests(text: &str) -> Option<Vec<(usize, String)>> {
    let item = Regex::new(r"^\s*\d+\.\s+(.*)$").ok()?;
    let mut in_section = false;
    let mut found = false;
    let mut out = Vec::new();
    for (n, line) in prose_lines(text) {
        let t = line.trim();
        if t.starts_with("## ") {
            if in_section {
                break;
            }
            in_section = t
                .trim_start_matches('#')
                .trim()
                .eq_ignore_ascii_case("Honesty tests");
            found |= in_section;
            continue;
        }
        if in_section && let Some(c) = item.captures(line) {
            out.push((
                n,
                c.get(1).map(|m| m.as_str().to_owned()).unwrap_or_default(),
            ));
        }
    }
    found.then_some(out)
}

/// Structure of `docs/UX/MEASURES.md`.
pub fn measures_findings(text: &str) -> Vec<Finding> {
    let loc = "docs/UX/MEASURES.md";
    let mut out = Vec::new();
    let Some((header, rows)) = section_table(text, "Measures") else {
        out.push(finding(loc, "no `## Measures` section with a table"));
        return out;
    };
    let cols = [
        ("Measure", column(&header, "Measure")),
        ("Definition", column(&header, "Definition")),
        ("Data source", column(&header, "Data source")),
        ("Privacy treatment", column(&header, "Privacy treatment")),
    ];
    for (name, idx) in &cols {
        if idx.is_none() {
            out.push(finding(
                loc,
                format!("the measures table has no `{name}` column"),
            ));
        }
    }
    if cols.iter().any(|(_, i)| i.is_none()) {
        return out;
    }
    for (n, row) in &rows {
        let who = cols
            .first()
            .and_then(|(_, i)| *i)
            .and_then(|i| row.get(i))
            .cloned()
            .unwrap_or_default();
        for (name, idx) in &cols {
            if idx.and_then(|i| row.get(i)).is_none_or(|c| c.is_empty()) {
                out.push(finding(
                    format!("{loc}:{n}"),
                    format!("measure `{who}` has an empty `{name}` cell"),
                ));
            }
        }
    }
    let names: Vec<String> = rows
        .iter()
        .filter_map(|(_, r)| r.first().map(|c| c.to_lowercase()))
        .collect();
    for (key, full) in MEASURES {
        if !names.iter().any(|n| n.contains(key)) {
            out.push(finding(loc, format!("the measure `{full}` is missing")));
        }
    }
    out
}

/// Structure of one decision record (`id` is the file stem, for example `UXD-001`).
pub fn decision_findings(id: &str, text: &str) -> Vec<Finding> {
    let loc = format!("docs/UX/decisions/{id}.md");
    let mut out = Vec::new();
    let first = text.lines().find(|l| !l.trim().is_empty()).unwrap_or("");
    if !first.starts_with(&format!("# {id}")) {
        out.push(finding(
            &loc,
            format!("the title line must start with `# {id}`"),
        ));
    }
    let status = text
        .lines()
        .find_map(|l| l.strip_prefix("Status:"))
        .map(str::trim);
    match status {
        Some(s) if STATUSES.contains(&s.to_lowercase().as_str()) => {}
        Some(s) => out.push(finding(
            &loc,
            format!("Status `{s}` is not one of {}", STATUSES.join(", ")),
        )),
        None => out.push(finding(&loc, "no `Status:` line")),
    }
    if !text.lines().any(|l| l.starts_with("Date:") && l.len() > 5) {
        out.push(finding(&loc, "no `Date:` line"));
    }
    for section in ["Context", "Decision", "Consequences"] {
        if !text.lines().any(|l| {
            l.trim()
                .strip_prefix("## ")
                .is_some_and(|h| h.trim().eq_ignore_ascii_case(section))
        }) {
            out.push(finding(&loc, format!("no `## {section}` section")));
        }
    }
    out
}

/// The title of a level-2 heading line (`## Title`), or `None` for any other line.
fn heading_title(line: &str) -> Option<&str> {
    line.trim_start().strip_prefix("## ").map(str::trim)
}

/// Text of the header block: every line before the first level-2 heading.
fn header_block(text: &str) -> String {
    let mut out = String::new();
    for line in text.lines() {
        if heading_title(line).is_some() {
            break;
        }
        out.push_str(line);
        out.push('\n');
    }
    out
}

/// Body lines (number and text) of the first `## <title>` section, without the heading itself.
fn section_body(text: &str, title: &str) -> Option<Vec<(usize, String)>> {
    let mut inside = false;
    let mut found = false;
    let mut out = Vec::new();
    for (n, line) in prose_lines(text) {
        if let Some(t) = heading_title(line) {
            if inside {
                break;
            }
            found = t.eq_ignore_ascii_case(title);
            inside = found;
            continue;
        }
        if inside {
            out.push((n, line.to_owned()));
        }
    }
    found.then_some(out)
}

/// Data rows of the first Markdown table among `lines` (header and separator removed), with line numbers.
fn table_rows(lines: &[(usize, String)]) -> Vec<(usize, Vec<String>)> {
    let mut out = Vec::new();
    let mut header_pending = true;
    for (n, line) in lines {
        let Some(row) = cells(line) else { continue };
        if row.is_empty() {
            continue;
        }
        let separator = row
            .iter()
            .all(|c| !c.is_empty() && c.chars().all(|ch| ch == '-' || ch == ':'));
        if separator {
            continue;
        }
        if header_pending {
            header_pending = false;
            continue;
        }
        out.push((*n, row));
    }
    out
}

/// A Markdown table with its header cells and data rows.
struct MdTable {
    header: Vec<String>,
    rows: Vec<(usize, Vec<String>)>,
}

/// Every Markdown table among `lines`, in order (a table is a header row, a separator row and data rows).
fn tables_in(lines: &[(usize, String)]) -> Vec<MdTable> {
    let mut out: Vec<MdTable> = Vec::new();
    let mut index = 0usize;
    while index < lines.len() {
        let Some((_, line)) = lines.get(index) else {
            break;
        };
        let Some(header) = cells(line) else {
            index += 1;
            continue;
        };
        let separator = lines
            .get(index + 1)
            .and_then(|(_, line)| cells(line))
            .is_some_and(|row| {
                !row.is_empty()
                    && row.iter().all(|cell| {
                        !cell.is_empty() && cell.chars().all(|ch| ch == '-' || ch == ':')
                    })
            });
        if header.is_empty() || !separator {
            index += 1;
            continue;
        }
        let mut rows = Vec::new();
        let mut next = index + 2;
        while let Some((n, line)) = lines.get(next) {
            let Some(row) = cells(line) else { break };
            if row.is_empty() {
                break;
            }
            rows.push((*n, row));
            next += 1;
        }
        out.push(MdTable { header, rows });
        index = next;
    }
    out
}

/// The first table whose normalised header equals `wanted`.
fn table_with_header<'a>(tables: &'a [MdTable], wanted: &[&str]) -> Option<&'a MdTable> {
    let needle: Vec<String> = wanted.iter().map(|cell| normalize_keys(cell)).collect();
    tables.iter().find(|table| {
        table
            .header
            .iter()
            .map(|cell| normalize_keys(cell))
            .collect::<Vec<String>>()
            == needle
    })
}

/// Body lines of the first `### <title>` subsection inside `section` (the level-3 heading itself excluded).
fn subsection_body(text: &str, section: &str, subsection: &str) -> Option<Vec<(usize, String)>> {
    let body = section_body(text, section)?;
    let mut inside = false;
    let mut found = false;
    let mut out = Vec::new();
    for (n, line) in body {
        let t = line.trim_start();
        if let Some(title) = t.strip_prefix("### ") {
            if inside {
                break;
            }
            inside = title.trim().eq_ignore_ascii_case(subsection);
            found = inside;
            continue;
        }
        if inside {
            out.push((n, line));
        }
    }
    found.then_some(out)
}

/// Normalised form of a shortcut (`g o`, `Ctrl/Cmd+K`, `Esc`) for set comparisons; backticks are decoration.
fn normalize_keys(text: &str) -> String {
    text.replace('`', "")
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
        .to_lowercase()
}

/// Whether `phrase` appears in `text` as consecutive whole words (case-insensitive).
fn mentions_phrase(text: &str, phrase: &str) -> bool {
    let words: Vec<String> = normalize_keys(text)
        .split_whitespace()
        .map(str::to_owned)
        .collect();
    let needle: Vec<String> = normalize_keys(phrase)
        .split_whitespace()
        .map(str::to_owned)
        .collect();
    !needle.is_empty()
        && words
            .windows(needle.len())
            .any(|window| window == needle.as_slice())
}

/// Content words of a text: lowercased alphanumeric tokens of at least five characters without a short stop list.
fn content_words(text: &str) -> BTreeSet<String> {
    const STOP: [&str; 44] = [
        "about", "after", "again", "also", "because", "before", "being", "between", "could",
        "every", "first", "from", "have", "into", "more", "most", "only", "other", "over", "same",
        "should", "some", "such", "than", "that", "their", "them", "then", "there", "these",
        "they", "this", "those", "through", "under", "until", "very", "were", "what", "when",
        "where", "which", "while", "with",
    ];
    text.split(|c: char| !c.is_alphanumeric())
        .map(str::to_lowercase)
        .filter(|word| word.chars().count() >= 5 && !STOP.contains(&word.as_str()))
        .collect()
}

/// Scenario blocks of the `## Scenarios` section: a level-3 heading starts a scenario, the following lines belong to it.
fn scenario_blocks(lines: &[(usize, String)]) -> Vec<(usize, String)> {
    let mut out: Vec<(usize, String)> = Vec::new();
    for (n, line) in lines {
        if line.trim_start().starts_with("### ") {
            out.push((*n, line.to_owned()));
        } else if let Some((_, last)) = out.last_mut() {
            last.push('\n');
            last.push_str(line);
        }
    }
    out
}

/// Text from the `Measurable outcome:` line to the end of the scenario block, on one line.
fn outcome_text(block: &str) -> Option<String> {
    let re = Regex::new(r"(?i)measurable outcome:").ok()?;
    for (i, line) in block.lines().enumerate() {
        if re.is_match(line) {
            return Some(
                block
                    .lines()
                    .skip(i)
                    .collect::<Vec<_>>()
                    .join(" ")
                    .trim()
                    .to_owned(),
            );
        }
    }
    None
}

/// Remove identifier references that are not measurements (review finding F-4): `J-nn`, `S-nnn`, `ATK-nnn`, `T-nnnn`,
/// `Q-nnn` and `B<n>.<n>`. Their digits must not make a vacuous outcome look measurable.
fn without_identifiers(text: &str) -> String {
    match Regex::new(r"(?i)\b(?:J-\d{2}|S-\d{3}|ATK-\d{3}|T-\d{4}|Q-\d{3}|B\d+\.\d+)\b") {
        Ok(re) => re.replace_all(text, " ").into_owned(),
        Err(_) => text.to_owned(),
    }
}

/// A measurable outcome names an acceptance check, an audit event or a metric, or a number attached to a unit or a
/// comparator (`3 minutes`, `5 clicks`, `100%`, `at most 2`, `under 10 s`, `within 1 day`, `zero`, `0 errors`).
///
/// Identifier references are removed first, so `see J-02` and `it works well` are not measurable (review finding F-4).
fn is_measurable(outcome: &str) -> bool {
    let stripped = without_identifiers(outcome).to_lowercase();
    let id = Regex::new(r"\b(?:ac-\d{2,}|aud-[a-z0-9_.-]+|met-[a-z0-9_]+)\b")
        .is_ok_and(|re| re.is_match(&stripped));
    let unit = Regex::new(
        r"\d+(?:\.\d+)?\s*(?:%|(?:seconds?|minutes?|hours?|days?|weeks?|ms|s|min|h|clicks?|attempts?|requests?|errors?|users?|domains?|rows?|items?|steps?|pages?|events?|times?|percent)\b)",
    )
    .is_ok_and(|re| re.is_match(&stripped));
    let comparator = Regex::new(
        r"\b(?:at most|at least|under|within|over|fewer than|less than|more than|no more than|no fewer than|up to|exactly)\s+\d+",
    )
    .is_ok_and(|re| re.is_match(&stripped));
    let zero = Regex::new(r"\bzero\b").is_ok_and(|re| re.is_match(&stripped));
    id || unit || comparator || zero
}

/// True when one of `lines` is a Markdown list item.
fn has_list_item(lines: &[(usize, String)]) -> bool {
    lines.iter().any(|(_, line)| {
        let t = line.trim_start();
        t.starts_with("- ") || t.starts_with("* ") || t.starts_with("+ ")
    })
}

/// WCAG criteria that `text` names, in the shape the B11.11 table uses (`1.4.4`, `2.1.x`). Whether a token is actually a
/// criterion is decided against the table by [`criterion_is_covered`].
fn criteria_tokens(text: &str) -> BTreeSet<String> {
    let mut out = BTreeSet::new();
    if let Ok(re) = Regex::new(r"\b\d{1,2}\.\d{1,2}\.(?:\d{1,2}|x)\b") {
        for m in re.find_iter(text) {
            out.insert(m.as_str().to_owned());
        }
    }
    out
}

/// ATK ids of the attack coverage matrix (spec C5), read from the master specification text.
///
/// Only table rows of the registry count: a prose mention of an id is not an entry (this is the distinction T-0313's
/// `attack-matrix check` will make with its own parser).
pub fn attack_registry(spec: &str) -> BTreeSet<String> {
    let mut ids = BTreeSet::new();
    let Ok(re) = Regex::new(r"^\| (ATK-\d{3}) \|") else {
        return ids;
    };
    for line in spec.lines() {
        if let Some(id) = re.captures(line).and_then(|c| c.get(1)) {
            ids.insert(id.as_str().to_owned());
        }
    }
    ids
}

/// Shape of a criterion as the B11.11 table writes it (`1.4.4`, `1.3.x`).
fn criterion_shape(text: &str) -> bool {
    Regex::new(r"^\d{1,2}\.\d{1,2}\.(?:\d{1,2}|x)$").is_ok_and(|re| re.is_match(text))
}

/// Criteria of the B11.11 accessibility table (the table's "Criterion" column), read from the master specification text.
///
/// Entries look like `1.4.3 / 1.4.11` or `2.1.x`; every part is kept. An `x` entry covers every criterion with that
/// prefix (see [`criterion_is_covered`]).
pub fn b11_11_criteria(spec: &str) -> BTreeSet<String> {
    let mut out = BTreeSet::new();
    let mut inside = false;
    let mut column: Option<usize> = None;
    for line in spec.lines() {
        let t = line.trim_start();
        if t.starts_with("### ") || t.starts_with("## ") {
            if inside {
                break;
            }
            inside = t.trim_start_matches('#').trim().starts_with("B11.11");
            continue;
        }
        if !inside {
            continue;
        }
        let Some(row) = cells(line) else { continue };
        let separator = row
            .iter()
            .all(|c| !c.is_empty() && c.chars().all(|ch| ch == '-' || ch == ':'));
        if separator {
            continue;
        }
        match column {
            None => {
                column = row.iter().position(|c| c.eq_ignore_ascii_case("Criterion"));
            }
            Some(index) => {
                let Some(cell) = row.get(index) else {
                    continue;
                };
                for part in cell.split('/') {
                    let criterion = part.trim();
                    if criterion_shape(criterion) {
                        out.insert(criterion.to_owned());
                    }
                }
            }
        }
    }
    out
}

/// True when `criterion` is named by, or covered by an `x` entry of, the B11.11 table (for example `2.1.x` covers
/// `2.1.1`). A criterion the table does not cover is not part of the accessibility contract (A3).
pub fn criterion_is_covered(criterion: &str, criteria: &BTreeSet<String>) -> bool {
    if criteria.contains(criterion) {
        return true;
    }
    let mut parts = criterion.split('.');
    let (Some(major), Some(minor), Some(_patch)) = (parts.next(), parts.next(), parts.next())
    else {
        return false;
    };
    if parts.next().is_some() {
        return false;
    }
    criteria.contains(&format!("{major}.{minor}.x"))
}

/// Declared `Key journeys` of one persona table in the master specification (`persona_heading` is the heading id, for
/// example `B1.1`). B1.7 (the adversary) has no row and returns the empty set (F-7).
pub fn key_journeys(spec: &str, persona_heading: &str) -> BTreeSet<String> {
    let mut out = BTreeSet::new();
    let mut inside = false;
    for line in spec.lines() {
        let t = line.trim_start();
        if t.starts_with("### ") || t.starts_with("## ") {
            if inside {
                break;
            }
            let title = t.trim_start_matches('#').trim();
            inside = title.split_whitespace().next() == Some(persona_heading);
            continue;
        }
        if !inside {
            continue;
        }
        let Some(row) = cells(line) else { continue };
        let Some(first) = row.first() else {
            continue;
        };
        if first.eq_ignore_ascii_case("Key journeys") {
            if let Some(list) = row.get(1) {
                out = journey_list(list);
            }
            return out;
        }
    }
    out
}

/// Journey ids of one `Key journeys` cell: `J-nn`, `J-a/J-b` and `J-a to J-b` forms (F-7).
fn journey_list(cell: &str) -> BTreeSet<String> {
    let mut out = BTreeSet::new();
    for token in cell.split(',') {
        let token = token.trim();
        if let Some((first, last)) = journey_range(token) {
            for number in first..=last {
                out.insert(format!("J-{number:02}"));
            }
        } else {
            for part in token.split('/') {
                let part = part.trim();
                if journey_number(part).is_some() {
                    out.insert(part.to_owned());
                }
            }
        }
    }
    out
}

/// `J-29 to J-31` expanded to `(29, 31)`.
fn journey_range(token: &str) -> Option<(usize, usize)> {
    let re = Regex::new(r"(?i)^\s*J-(\d{2})\s+to\s+J-(\d{2})\s*$").ok()?;
    let caps = re.captures(token)?;
    let first: usize = caps.get(1)?.as_str().parse().ok()?;
    let last: usize = caps.get(2)?.as_str().parse().ok()?;
    (first <= last).then_some((first, last))
}

/// The number of a `J-nn` id, or `None` when the text is not one.
fn journey_number(token: &str) -> Option<usize> {
    let re = Regex::new(r"^J-(\d{2})$").ok()?;
    re.captures(token)?.get(1)?.as_str().parse().ok()
}

/// Journeys a persona file lists in its `Journeys and screens` section (F-7).
fn persona_journey_list(text: &str) -> BTreeSet<String> {
    let mut out = BTreeSet::new();
    let Some(body) = section_body(text, "Journeys and screens") else {
        return out;
    };
    let joined = body
        .iter()
        .map(|(_, line)| line.as_str())
        .collect::<Vec<_>>()
        .join("\n");
    if let Ok(re) = Regex::new(r"\bJ-\d{2}\b") {
        for m in re.find_iter(&joined) {
            out.insert(m.as_str().to_owned());
        }
    }
    out
}

/// Persona files linked from each journey row of the matrix (F-7).
fn matrix_persona_links(text: &str) -> BTreeMap<String, BTreeSet<String>> {
    let mut out: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    let (Ok(journey_re), Ok(link_re)) = (
        Regex::new(r"\bJ-\d{2}\b"),
        Regex::new(r"\[[^\]]*\]\(([^)\s]+)\)"),
    ) else {
        return out;
    };
    for (_, line) in prose_lines(text) {
        let Some(row) = cells(line) else { continue };
        let Some(id) = row
            .first()
            .and_then(|cell| journey_re.find(cell))
            .map(|m| m.as_str().to_owned())
        else {
            continue;
        };
        let entry = out.entry(id).or_default();
        for cap in link_re.captures_iter(line) {
            let Some(target) = cap.get(1).map(|m| m.as_str()) else {
                continue;
            };
            let path = target.split('#').next().unwrap_or(target);
            let Some(name) = path.strip_prefix("personas/") else {
                continue;
            };
            let stem = name.strip_suffix(".md").unwrap_or(name);
            if PERSONAS.contains(&stem) {
                entry.insert(stem.to_owned());
            }
        }
    }
    out
}

/// Declared key journeys of B1.1 to B1.6 cross-checked against the persona files and the matrix (F-7).
///
/// A persona must list every journey the specification declares for it, and the matrix row of every journey it lists
/// (declared or not) must link it. The matrix may link more personas than a file lists; that direction is allowed.
fn key_journey_findings(
    declared: &BTreeMap<String, BTreeSet<String>>,
    listed: &BTreeMap<String, BTreeSet<String>>,
    matrix: &BTreeMap<String, BTreeSet<String>>,
) -> Vec<Finding> {
    let mut out = Vec::new();
    for (stem, heading) in PERSONA_HEADINGS {
        let declared_persona = declared.get(stem).cloned().unwrap_or_default();
        let listed_persona = listed.get(stem).cloned().unwrap_or_default();
        for journey in &declared_persona {
            if !listed_persona.contains(journey) {
                out.push(finding(
                    format!("docs/UX/personas/{stem}.md"),
                    format!(
                        "persona {stem} does not list {journey} in its `Journeys and screens` section, but spec {heading} declares it as a key journey"
                    ),
                ));
            }
        }
        let mut all: BTreeSet<String> = declared_persona.clone();
        all.extend(listed_persona.iter().cloned());
        for journey in &all {
            let linked = matrix
                .get(journey)
                .is_some_and(|stems| stems.contains(stem));
            if linked {
                continue;
            }
            let message = if declared_persona.contains(journey) {
                format!(
                    "the matrix row for {journey} does not link persona {stem}, whose key journeys include it (spec {heading})"
                )
            } else {
                format!(
                    "persona {stem} lists {journey}, but the matrix row for {journey} does not link it"
                )
            };
            out.push(finding(MATRIX, message));
        }
    }
    out
}

/// Structure of one persona document (`stem` is the file stem, for example `maya`): the fictional-composite header, the
/// context of use, three scenarios with measurable outcomes, anti-goals, accessibility mapped to B11.11 and cross-links
/// to journeys and screens (T-0012 A1, A3 and steps 1 to 6).
pub fn persona_findings(stem: &str, text: &str, b11_11: Option<&BTreeSet<String>>) -> Vec<Finding> {
    let loc = format!("docs/UX/personas/{stem}.md");
    let mut out = Vec::new();
    if !header_block(text)
        .to_lowercase()
        .contains("fictional composite")
    {
        out.push(finding(
            &loc,
            "the header must say the persona is a fictional composite (B1 note, R-16)",
        ));
    }
    match section_body(text, "Context of use") {
        None => out.push(finding(
            &loc,
            "no `## Context of use` section (T-0012 step 1)",
        )),
        Some(body) => {
            let rows = table_rows(&body);
            for label in CONTEXT_ROWS {
                let present = rows
                    .iter()
                    .any(|(_, row)| row.first().is_some_and(|c| c.eq_ignore_ascii_case(label)));
                if !present {
                    out.push(finding(
                        &loc,
                        format!("the context of use has no `{label}` row (T-0012 step 1)"),
                    ));
                }
            }
        }
    }
    match section_body(text, "Scenarios") {
        None => out.push(finding(
            &loc,
            "no `## Scenarios` section with three scenarios (T-0012 step 2)",
        )),
        Some(body) => {
            let blocks = scenario_blocks(&body);
            if blocks.len() < MIN_SCENARIOS {
                out.push(finding(
                    &loc,
                    format!(
                        "the persona has {} scenario(s); at least three scenarios are required (A1)",
                        blocks.len()
                    ),
                ));
            }
            for (n, block) in &blocks {
                let flat = block
                    .split_whitespace()
                    .collect::<Vec<_>>()
                    .join(" ")
                    .to_lowercase();
                for (needle, what) in [
                    ("when ", "`When ...`"),
                    (", i want to ", "`, I want to ...`"),
                    (", so i can ", "`, so I can ...`"),
                ] {
                    if !flat.contains(needle) {
                        out.push(finding(
                            format!("{loc}:{n}"),
                            format!(
                                "a scenario is not in the form `When ..., I want to ..., so I can ...` (T-0012 step 2): no {what}"
                            ),
                        ));
                    }
                }
                match outcome_text(block) {
                    None => out.push(finding(
                        format!("{loc}:{n}"),
                        "a scenario has no measurable outcome (T-0012 step 2): add `Measurable outcome: <result>`",
                    )),
                    Some(outcome) if !is_measurable(&outcome) => out.push(finding(
                        format!("{loc}:{n}"),
                        "a scenario's measurable outcome names no `AC-`, `AUD-` or `MET-` id and no number with a unit or comparator (T-0012 A1)",
                    )),
                    Some(_) => {}
                }
            }
        }
    }
    match section_body(text, "Anti-goals") {
        None => out.push(finding(&loc, "no `## Anti-goals` section (T-0012 step 3)")),
        Some(body) if !has_list_item(&body) => out.push(finding(
            &loc,
            "the `## Anti-goals` section has no list items (T-0012 step 3)",
        )),
        Some(_) => {}
    }
    match section_body(text, "Accessibility") {
        None => out.push(finding(
            &loc,
            "no `## Accessibility` section (T-0012 step 4)",
        )),
        Some(body) => {
            let joined = body
                .iter()
                .map(|(_, l)| l.as_str())
                .collect::<Vec<_>>()
                .join("\n");
            if !joined.contains("B11.11") {
                out.push(finding(
                    &loc,
                    "the accessibility section must map to the B11.11 criteria (A3)",
                ));
            }
            let cited = criteria_tokens(&joined);
            if let Some(table) = b11_11 {
                let mut covered = 0;
                for criterion in &cited {
                    if criterion_is_covered(criterion, table) {
                        covered += 1;
                    } else {
                        out.push(finding(
                            &loc,
                            format!("`{criterion}` is not a criterion of the B11.11 table (A3)"),
                        ));
                    }
                }
                if covered < 2 {
                    out.push(finding(
                        &loc,
                        format!(
                            "the accessibility section names {covered} covered B11.11 criteria; at least two criteria are required (A3)"
                        ),
                    ));
                }
            }
        }
    }
    match section_body(text, "Journeys and screens") {
        None => out.push(finding(
            &loc,
            "no `## Journeys and screens` section (T-0012 step 6)",
        )),
        Some(body) => {
            let joined = body
                .iter()
                .map(|(_, l)| l.as_str())
                .collect::<Vec<_>>()
                .join("\n");
            let has = |pattern: &str| Regex::new(pattern).is_ok_and(|re| re.is_match(&joined));
            if !has(r"\bJ-\d{2}\b") {
                out.push(finding(
                    &loc,
                    "the journeys and screens section names no journey (J-nn) (T-0012 step 6)",
                ));
            }
            if !has(r"\bS-\d{3}\b") {
                out.push(finding(
                    &loc,
                    "the journeys and screens section names no screen (S-nnn) (T-0012 step 6)",
                ));
            }
        }
    }
    out
}

/// Abuse stories of the adversary document: at least ten distinct `ATK-nnn` references, each an entry of the attack
/// coverage matrix (T-0012 A4). `registry` is `None` when the master specification could not be read; the finding for
/// that is reported once by [`check`], so membership is skipped to avoid repeating it per id.
pub fn adversary_findings(text: &str, registry: Option<&BTreeSet<String>>) -> Vec<Finding> {
    let loc = format!("docs/UX/personas/{ADVERSARY}.md");
    let mut out = Vec::new();
    let mut ids = BTreeSet::new();
    if let Ok(re) = Regex::new(r"\bATK-\d{3}\b") {
        for m in re.find_iter(text) {
            ids.insert(m.as_str().to_owned());
        }
    }
    if ids.len() < MIN_ABUSE_STORIES {
        out.push(finding(
            &loc,
            format!(
                "{} distinct ATK references; the adversary file needs at least ten abuse stories mapped to the attack coverage matrix (A4)",
                ids.len()
            ),
        ));
    }
    if let Some(registry) = registry {
        for id in &ids {
            if !registry.contains(id) {
                out.push(finding(
                    &loc,
                    format!("`{id}` is not an id of the attack coverage matrix (C5)"),
                ));
            }
        }
    }
    out
}

/// Completeness of `docs/UX/persona-journey-matrix.md`: every journey J-01 to J-34 appears once and links to one of the
/// seven persona files; no id outside the B3 range is invented (T-0012 A2).
pub fn matrix_findings(text: &str) -> Vec<Finding> {
    let loc = MATRIX;
    let mut out = Vec::new();
    let (Ok(journey_re), Ok(link_re)) = (
        Regex::new(r"\bJ-\d{2}\b"),
        Regex::new(r"\[[^\]]*\]\(([^)\s]+)\)"),
    ) else {
        return out;
    };
    let mut seen: BTreeSet<String> = BTreeSet::new();
    for (n, line) in prose_lines(text) {
        let Some(row) = cells(line) else { continue };
        let Some(id) = row
            .first()
            .and_then(|cell| journey_re.find(cell))
            .map(|m| m.as_str().to_owned())
        else {
            continue;
        };
        let number: usize = id
            .get(2..)
            .and_then(|digits| digits.parse::<usize>().ok())
            .unwrap_or(0);
        if number == 0 || number > JOURNEYS {
            out.push(finding(
                format!("{loc}:{n}"),
                format!("the matrix names {id}, which is not a journey of B3 (J-01 to J-34)"),
            ));
            continue;
        }
        if !seen.insert(id.clone()) {
            out.push(finding(
                format!("{loc}:{n}"),
                format!("the matrix lists {id} more than once"),
            ));
        }
        let mut linked = false;
        for cap in link_re.captures_iter(line) {
            let Some(target) = cap.get(1).map(|m| m.as_str()) else {
                continue;
            };
            let path = target.split('#').next().unwrap_or(target);
            let Some(name) = path.strip_prefix("personas/") else {
                continue;
            };
            let stem = name.strip_suffix(".md").unwrap_or(name);
            if PERSONAS.contains(&stem) {
                linked = true;
            } else {
                out.push(finding(
                    format!("{loc}:{n}"),
                    format!(
                        "{id} links to `{target}`, which is not one of the seven persona files"
                    ),
                ));
            }
        }
        if !linked {
            out.push(finding(
                format!("{loc}:{n}"),
                format!("the matrix row for {id} links to no persona file (A2)"),
            ));
        }
    }
    for journey in 1..=JOURNEYS {
        let id = format!("J-{journey:02}");
        if !seen.contains(&id) {
            out.push(finding(
                loc,
                format!("journey {id} is not linked to a persona (A2)"),
            ));
        }
    }
    out
}

/// The primary-persona question in `docs/OPERATOR-QUESTIONS.md`: present in the section titled `Primary persona for the
/// pilot`, defaulting to Maya, and marked OPEN (A5).
///
/// The numbered Appendix E8 register is frozen at its 58 verbatim questions, so a question added by a later task lives in
/// its own section of the register. Only that section is read: a row elsewhere in the register that happens to mention
/// both "persona" and "primary" is not the primary-persona question and must not be bound by mistake (review round 2).
pub fn primary_persona_findings(register: &str) -> Vec<Finding> {
    let loc = "docs/OPERATOR-QUESTIONS.md";
    let mut inside = false;
    let mut found_section = false;
    let mut header: Option<Vec<String>> = None;
    let mut matched: Option<(usize, Vec<String>, Vec<String>)> = None;
    for (n, line) in prose_lines(register) {
        if let Some(title) = heading_title(line) {
            if inside {
                break;
            }
            inside = title
                .to_lowercase()
                .starts_with("primary persona for the pilot");
            found_section |= inside;
            continue;
        }
        if !inside {
            continue;
        }
        let Some(row) = cells(line) else {
            header = None;
            continue;
        };
        let separator = row
            .iter()
            .all(|c| !c.is_empty() && c.chars().all(|ch| ch == '-' || ch == ':'));
        if separator {
            continue;
        }
        let Some(table_header) = header.as_ref() else {
            header = Some(row);
            continue;
        };
        let joined = row.join(" ").to_lowercase();
        if joined.contains("persona") && joined.contains("primary") {
            matched = Some((n, table_header.clone(), row));
            break;
        }
    }
    if !found_section {
        return vec![finding(
            loc,
            "the register has no primary-persona question for the pilot (A5)",
        )];
    }
    let Some((n, table_header, row)) = matched else {
        return vec![finding(
            loc,
            "the register's `Primary persona for the pilot` section has no primary-persona row (A5)",
        )];
    };
    let column = |name: &str| {
        table_header
            .iter()
            .position(|h| h.to_lowercase().contains(name))
    };
    let cell = |name: &str, row: &[String]| -> String {
        match column(name) {
            Some(i) => row.get(i).cloned().unwrap_or_default(),
            None => row.join(" "),
        }
        .to_lowercase()
    };
    let mut out = Vec::new();
    if !cell("default", &row).contains("maya") {
        out.push(finding(
            format!("{loc}:{n}"),
            "the primary-persona question has no default; the default is Maya, the site owner (B1.1)",
        ));
    }
    if !cell("state", &row).contains("open") {
        out.push(finding(
            format!("{loc}:{n}"),
            "the primary-persona question is not marked OPEN (A5)",
        ));
    }
    out
}

/// Mojibake markers left behind when a UTF-8 document is read as cp1252 and written back: `â€` (the start of an
/// em dash) and `Ã` (the start of a wrongly decoded accented character).
pub const MOJIBAKE: [&str; 2] = ["â€", "Ã"];

/// Findings for mojibake sequences in one persona or matrix document (review finding F-3 of T-0012).
///
/// A document written or re-written through a cp1252 view of its bytes carries `â€` where an em dash was and `Ã` where an
/// accented character was. Both markers mean the file was not written as UTF-8 without a byte-order mark; the fix is to
/// write the file again, in UTF-8, with the character spelled out (` - `, `,` or `:`), never to re-decode it.
pub fn mojibake_findings(location: &str, text: &str) -> Vec<Finding> {
    let mut out = Vec::new();
    for (n, line) in text.lines().enumerate() {
        for marker in MOJIBAKE {
            if line.contains(marker) {
                out.push(finding(
                    format!("{location}:{}", n + 1),
                    format!(
                        "the document contains a mojibake sequence `{marker}` (UTF-8 text read as cp1252); write the file as UTF-8 without a byte-order mark"
                    ),
                ));
            }
        }
    }
    out
}

/// The `Status:` line of a document: the text after `Status:` on the first such line before the first level-2 heading.
fn status_line(text: &str) -> Option<(usize, String)> {
    for (n, line) in text.lines().enumerate() {
        if heading_title(line).is_some() {
            break;
        }
        if let Some(rest) = line.trim().strip_prefix("Status:") {
            return Some((n + 1, rest.trim().to_owned()));
        }
    }
    None
}

/// True when a status value is `PASS` or `UNVERIFIED(<non-empty reason>)` (T-0013 A5).
fn status_is_valid(value: &str) -> bool {
    if status_is_pass(value) {
        return true;
    }
    let Some(rest) = value.strip_prefix("UNVERIFIED(") else {
        return false;
    };
    rest.split_once(')')
        .is_some_and(|(reason, _)| !reason.trim().is_empty())
}

/// True when a status value states `PASS`.
fn status_is_pass(value: &str) -> bool {
    value == "PASS" || value.starts_with("PASS ")
}

/// One `## Topic: <name>` section of `PATTERNS.md`: the name, its heading line and its body lines.
struct PatternTopic<'a> {
    /// Topic name after `Topic:`.
    name: String,
    /// 1-based line number of the heading.
    line: usize,
    /// Body lines with their 1-based numbers.
    body: Vec<(usize, &'a str)>,
}

/// Topic sections of `PATTERNS.md`: level-2 headings titled `Topic: <name>` with their body lines.
fn pattern_topics(text: &str) -> Vec<PatternTopic<'_>> {
    let mut out: Vec<PatternTopic<'_>> = Vec::new();
    let mut inside = false;
    for (n, line) in prose_lines(text) {
        if let Some(title) = heading_title(line) {
            inside = false;
            if let Some(name) = title.strip_prefix("Topic:").map(str::trim) {
                out.push(PatternTopic {
                    name: name.to_owned(),
                    line: n,
                    body: Vec::new(),
                });
                inside = true;
            }
            continue;
        }
        if inside && let Some(topic) = out.last_mut() {
            topic.body.push((n, line));
        }
    }
    out
}

/// Structure of `docs/UX/PATTERNS.md` (T-0013 A1, A2, A5): the status line, at least twelve topics, the five labeled parts
/// of each topic, allowed `Source:` values, and `PASS` only when a source was fetched.
pub fn patterns_findings(text: &str) -> Vec<Finding> {
    let loc = PATTERNS;
    let mut out = Vec::new();
    match status_line(text) {
        None => out.push(finding(loc, "no `Status:` line at the top (T-0013 A5)")),
        Some((n, value)) if !status_is_valid(&value) => out.push(finding(
            format!("{loc}:{n}"),
            format!(
                "the `Status:` value `{value}` is neither `PASS` nor `UNVERIFIED(<reason>)` (T-0013 A5)"
            ),
        )),
        Some(_) => {}
    }
    let topics = pattern_topics(text);
    if topics.len() < MIN_PATTERN_TOPICS {
        out.push(finding(
            loc,
            format!(
                "{} topic entries; at least {MIN_PATTERN_TOPICS} are required (T-0013 A1)",
                topics.len()
            ),
        ));
    }
    let mut sources: Vec<String> = Vec::new();
    for topic in &topics {
        let name = &topic.name;
        let n = topic.line;
        let body = &topic.body;
        for part in TOPIC_PARTS {
            let present = body
                .iter()
                .any(|(_, line)| line.trim_start().starts_with(part));
            if !present {
                out.push(finding(
                    format!("{loc}:{n}"),
                    format!("topic `{name}` has no `{part}` part (T-0013 steps 3 and 4)"),
                ));
            }
        }
        if let Some((line_no, value)) = body.iter().find_map(|(body_n, line)| {
            line.trim_start()
                .strip_prefix("Source:")
                .map(|rest| (*body_n, rest.trim().to_owned()))
        }) {
            if SOURCE_VALUES.contains(&value.as_str()) {
                sources.push(value);
            } else {
                out.push(finding(
                    format!("{loc}:{line_no}"),
                    format!(
                        "topic `{name}` has Source `{value}`, not one of {} (T-0013 A2)",
                        SOURCE_VALUES.join(" / ")
                    ),
                ));
            }
        }
    }
    if let Some((_, value)) = &status_line(text)
        && status_is_pass(value)
        && !topics.is_empty()
        && sources.iter().all(|source| source == "first principles")
    {
        out.push(finding(
            loc,
            "the status is PASS but every topic cites first principles and no source was fetched; the review must be UNVERIFIED(capability_not_supplied) (T-0013 A5)",
        ));
    }
    match section_body(text, "Honesty-test review") {
        None => out.push(finding(
            loc,
            "no `## Honesty-test review` section (T-0013 step 7)",
        )),
        Some(body) => {
            let rows = table_rows(&body);
            if rows.len() != HONESTY_TESTS {
                out.push(finding(
                    loc,
                    format!(
                        "the honesty-test review has {} rows; exactly five are required (T-0013 step 7)",
                        rows.len()
                    ),
                ));
            }
            for (n, row) in &rows {
                let answer = row
                    .get(2)
                    .map(|cell| cell.trim().to_lowercase())
                    .unwrap_or_default();
                let reason = row.get(3).map(|cell| cell.trim()).unwrap_or("");
                if answer != "yes" && answer != "no" {
                    out.push(finding(
                        format!("{loc}:{n}"),
                        format!(
                            "the honesty-test answer `{answer}` must be Yes or No (T-0013 step 7)"
                        ),
                    ));
                } else if answer == "no" {
                    out.push(finding(
                        format!("{loc}:{n}"),
                        "the honesty-test review answers No; a No blocks the change and the document cannot ship (T-0013 step 7)",
                    ));
                }
                if reason.is_empty() {
                    out.push(finding(
                        format!("{loc}:{n}"),
                        "the honesty-test review row has an empty Reason cell (T-0013 step 7)",
                    ));
                }
            }
        }
    }
    out
}

/// Lines of the first spec section whose heading id equals `heading` (for example `B11.8`), without the heading.
fn spec_section<'a>(spec: &'a str, heading: &str) -> Vec<(usize, &'a str)> {
    let mut inside = false;
    let mut out = Vec::new();
    for (n, line) in spec.lines().enumerate() {
        let t = line.trim_start();
        if t.starts_with("### ") || t.starts_with("## ") {
            if inside {
                break;
            }
            let title = t.trim_start_matches('#').trim();
            inside = title.split_whitespace().next() == Some(heading);
            continue;
        }
        if inside {
            out.push((n + 1, line));
        }
    }
    out
}

/// Screen ids of the spec B12.1 screen table (`S-nnn`, ranges expanded).
pub fn screen_ids(spec: &str) -> BTreeSet<String> {
    let mut out = BTreeSet::new();
    let (Ok(range_re), Ok(id_re)) = (
        Regex::new(r"S-(\d{3})\s+to\s+S-(\d{3})"),
        Regex::new(r"S-\d{3}"),
    ) else {
        return out;
    };
    for (_, line) in spec_section(spec, "B12.1") {
        for cap in range_re.captures_iter(line) {
            let first: usize = cap
                .get(1)
                .and_then(|m| m.as_str().parse().ok())
                .unwrap_or(0);
            let last: usize = cap
                .get(2)
                .and_then(|m| m.as_str().parse().ok())
                .unwrap_or(0);
            for number in first..=last {
                out.insert(format!("S-{number:03}"));
            }
        }
        for m in id_re.find_iter(line) {
            out.insert(m.as_str().to_owned());
        }
    }
    out
}

/// Component names of the spec B11.8 component inventory.
pub fn component_names(spec: &str) -> BTreeSet<String> {
    let mut out = BTreeSet::new();
    let Ok(paren) = Regex::new(r"\([^)]*\)") else {
        return out;
    };
    for (_, line) in spec_section(spec, "B11.8") {
        let Some(row) = cells(line) else { continue };
        let Some(first) = row.first() else { continue };
        if first.eq_ignore_ascii_case("Component") {
            continue;
        }
        if first.chars().all(|c| c == '-' || c == ':') {
            continue;
        }
        let stripped = paren.replace_all(first, "");
        for part in stripped.split('/') {
            let name = part.trim();
            if !name.is_empty() {
                out.insert(name.to_owned());
            }
        }
    }
    out
}

/// True when `cell` names `component` as a whole token. A component name inside a longer word (`DataTableOfDoom`,
/// `Linked`) is not a reference to that component (review finding F-8).
fn names_component(cell: &str, component: &str) -> bool {
    Regex::new(&format!(r"\b{}\b", regex::escape(component))).is_ok_and(|re| re.is_match(cell))
}

/// Structure of `docs/UX/design-requirements.md` (T-0013 A4): DR-01 to DR-20 once each, a rationale, a PATTERNS.md topic
/// anchor that exists, and an existing screen or component.
pub fn design_requirement_findings(
    text: &str,
    patterns: Option<&str>,
    screens: Option<&BTreeSet<String>>,
    components: Option<&BTreeSet<String>>,
) -> Vec<Finding> {
    let loc = DESIGN_REQUIREMENTS_FILE;
    let mut out = Vec::new();
    let Ok(screen_re) = Regex::new(r"\bS-\d{3}\b") else {
        return out;
    };
    if let Some(screens) = screens {
        for (n, line) in text.lines().enumerate() {
            for m in screen_re.find_iter(line) {
                if !screens.contains(m.as_str()) {
                    out.push(finding(
                        format!("{loc}:{}", n + 1),
                        format!(
                            "`{}` is not a screen of the spec B12.1 screen table (T-0013 A4)",
                            m.as_str()
                        ),
                    ));
                }
            }
        }
    }
    let (Ok(dr_re), Ok(link_re)) = (
        Regex::new(r"^DR-(\d{2})$"),
        Regex::new(r"\[[^\]]*\]\(([^)\s]+)\)"),
    ) else {
        return out;
    };
    let anchor_set = patterns.map(anchors);
    let mut seen: BTreeSet<String> = BTreeSet::new();
    for (n, line) in text.lines().enumerate() {
        let Some(row) = cells(line) else { continue };
        let Some(first) = row.first().map(|cell| cell.trim()) else {
            continue;
        };
        let Some(caps) = dr_re.captures(first) else {
            continue;
        };
        let number: usize = caps
            .get(1)
            .and_then(|m| m.as_str().parse().ok())
            .unwrap_or(0);
        if number == 0 || number > DESIGN_REQUIREMENTS {
            out.push(finding(
                format!("{loc}:{}", n + 1),
                format!(
                    "{first} is not one of DR-01 to DR-{DESIGN_REQUIREMENTS:02} (T-0013 step 5)"
                ),
            ));
            continue;
        }
        let id = format!("DR-{number:02}");
        if !seen.insert(id.clone()) {
            out.push(finding(
                format!("{loc}:{}", n + 1),
                format!("{id} appears more than once (T-0013 A4)"),
            ));
        }
        if row
            .get(2)
            .is_none_or(|rationale| rationale.trim().is_empty())
        {
            out.push(finding(
                format!("{loc}:{}", n + 1),
                format!("{id} has an empty rationale (T-0013 step 5)"),
            ));
        }
        let mut linked = false;
        for cap in link_re.captures_iter(line) {
            let Some(target) = cap.get(1).map(|m| m.as_str()) else {
                continue;
            };
            let (path, fragment) = match target.split_once('#') {
                Some((path, fragment)) => (path, Some(fragment)),
                None => (target, None),
            };
            if path.trim() != "PATTERNS.md" {
                continue;
            }
            linked = true;
            match (fragment, anchor_set.as_ref()) {
                (Some(fragment), Some(anchors)) if !anchors.contains(&fragment.to_lowercase()) => {
                    out.push(finding(
                        format!("{loc}:{}", n + 1),
                        format!(
                            "{id} links `PATTERNS.md#{fragment}`, which is not a heading of PATTERNS.md (T-0013 A4)"
                        ),
                    ));
                }
                (None, _) => out.push(finding(
                    format!("{loc}:{}", n + 1),
                    format!("{id} links PATTERNS.md without a topic anchor (T-0013 A4)"),
                )),
                _ => {}
            }
        }
        if !linked {
            out.push(finding(
                format!("{loc}:{}", n + 1),
                format!("{id} does not link a PATTERNS.md topic (T-0013 A4)"),
            ));
        }
        let target_cell = row.get(4).cloned().unwrap_or_default();
        let has_screen = screens.is_some_and(|screens| {
            screen_re
                .find_iter(&target_cell)
                .any(|m| screens.contains(m.as_str()))
        });
        let has_component = components.is_some_and(|components| {
            components
                .iter()
                .any(|name| names_component(&target_cell, name))
        });
        if (screens.is_some() || components.is_some()) && !has_screen && !has_component {
            out.push(finding(
                format!("{loc}:{}", n + 1),
                format!("{id} names no screen (S-nnn) or component from the spec (T-0013 A4)"),
            ));
        }
    }
    for number in 1..=DESIGN_REQUIREMENTS {
        let id = format!("DR-{number:02}");
        if !seen.contains(&id) {
            out.push(finding(loc, format!("{id} is missing (T-0013 A4)")));
        }
    }
    out
}

/// True when a line is a Markdown list item (bulleted or numbered).
fn is_list_item(line: &str) -> bool {
    let t = line.trim_start();
    if t.starts_with("- ") || t.starts_with("* ") || t.starts_with("+ ") {
        return true;
    }
    let digits = t.chars().take_while(|c| c.is_ascii_digit()).count();
    digits > 0 && t.get(digits..).is_some_and(|rest| rest.starts_with(". "))
}

/// Sentences of a Markdown document longer than [`COPY_GUARD_WORDS`], with whitespace normalised.
fn long_sentences(text: &str) -> BTreeSet<String> {
    let mut out = BTreeSet::new();
    let Ok(split) = Regex::new(r"[.!?]\s+") else {
        return out;
    };
    let mut paragraph = String::new();
    let consider = |chunk: &str, out: &mut BTreeSet<String>| {
        for part in split.split(chunk) {
            let sentence = part
                .trim_end_matches(['.', '!', '?'])
                .split_whitespace()
                .collect::<Vec<_>>()
                .join(" ");
            if sentence.split_whitespace().count() > COPY_GUARD_WORDS {
                out.insert(sentence);
            }
        }
    };
    for (_, line) in prose_lines(text) {
        let t = line.trim();
        if t.is_empty() {
            if !paragraph.is_empty() {
                consider(&paragraph, &mut out);
                paragraph.clear();
            }
            continue;
        }
        if t.starts_with('#') || t.starts_with('|') || t.starts_with('>') || is_list_item(t) {
            if !paragraph.is_empty() {
                consider(&paragraph, &mut out);
                paragraph.clear();
            }
            if t.starts_with('|') {
                for cell in t.split('|') {
                    consider(cell, &mut out);
                }
            } else {
                consider(t, &mut out);
            }
        } else {
            if !paragraph.is_empty() {
                paragraph.push(' ');
            }
            paragraph.push_str(t);
        }
    }
    if !paragraph.is_empty() {
        consider(&paragraph, &mut out);
    }
    out
}

/// The self-copy guard (T-0013 tests): a sentence longer than [`COPY_GUARD_WORDS`] that appears verbatim in more than one
/// UX document.
pub fn self_copy_findings(docs: &[(&str, &str)]) -> Vec<Finding> {
    let mut by_sentence: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    for (path, text) in docs {
        for sentence in long_sentences(text) {
            by_sentence
                .entry(sentence)
                .or_default()
                .insert((*path).to_owned());
        }
    }
    let mut out = Vec::new();
    for (sentence, paths) in by_sentence {
        if paths.len() > 1 {
            out.push(finding(
                "docs/UX",
                format!(
                    "a sentence of more than {COPY_GUARD_WORDS} words appears verbatim in {} documents ({}): \"{sentence}\"",
                    paths.len(),
                    paths.iter().cloned().collect::<Vec<_>>().join(", ")
                ),
            ));
        }
    }
    out
}

/// One `[[route]]` of `docs/UX/routes.toml` (T-0014).
#[derive(Debug, Clone, Deserialize)]
pub struct RouteEntry {
    /// URL pattern, for example `/app/o/{org}/domains`.
    pub pattern: String,
    /// Screen id (`S-nnn`), `support` or `data-plane`.
    pub screen: String,
    /// One of [`SURFACES`].
    pub surface: String,
    /// A `PERM-` id of spec B4.2 or `public`.
    pub permission: String,
    /// One or more of [`METHODS`].
    pub methods: Vec<String>,
    /// One of the spec B6.1 rate-limit classes.
    pub rate_limit_class: String,
    /// Optional explanation.
    #[serde(default)]
    pub note: Option<String>,
}

/// The array of routes in `routes.toml` (`[[route]]`).
#[derive(Debug, Clone, Deserialize)]
struct RoutesFile {
    route: Vec<RouteEntry>,
}

/// Backticked code spans of one line, trimmed.
fn code_spans(text: &str) -> Vec<String> {
    text.split('`')
        .skip(1)
        .step_by(2)
        .map(|span| span.trim().to_owned())
        .filter(|span| !span.is_empty())
        .collect()
}

/// Whole-token `S-nnn` ids in `text`.
fn s_tokens(text: &str) -> Vec<String> {
    let mut out = Vec::new();
    if let Ok(re) = Regex::new(r"\bS-\d{3}\b") {
        for m in re.find_iter(text) {
            out.push(m.as_str().to_owned());
        }
    }
    out
}

/// Permission ids of the spec B4.2 catalog.
pub fn permission_ids(spec: &str) -> BTreeSet<String> {
    let mut out = BTreeSet::new();
    for (_, line) in spec_section(spec, "B4.2") {
        let Some(row) = cells(line) else { continue };
        let Some(first) = row.first() else { continue };
        let id = first.trim();
        if id.starts_with("PERM-") {
            out.insert(id.to_owned());
        }
    }
    out
}

/// Rate-limit classes named by spec B6.1.
pub fn rate_limit_classes(spec: &str) -> BTreeSet<String> {
    let mut out = BTreeSet::new();
    for line in spec.lines() {
        if let Some(rest) = line.trim().strip_prefix("- Rate limit classes:") {
            for class in code_spans(rest) {
                out.insert(class);
            }
        }
    }
    out
}

/// Patterns listed under `## Token routes` of `IA.md` (backticked patterns that carry a `{token}` parameter).
pub fn token_route_patterns(ia: &str) -> BTreeSet<String> {
    let mut out = BTreeSet::new();
    let Some(body) = section_body(ia, "Token routes") else {
        return out;
    };
    for (_, line) in &body {
        for span in code_spans(line) {
            if span.starts_with('/') && span.contains("{token}") {
                out.insert(span);
            }
        }
    }
    out
}

/// Pattern rules of T-0014: lowercase, no underscore outside a placeholder, no trailing slash except `/`, no `?`, no `@`,
/// no literal token-like segment of 20 or more characters, no `{email}`, and no unlisted `{token}` parameter (A5).
fn pattern_findings(at: &str, pattern: &str, token_patterns: &BTreeSet<String>) -> Vec<Finding> {
    let mut out = Vec::new();
    if pattern.chars().any(|c| c.is_uppercase()) {
        out.push(finding(
            at,
            format!("pattern `{pattern}` contains an uppercase letter"),
        ));
    }
    if pattern != "/" && pattern.ends_with('/') {
        out.push(finding(
            at,
            format!("pattern `{pattern}` has a trailing slash"),
        ));
    }
    if pattern.contains('?') {
        out.push(finding(at, format!("pattern `{pattern}` contains a `?`")));
    }
    if pattern.contains('@') {
        out.push(finding(at, format!("pattern `{pattern}` contains an `@`")));
    }
    if pattern.contains("{email}") {
        out.push(finding(
            at,
            format!("pattern `{pattern}` contains an email placeholder"),
        ));
    }
    if pattern.contains("{token}") && !token_patterns.contains(pattern) {
        out.push(finding(
            at,
            format!(
                "pattern `{pattern}` carries a `token` parameter but is not listed in the `## Token routes` section of {IA} (A5)"
            ),
        ));
    }
    let mut literal = String::new();
    let mut depth = 0usize;
    for c in pattern.chars() {
        match c {
            '{' => depth += 1,
            '}' => depth = depth.saturating_sub(1),
            _ if depth == 0 => literal.push(c),
            _ => {}
        }
    }
    let without_prefix = literal.replace(RESERVED_PREFIX, "/");
    if without_prefix.contains('_') {
        out.push(finding(
            at,
            format!("pattern `{pattern}` contains an underscore outside a placeholder"),
        ));
    }
    let mut run = 0usize;
    let mut longest = 0usize;
    for c in without_prefix.chars() {
        if c.is_ascii_alphanumeric() {
            run += 1;
            longest = longest.max(run);
        } else {
            run = 0;
        }
    }
    if longest >= 20 {
        out.push(finding(
            at,
            format!(
                "pattern `{pattern}` contains a literal token-like segment of {longest} characters"
            ),
        ));
    }
    out
}

/// The `## Rate-class exceptions` table of `IA.md`: pattern to the non-GET methods allowed a read-like class (F-10c).
pub fn rate_class_exceptions(ia: &str) -> BTreeMap<String, BTreeSet<String>> {
    let mut out: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    let Some(body) = section_body(ia, "Rate-class exceptions") else {
        return out;
    };
    for (_, row) in table_rows(&body) {
        let pattern_cell = row
            .first()
            .map(|cell| cell.trim().to_owned())
            .unwrap_or_default();
        let pattern = code_spans(&pattern_cell)
            .into_iter()
            .next()
            .unwrap_or(pattern_cell);
        let methods: BTreeSet<String> = row
            .get(1)
            .map(|cell| {
                cell.split(|c: char| c == ',' || c.is_whitespace())
                    .map(|part| part.trim().to_uppercase())
                    .filter(|part| !part.is_empty())
                    .collect()
            })
            .unwrap_or_default();
        if pattern.starts_with('/') && !methods.is_empty() {
            out.entry(pattern).or_default().extend(methods);
        }
    }
    out
}

/// Checks of `docs/UX/routes.toml`: keys and values, permissions, screen coverage, pattern rules, token parameters,
/// duplicate pattern/method sets and the cross-key consistency rules (T-0014 A1, A2, A5; review finding F-10).
pub fn routes_findings(
    routes: &str,
    screens: &BTreeSet<String>,
    permissions: &BTreeSet<String>,
    classes: &BTreeSet<String>,
    token_patterns: &BTreeSet<String>,
    rate_exceptions: &BTreeMap<String, BTreeSet<String>>,
) -> Vec<Finding> {
    let loc = ROUTES;
    let mut out = Vec::new();
    let file: RoutesFile = match toml::from_str(routes) {
        Ok(file) => file,
        Err(e) => {
            out.push(finding(
                loc,
                format!("the route table cannot be parsed as TOML with [[route]] entries: {e}"),
            ));
            return out;
        }
    };
    if file.route.is_empty() {
        out.push(finding(
            loc,
            "the route table has no [[route]] entries (T-0014 A1)",
        ));
        return out;
    }
    let screen_re = Regex::new(r"^S-\d{3}$").ok();
    let mut screen_counts: BTreeMap<String, usize> = BTreeMap::new();
    let mut data_plane_marks: BTreeMap<String, usize> = BTreeMap::new();
    let mut pattern_methods: BTreeMap<String, usize> = BTreeMap::new();
    for (index, route) in file.route.iter().enumerate() {
        let at = format!("{loc}: route {index}");
        if !SURFACES.contains(&route.surface.as_str()) {
            out.push(finding(
                &at,
                format!(
                    "surface `{}` is not one of {}",
                    route.surface,
                    SURFACES.join(", ")
                ),
            ));
        }
        if route.permission != "public" && !permissions.contains(&route.permission) {
            out.push(finding(
                &at,
                format!(
                    "permission `{}` is not an id of the B4.2 catalog and is not `public` (A2)",
                    route.permission
                ),
            ));
        }
        if route.methods.is_empty() {
            out.push(finding(&at, "the route declares no method"));
        }
        for method in &route.methods {
            if !METHODS.contains(&method.as_str()) {
                out.push(finding(
                    &at,
                    format!("method `{method}` is not one of {}", METHODS.join(", ")),
                ));
            }
        }
        if !classes.contains(&route.rate_limit_class) {
            out.push(finding(
                &at,
                format!(
                    "rate-limit class `{}` is not one of the B6.1 classes",
                    route.rate_limit_class
                ),
            ));
        }
        // F-10a: a `public` permission on a surface that expects a session.
        if route.permission == "public" {
            if route.surface == "admin" || route.surface == "api" {
                out.push(finding(
                    &at,
                    format!(
                        "the `public` permission is not allowed on the `{}` surface (F-10a)",
                        route.surface
                    ),
                ));
            } else if route.surface == "app"
                && route.rate_limit_class != "auth"
                && route.rate_limit_class != "public"
            {
                out.push(finding(
                    &at,
                    format!(
                        "`public` on the `app` surface is allowed only with class `auth` or `public`, not `{}` (F-10a)",
                        route.rate_limit_class
                    ),
                ));
            }
        }
        // F-10b: platform permissions belong to the admin surface, and the admin surface needs one.
        if route.permission.starts_with("PERM-platform.") && route.surface != "admin" {
            out.push(finding(
                &at,
                format!(
                    "`{}` is a platform permission and is allowed only on the `admin` surface (F-10b)",
                    route.permission
                ),
            ));
        }
        if route.surface == "admin" && !route.permission.starts_with("PERM-platform.") {
            let admin_login = route.permission == "public" && route.rate_limit_class == "auth";
            if !admin_login {
                out.push(finding(
                    &at,
                    "an `admin` route must carry a `PERM-platform.*` permission, or be `public` with class `auth` (F-10b)",
                ));
            }
        }
        // F-10c: the rate-limit class must fit the methods, unless IA lists the pattern and method as an exception.
        let mutating_methods: Vec<&String> = route
            .methods
            .iter()
            .filter(|method| !matches!(method.as_str(), "GET" | "HEAD"))
            .collect();
        if mutating_methods.is_empty() {
            if route.rate_limit_class == "write" {
                out.push(finding(
                    &at,
                    format!(
                        "route `{}` is GET/HEAD only but has rate-limit class `write` (F-10c)",
                        route.pattern
                    ),
                ));
            }
        } else {
            let exempt = mutating_methods.iter().all(|method| {
                rate_exceptions
                    .get(&route.pattern)
                    .is_some_and(|methods| methods.contains(method.as_str()))
            });
            if !matches!(route.rate_limit_class.as_str(), "write" | "auth" | "export") && !exempt {
                out.push(finding(
                    &at,
                    format!(
                        "route `{}` takes a non-GET method but has rate-limit class `{}`; use write, auth or export, or list the pattern and method under `Rate-class exceptions` (F-10c)",
                        route.pattern, route.rate_limit_class
                    ),
                ));
            }
        }
        out.extend(pattern_findings(&at, &route.pattern, token_patterns));
        let note_tokens = route.note.as_deref().map(s_tokens).unwrap_or_default();
        for token in &note_tokens {
            if !screens.contains(token) {
                out.push(finding(
                    &at,
                    format!("the note cites `{token}`, which is not a screen of B12.1"),
                ));
            }
        }
        let screen = route.screen.trim();
        if screen == "support" {
            // A support route (robots.txt, health probe, and so on).
        } else if screen == "data-plane" {
            if route.surface != "data-plane" {
                out.push(finding(
                    &at,
                    "a route with screen `data-plane` must use surface `data-plane`",
                ));
            }
            let marked: Vec<&String> = note_tokens
                .iter()
                .filter(|token| DATA_PLANE_SCREENS.contains(&token.as_str()))
                .collect();
            if marked.is_empty() {
                out.push(finding(
                    &at,
                    "a data-plane route needs a note naming the visitor-facing screens it serves (A1)",
                ));
            }
            for token in marked {
                *data_plane_marks.entry(token.clone()).or_insert(0) += 1;
            }
        } else if screen_re.as_ref().is_some_and(|re| re.is_match(screen)) {
            if !screens.contains(screen) {
                out.push(finding(
                    &at,
                    format!("`{screen}` is not a screen of the B12.1 screen table"),
                ));
            } else if DATA_PLANE_SCREENS.contains(&screen) {
                out.push(finding(
                    &at,
                    format!(
                        "`{screen}` is a visitor-facing screen; mark it with a data-plane route instead of using it as a route screen"
                    ),
                ));
            } else {
                *screen_counts.entry(screen.to_owned()).or_insert(0) += 1;
            }
        } else {
            out.push(finding(
                &at,
                format!("screen `{screen}` must be an S-nnn id, `support` or `data-plane`"),
            ));
        }
        let mut methods = route.methods.clone();
        methods.sort();
        methods.dedup();
        *pattern_methods
            .entry(format!("{}|{}", route.pattern, methods.join(",")))
            .or_insert(0) += 1;
    }
    let mut declared_methods: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    for route in &file.route {
        declared_methods
            .entry(route.pattern.clone())
            .or_default()
            .extend(route.methods.iter().cloned());
    }
    for (pattern, methods) in rate_exceptions {
        for method in methods {
            let matched = declared_methods
                .get(pattern)
                .is_some_and(|declared| declared.contains(method));
            if !matched {
                out.push(finding(
                    loc,
                    format!(
                        "the `Rate-class exceptions` entry for `{pattern}` {method} does not match any route (F-10c)"
                    ),
                ));
            }
        }
    }
    for screen in screens {
        if DATA_PLANE_SCREENS.contains(&screen.as_str()) {
            if data_plane_marks.get(screen).copied().unwrap_or(0) == 0 {
                out.push(finding(
                    loc,
                    format!("screen {screen} is not marked by any data-plane route note (A1)"),
                ));
            }
            continue;
        }
        let count = screen_counts.get(screen).copied().unwrap_or(0);
        if SHARED_SCREENS.contains(&screen.as_str()) {
            if count != 2 {
                out.push(finding(
                    loc,
                    format!(
                        "screen {screen} appears {count} time(s); B2.2 serves it at two paths, so two route rows are required (A1)"
                    ),
                ));
            }
        } else if count != 1 {
            out.push(finding(
                loc,
                format!(
                    "screen {screen} appears {count} time(s); exactly one route row is required (A1)"
                ),
            ));
        }
    }
    for (key, count) in pattern_methods {
        if count > 1 {
            let pattern = key.split('|').next().unwrap_or("");
            out.push(finding(
                loc,
                format!("the same pattern and method set appears {count} times (`{pattern}`)"),
            ));
        }
    }
    out
}

/// Checks of `docs/UX/IA.md`: required sections, `Test:` lines under the URL rules, and the identifier regex with its
/// worked example (T-0014 A3, A4).
pub fn ia_findings(text: &str) -> Vec<Finding> {
    let loc = IA;
    let mut out = Vec::new();
    for section in IA_SECTIONS {
        if section_body(text, section).is_none() {
            out.push(finding(
                loc,
                format!("no `## {section}` section (T-0014 deliverable)"),
            ));
        }
    }
    if let Some(body) = section_body(text, "URL rules") {
        let mut rules = 0usize;
        let mut tests = 0usize;
        for (_, line) in &body {
            let t = line.trim_start();
            if t.starts_with("- ") || t.starts_with("* ") {
                rules += 1;
            } else {
                let digits = t.chars().take_while(|c| c.is_ascii_digit()).count();
                if digits > 0 && t.get(digits..).is_some_and(|rest| rest.starts_with(". ")) {
                    rules += 1;
                }
            }
            if t.starts_with("Test:") {
                tests += 1;
            }
        }
        if tests < rules {
            out.push(finding(
                loc,
                format!(
                    "the URL rules have {rules} rules but {tests} `Test:` lines; each rule needs one (A3)"
                ),
            ));
        }
    }
    if let Some(body) = section_body(text, "Rate-class exceptions") {
        let rows = table_rows(&body);
        if rows.is_empty() {
            out.push(finding(
                loc,
                "the `Rate-class exceptions` section has no table rows (F-10c)",
            ));
        }
        for (n, row) in &rows {
            let pattern_cell = row
                .first()
                .map(|cell| cell.trim().to_owned())
                .unwrap_or_default();
            let pattern = code_spans(&pattern_cell)
                .into_iter()
                .next()
                .unwrap_or(pattern_cell);
            let method = row
                .get(1)
                .map(|cell| cell.trim().to_uppercase())
                .unwrap_or_default();
            let reason = row.get(2).map(|cell| cell.trim()).unwrap_or("");
            if !pattern.starts_with('/') {
                out.push(finding(
                    format!("{loc}:{n}"),
                    format!(
                        "the `Rate-class exceptions` pattern `{pattern}` must start with `/` (F-10c)"
                    ),
                ));
            }
            if !METHODS.contains(&method.as_str()) {
                out.push(finding(
                    format!("{loc}:{n}"),
                    format!(
                        "the `Rate-class exceptions` method `{method}` is not one of {} (F-10c)",
                        METHODS.join(", ")
                    ),
                ));
            }
            if reason.is_empty() {
                out.push(finding(
                    format!("{loc}:{n}"),
                    "a `Rate-class exceptions` row needs a reason (F-10c)",
                ));
            }
        }
    }
    if let Some(body) = section_body(text, "Identifier format") {
        let mut regex_text: Option<String> = None;
        let mut example: Option<String> = None;
        for (_, line) in &body {
            let t = line.trim_start();
            if regex_text.is_none() && t.starts_with("Regex:") {
                regex_text = code_spans(t).into_iter().next();
            }
            if example.is_none() && t.starts_with("Example:") {
                example = code_spans(t).into_iter().next();
            }
        }
        let Some(regex_text) = regex_text else {
            out.push(finding(
                loc,
                "the identifier format has no `Regex:` line (A4)",
            ));
            return out;
        };
        let Some(example) = example else {
            out.push(finding(
                loc,
                "the identifier format has no `Example:` line (A4)",
            ));
            return out;
        };
        match Regex::new(&regex_text) {
            Err(e) => out.push(finding(
                loc,
                format!("the identifier regex does not compile: {e}"),
            )),
            Ok(re) => {
                if !re.is_match(&example) {
                    out.push(finding(
                        loc,
                        format!(
                            "the worked example `{example}` does not match the identifier regex"
                        ),
                    ));
                }
            }
        }
    }
    out
}

/// The shortcuts of spec B2.3, read from the master specification and normalised for comparison (T-0015 A5).
pub fn shortcut_list(spec: &str) -> BTreeSet<String> {
    let mut out = BTreeSet::new();
    let Ok(key_re) = Regex::new(r"[A-Za-z]+/[A-Za-z]+\+[A-Za-z0-9]") else {
        return out;
    };
    for (_, line) in spec_section(spec, "B2.3") {
        if line.to_lowercase().contains("keyboard shortcuts") {
            for span in code_spans(line) {
                out.insert(normalize_keys(&span));
            }
        }
        for found in key_re.find_iter(line) {
            out.insert(normalize_keys(found.as_str()));
        }
    }
    out
}

/// Checks of `docs/UX/NAVIGATION.md`: required sections and subsections, the elements table against `routes.toml`, the
/// shortcut map against the reserved list and spec B2.3, the restricted-item states, focus management, mobile widths and
/// the no-hover rule (T-0015 A1 to A5).
pub fn navigation_findings(
    text: &str,
    route_permissions: &BTreeMap<String, String>,
    b23_shortcuts: &BTreeSet<String>,
) -> Vec<Finding> {
    let loc = NAVIGATION;
    let mut out = Vec::new();
    for section in NAV_SECTIONS {
        if section_body(text, section).is_none() {
            out.push(finding(
                loc,
                format!("no `## {section}` section (T-0015 deliverable)"),
            ));
        }
    }
    let mut sidebar_seen: BTreeSet<String> = BTreeSet::new();
    let mut tab_seen: BTreeSet<String> = BTreeSet::new();
    let mut control_seen: BTreeSet<String> = BTreeSet::new();
    let mut element_names: BTreeSet<String> = BTreeSet::new();
    if let Some(body) = section_body(text, "Navigation elements") {
        let tables = tables_in(&body);
        let wanted = [
            "element",
            "route",
            "permission",
            "keyboard",
            "aria role",
            "notes",
        ];
        match tables.iter().find(|table| {
            table
                .header
                .iter()
                .map(|cell| normalize_keys(cell))
                .eq(wanted)
        }) {
            None => out.push(finding(
                loc,
                "the `Navigation elements` section has no table with columns Element | Route | Permission | Keyboard | ARIA role | Notes (A1)",
            )),
            Some(table) => {
                for (n, row) in &table.rows {
                    let at = format!("{loc}:{n}");
                    if row.len() < 6 {
                        out.push(finding(
                            &at,
                            "an elements row needs six cells: Element | Route | Permission | Keyboard | ARIA role | Notes (A1)",
                        ));
                        continue;
                    }
                    let element = row.first().map_or("", |cell| cell.trim());
                    let keyboard = row.get(3).map_or("", |cell| cell.trim());
                    let aria = row.get(4).map_or("", |cell| cell.trim());
                    if keyboard.is_empty() {
                        out.push(finding(
                            &at,
                            format!("the `Keyboard` cell of `{element}` is empty (A1)"),
                        ));
                    }
                    if aria.is_empty() {
                        out.push(finding(
                            &at,
                            format!("the `ARIA role` cell of `{element}` is empty (A1)"),
                        ));
                    }
                    let normalized = normalize_keys(element);
                    let mut kind = "row";
                    if let Some(name) = normalized.strip_prefix("sidebar · ") {
                        kind = "sidebar item";
                        element_names.insert(normalize_keys(name));
                        if let Some(item) = SIDEBAR_ITEMS
                            .iter()
                            .find(|item| normalize_keys(item) == name)
                        {
                            sidebar_seen.insert((*item).to_owned());
                        } else {
                            out.push(finding(
                                &at,
                                format!("`{element}` is not an org-sidebar item of B2.3"),
                            ));
                        }
                    } else if let Some(name) = normalized.strip_prefix("tab · ") {
                        kind = "tab";
                        element_names.insert(normalize_keys(name));
                        if let Some(item) =
                            DOMAIN_TABS.iter().find(|item| normalize_keys(item) == name)
                        {
                            tab_seen.insert((*item).to_owned());
                        } else {
                            out.push(finding(
                                &at,
                                format!("`{element}` is not a domain tab of B2.3"),
                            ));
                        }
                    } else if let Some(name) = normalized.strip_prefix("top bar · ") {
                        kind = "top-bar control";
                        element_names.insert(normalize_keys(name));
                        if let Some(item) = TOP_BAR_CONTROLS
                            .iter()
                            .find(|item| normalize_keys(item) == name)
                        {
                            control_seen.insert((*item).to_owned());
                        } else {
                            out.push(finding(
                                &at,
                                format!("`{element}` is not a top-bar control of B2.3"),
                            ));
                        }
                    }
                    let route = row
                        .get(1)
                        .map_or("", |cell| cell.trim().trim_matches('`').trim());
                    let permission = row
                        .get(2)
                        .map_or("", |cell| cell.trim().trim_matches('`').trim());
                    if route == "-" {
                        if kind != "row" && kind != "top-bar control" {
                            out.push(finding(
                                &at,
                                format!(
                                    "the {kind} `{element}` names no route; a sidebar item or tab needs one (A1)"
                                ),
                            ));
                        }
                    } else {
                        match route_permissions.get(route) {
                            None => out.push(finding(
                                &at,
                                format!("route `{route}` is not in routes.toml (A1)"),
                            )),
                            Some(known) if known != permission => out.push(finding(
                                &at,
                                format!(
                                    "permission `{permission}` of `{element}` differs from the route's permission `{known}` for `{route}` in routes.toml (A1)"
                                ),
                            )),
                            Some(_) => {}
                        }
                    }
                }
            }
        }
    }
    element_names.insert("search control".to_owned());
    element_names.insert("command palette".to_owned());
    for item in SIDEBAR_ITEMS {
        if !sidebar_seen.contains(item) {
            out.push(finding(
                loc,
                format!("the sidebar item `{item}` has no row in the elements table (A1)"),
            ));
        }
    }
    for item in DOMAIN_TABS {
        if !tab_seen.contains(item) {
            out.push(finding(
                loc,
                format!("the domain tab `{item}` has no row in the elements table (A1)"),
            ));
        }
    }
    for item in TOP_BAR_CONTROLS {
        if !control_seen.contains(item) {
            out.push(finding(
                loc,
                format!("the top-bar control `{item}` has no row in the elements table (A1)"),
            ));
        }
    }
    if let Some(body) = section_body(text, "Restricted items") {
        let tables = tables_in(&body);
        let wanted = ["state", "when", "display", "example"];
        match tables.iter().find(|table| {
            table
                .header
                .iter()
                .map(|cell| normalize_keys(cell))
                .eq(wanted)
        }) {
            None => out.push(finding(
                loc,
                "the `Restricted items` section has no table with columns State | When | Display | Example (A3)",
            )),
            Some(table) => {
                let states: BTreeSet<String> = table
                    .rows
                    .iter()
                    .filter_map(|(_, row)| row.first().map(|cell| normalize_keys(cell)))
                    .collect();
                for state in ["permission-hidden", "plan-limited"] {
                    if !states.contains(state) {
                        out.push(finding(
                            loc,
                            format!(
                                "the `Restricted items` table has no `{state}` row (A3)"
                            ),
                        ));
                    }
                }
            }
        }
    }
    let mut map_keys: BTreeMap<String, usize> = BTreeMap::new();
    if let Some(body) = section_body(text, "Command palette and shortcuts") {
        let prose = body
            .iter()
            .map(|(_, line)| line.as_str())
            .collect::<Vec<_>>()
            .join(" ")
            .to_lowercase();
        if !prose.contains("convenience") || !prose.contains("only path") {
            out.push(finding(
                loc,
                "the `Command palette and shortcuts` section does not say that shortcuts are conveniences and never the only path (F-11)",
            ));
        }
        let tables = tables_in(&body);
        let map = tables.iter().find(|table| {
            table
                .header
                .iter()
                .map(|cell| normalize_keys(cell))
                .eq(["keys", "action", "scope"])
        });
        let reserved = tables.iter().find(|table| {
            table
                .header
                .first()
                .is_some_and(|cell| normalize_keys(cell) == "keys")
                && !table
                    .header
                    .iter()
                    .map(|cell| normalize_keys(cell))
                    .eq(["keys", "action", "scope"])
        });
        if let Some(map) = map {
            for (n, row) in &map.rows {
                let at = format!("{loc}:{n}");
                if row.len() < 3 {
                    out.push(finding(
                        &at,
                        "a shortcut row needs three cells: Keys | Action | Scope (A5)",
                    ));
                    continue;
                }
                let keys = row.first().map_or("", |cell| cell.trim());
                if keys.is_empty() {
                    out.push(finding(&at, "a shortcut row has an empty `Keys` cell (A5)"));
                    continue;
                }
                let normalized = normalize_keys(keys);
                let count = map_keys.entry(normalized).or_insert(0);
                *count += 1;
                if *count > 1 {
                    out.push(finding(
                        &at,
                        format!("the shortcut `{keys}` appears twice in the shortcut map (A5)"),
                    ));
                }
            }
            for expected in b23_shortcuts {
                if !map_keys.contains_key(expected) {
                    out.push(finding(
                        loc,
                        format!("the shortcut map is missing the B2.3 shortcut `{expected}` (A5)"),
                    ));
                }
            }
            if let Some(reserved) = reserved {
                if reserved.rows.len() < 10 {
                    out.push(finding(
                loc,
                format!(
                    "the `Reserved by browsers and assistive technology` table has {} rows; at least ten are required (A5)",
                    reserved.rows.len()
                ),
            ));
                }
                let reserved_keys: BTreeSet<String> = reserved
                    .rows
                    .iter()
                    .filter_map(|(_, row)| row.first().map(|cell| normalize_keys(cell)))
                    .collect();
                for key in map_keys.keys() {
                    if reserved_keys.contains(key) {
                        out.push(finding(
                    loc,
                    format!(
                        "the shortcut `{key}` is both in the map and in the `Reserved by browsers and assistive technology` table (A5)"
                    ),
                ));
                    }
                }
            } else {
                out.push(finding(
                loc,
                "the `Command palette and shortcuts` section has no `Reserved by browsers and assistive technology` table (A5)",
            ));
            }
        } else {
            out.push(finding(
                loc,
                "the `Command palette and shortcuts` section has no table with columns Keys | Action | Scope (A5)",
            ));
        }
    }
    if let Some(body) = section_body(text, "Documented conflicts") {
        let tables = tables_in(&body);
        let wanted = ["keys", "owner of the default", "effect", "mitigation"];
        match tables.iter().find(|table| {
            table
                .header
                .iter()
                .map(|cell| normalize_keys(cell))
                .eq(wanted)
        }) {
            None => out.push(finding(
                loc,
                "the `Documented conflicts` section has no table with columns Keys | Owner of the default | Effect | Mitigation (F-11)",
            )),
            Some(table) => {
                let mut documented: BTreeSet<String> = BTreeSet::new();
                for (n, row) in &table.rows {
                    let at = format!("{loc}:{n}");
                    if row.len() < 4 {
                        out.push(finding(
                            &at,
                            "a `Documented conflicts` row needs four cells (F-11)",
                        ));
                        continue;
                    }
                    let keys_cell = row.first().map_or("", |cell| cell.trim());
                    let owner = row.get(1).map_or("", |cell| cell.trim());
                    let effect = row.get(2).map_or("", |cell| cell.trim());
                    let mitigation = row.get(3).map_or("", |cell| cell.trim());
                    let mut keys: BTreeSet<String> = code_spans(keys_cell)
                        .into_iter()
                        .map(|span| normalize_keys(&span))
                        .collect();
                    if keys.is_empty() && !keys_cell.is_empty() {
                        keys.insert(normalize_keys(keys_cell));
                    }
                    if keys.is_empty() {
                        out.push(finding(
                            &at,
                            "a `Documented conflicts` row has no keys (F-11)",
                        ));
                    }
                    if owner.is_empty() {
                        out.push(finding(
                            &at,
                            "a `Documented conflicts` row has an empty `Owner of the default` cell (F-11)",
                        ));
                    }
                    if effect.is_empty() {
                        out.push(finding(
                            &at,
                            "a `Documented conflicts` row has an empty `Effect` cell (F-11)",
                        ));
                    }
                    if mitigation.is_empty() {
                        out.push(finding(
                            &at,
                            "a `Documented conflicts` row has an empty `Mitigation` cell (F-11)",
                        ));
                    } else {
                        if !element_names
                            .iter()
                            .any(|name| mentions_phrase(mitigation, name))
                        {
                            out.push(finding(
                                &at,
                                format!(
                                    "the `Mitigation` of `{keys_cell}` does not name an element of the `Navigation elements` table, the search control or the command palette (F-11)"
                                ),
                            ));
                        }
                        let words: Vec<String> = normalize_keys(mitigation)
                            .split_whitespace()
                            .map(str::to_owned)
                            .collect();
                        let names_shortcut = words
                            .iter()
                            .any(|word| word == "shortcut" || word == "shortcuts");
                        if !names_shortcut || !words.iter().any(|word| word == "off") {
                            out.push(finding(
                                &at,
                                format!(
                                    "the `Mitigation` of `{keys_cell}` does not say that shortcuts can be turned off (F-11)"
                                ),
                            ));
                        }
                    }
                    for key in &keys {
                        documented.insert(key.clone());
                        let related = map_keys.contains_key(key)
                            || (key.chars().count() == 1
                                && map_keys
                                    .keys()
                                    .any(|map_key| map_key.starts_with(&format!("{key} "))));
                        if !related {
                            out.push(finding(
                                &at,
                                format!(
                                    "the `Documented conflicts` row `{key}` is stale: it is not in the shortcut map (F-11)"
                                ),
                            ));
                        }
                    }
                }
                for key in map_keys.keys() {
                    let single = key.chars().count() == 1;
                    if (key == "ctrl/cmd+k" || key == "/" || key == "?" || single)
                        && !documented.contains(key)
                    {
                        out.push(finding(
                            loc,
                            format!(
                                "the shortcut `{key}` has a browser or screen-reader default but no row in `Documented conflicts` (F-11)"
                            ),
                        ));
                    }
                }
            }
        }
    }
    for subsection in NAV_FOCUS_SUBSECTIONS {
        if subsection_body(text, "Focus management", subsection).is_none() {
            out.push(finding(
                loc,
                format!("the `Focus management` section has no `### {subsection}` subsection (A2)"),
            ));
        }
    }
    for width in NAV_MOBILE_WIDTHS {
        if subsection_body(text, "Mobile", width).is_none() {
            out.push(finding(
                loc,
                format!("the `Mobile` section has no `### {width}` subsection (A4)"),
            ));
        }
    }
    for (n, line) in text.lines().enumerate() {
        if cells(line).is_some() {
            let lower = line.to_lowercase();
            if lower.contains("hover") && !lower.contains("keyboard") && !lower.contains("focus") {
                out.push(finding(
                    format!("{loc}:{}", n + 1),
                    "a table row mentions `hover` without a keyboard or focus path; no navigation function may depend on hover (T-0015)",
                ));
            }
        }
    }
    let fences = text
        .lines()
        .filter(|line| line.trim_start().starts_with("```"))
        .count();
    if fences < 6 {
        out.push(finding(
            loc,
            format!(
                "the document has {fences} fenced code-block markers; at least three wireframe ASCII diagrams are required (T-0015 deliverable)"
            ),
        ));
    }
    out
}

/// Everything the per-journey checks read from the specification and the other UX documents (T-0016).
pub struct JourneyContext<'a> {
    /// Journey id to the exact title line of spec B3.
    pub titles: &'a BTreeMap<String, String>,
    /// Journey id to the persona file stems of the persona-journey matrix.
    pub personas: &'a BTreeMap<String, BTreeSet<String>>,
    /// Screens of the B12.1 screen table.
    pub screens: &'a BTreeSet<String>,
    /// Journey id to the `S-nnn` ids its spec text mentions.
    pub mentions: &'a BTreeMap<String, BTreeSet<String>>,
    /// Journey id to the `AC-nn` ids its spec text mentions.
    pub acs: &'a BTreeMap<String, BTreeSet<String>>,
    /// Error code to HTTP status from spec B7.
    pub errors: &'a BTreeMap<String, u16>,
    /// `ATK-nnn` ids of the C5 attack matrix.
    pub atks: &'a BTreeSet<String>,
    /// `AUD-` ids of spec B8.
    pub audits: &'a BTreeSet<String>,
    /// Proposed screen ids of `spec-patches.md`.
    pub patches: &'a BTreeSet<String>,
    /// Error code to the B7 title and note (for the error-path step-fit heuristic).
    pub error_text: &'a BTreeMap<String, String>,
    /// Screen id to the B12.1 name.
    pub screen_names: &'a BTreeMap<String, String>,
}

/// Journey ids and exact titles of spec B3 (`### J-nn <title>`).
pub fn journey_headings(spec: &str) -> BTreeMap<String, String> {
    let mut out = BTreeMap::new();
    for line in spec.lines() {
        let t = line.trim_start();
        let Some(rest) = t.strip_prefix("### J-") else {
            continue;
        };
        let digits: String = rest.chars().take_while(|c| c.is_ascii_digit()).collect();
        if digits.len() != 2 {
            continue;
        }
        let id = format!("J-{digits}");
        let title = rest
            .get(digits.len()..)
            .map(str::trim)
            .unwrap_or_default()
            .to_owned();
        out.entry(id).or_insert(title);
    }
    out
}

/// Error code to HTTP status from spec B7.
pub fn error_catalog(spec: &str) -> BTreeMap<String, u16> {
    let mut out = BTreeMap::new();
    for (_, line) in spec_section(spec, "B7.") {
        let Some(row) = cells(line) else { continue };
        let Some(code) = row.first() else { continue };
        let code = code.trim();
        if !code.starts_with("ERR-") {
            continue;
        }
        if let Some(status) = row.get(1).and_then(|cell| cell.trim().parse::<u16>().ok()) {
            out.insert(code.to_owned(), status);
        }
    }
    out
}

/// Error code to the B7 title and note, for the error-path step-fit heuristic.
pub fn error_descriptions(spec: &str) -> BTreeMap<String, String> {
    let mut out = BTreeMap::new();
    for (_, line) in spec_section(spec, "B7.") {
        let Some(row) = cells(line) else { continue };
        let Some(code) = row.first() else { continue };
        let code = code.trim();
        if !code.starts_with("ERR-") {
            continue;
        }
        let title = row.get(2).map_or("", |cell| cell.trim());
        let note = row.get(3).map_or("", |cell| cell.trim());
        out.insert(code.to_owned(), format!("{title} {note}"));
    }
    out
}

/// Screen id to the B12.1 name.
pub fn screen_names(spec: &str) -> BTreeMap<String, String> {
    let mut out = BTreeMap::new();
    let Ok(screen_re) = Regex::new(r"^S-\d{3}$") else {
        return out;
    };
    for (_, line) in spec_section(spec, "B12.1") {
        let Some(row) = cells(line) else { continue };
        let Some(first) = row.first() else { continue };
        let id = first.trim();
        if !screen_re.is_match(id) {
            continue;
        }
        let name = row.get(1).map_or("", |cell| cell.trim());
        if !name.is_empty() {
            out.insert(id.to_owned(), name.to_owned());
        }
    }
    out
}

/// `AUD-` ids of spec B8.
pub fn audit_ids(spec: &str) -> BTreeSet<String> {
    let mut out = BTreeSet::new();
    let Ok(token_re) = Regex::new(r"AUD-[a-z0-9_.]+") else {
        return out;
    };
    for (_, line) in spec_section(spec, "B8.") {
        let Some(row) = cells(line) else { continue };
        let Some(event) = row.first() else { continue };
        let event = event.trim();
        if !event.starts_with("AUD-") {
            continue;
        }
        out.insert(event.to_owned());
        let mut parts = event.split('/');
        let Some(first) = parts.next() else { continue };
        let Some(token) = token_re.find(first).map(|found| found.as_str().to_owned()) else {
            continue;
        };
        out.insert(token.clone());
        let Some(dot) = token.rfind('.') else {
            continue;
        };
        let last = &token[dot + 1..];
        let stem_end = last.rfind('_').map_or(dot + 1, |index| dot + 1 + index + 1);
        let stem = &token[..stem_end];
        for alternative in parts {
            let alternative = alternative.trim();
            if alternative.is_empty()
                || alternative.contains('.')
                || alternative.contains(char::is_whitespace)
            {
                continue;
            }
            out.insert(format!("{stem}{alternative}"));
        }
    }
    out
}

/// Journey id to persona file stems from the persona-journey matrix.
pub fn matrix_personas(text: &str) -> BTreeMap<String, BTreeSet<String>> {
    let mut out: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    let Ok(journey_re) = Regex::new(r"J-\d{2}") else {
        return out;
    };
    let Ok(persona_re) = Regex::new(r"personas/([a-z][a-z0-9-]*)\.md") else {
        return out;
    };
    for line in text.lines() {
        let Some(row) = cells(line) else { continue };
        let Some(first) = row.first() else { continue };
        let Some(journey) = journey_re.find(first) else {
            continue;
        };
        let Some(persona_cell) = row.get(2) else {
            continue;
        };
        let stems: BTreeSet<String> = persona_re
            .captures_iter(persona_cell)
            .filter_map(|capture| capture.get(1).map(|stem| stem.as_str().to_owned()))
            .collect();
        out.entry(journey.as_str().to_owned())
            .or_default()
            .extend(stems);
    }
    out
}

/// Proposed screen ids of `spec-patches.md`.
pub fn proposed_screens(text: &str) -> BTreeSet<String> {
    let mut out = BTreeSet::new();
    let lines: Vec<(usize, String)> = text
        .lines()
        .enumerate()
        .map(|(index, line)| (index + 1, line.to_owned()))
        .collect();
    let Ok(screen_re) = Regex::new(r"^S-\d{3}$") else {
        return out;
    };
    for table in tables_in(&lines) {
        if !table
            .header
            .first()
            .is_some_and(|cell| normalize_keys(cell) == "proposed screen")
        {
            continue;
        }
        for (_, row) in &table.rows {
            let Some(cell) = row.first() else { continue };
            let id = cell.trim().trim_matches('`').trim();
            if screen_re.is_match(id) {
                out.insert(id.to_owned());
            }
        }
    }
    out
}

/// `S-nnn` ids named in a `Missing screens` section.
pub fn missing_screens(text: &str) -> BTreeSet<String> {
    let Some(body) = section_body(text, "Missing screens") else {
        return BTreeSet::new();
    };
    let joined = body
        .iter()
        .map(|(_, line)| line.as_str())
        .collect::<Vec<_>>()
        .join("\n");
    tokens_in(&joined, r"S-\d{3}")
}

/// Whole-token values of `pattern` (for example `S-\d{3}`) in `text`.
pub fn tokens_in(text: &str, pattern: &str) -> BTreeSet<String> {
    let mut out = BTreeSet::new();
    let Ok(re) = Regex::new(pattern) else {
        return out;
    };
    for found in re.find_iter(text) {
        out.insert(found.as_str().to_owned());
    }
    out
}

/// The screen token of a steps `Screen` cell: an `S-nnn` id, the id after `data-plane:`, or `email`.
fn screen_token(cell: &str) -> Option<String> {
    let trimmed = cell.trim().trim_matches('`').trim();
    if trimmed == "email" {
        return Some(trimmed.to_owned());
    }
    let token = if let Some(rest) = trimmed.strip_prefix("data-plane:") {
        rest.trim()
    } else {
        trimmed
    };
    Regex::new(r"^S-\d{3}$")
        .ok()
        .filter(|re| re.is_match(token))
        .map(|_| token.to_owned())
}

/// Checks of one journey map (T-0016 A1 to A4): title, personas, steps, trust moments, security, accessibility,
/// instrumentation, success checks and missing screens.
pub fn journey_findings(text: &str, id: &str, ctx: &JourneyContext<'_>) -> Vec<Finding> {
    let loc = format!("{JOURNEYS_DIR}/{id}.md");
    let mut out = Vec::new();
    let first_line = text.lines().next().unwrap_or_default().trim();
    match ctx.titles.get(id) {
        None => out.push(finding(
            &loc,
            format!("the specification has no B3 heading for {id}"),
        )),
        Some(title) => {
            let expected = format!("# {id} {title}");
            if first_line != expected {
                out.push(finding(
                    &loc,
                    format!("the title `{first_line}` differs from the spec title `{expected}`"),
                ));
            }
        }
    }
    for section in JOURNEY_SECTIONS {
        if section_body(text, section).is_none() {
            out.push(finding(
                &loc,
                format!("no `## {section}` section (T-0016 deliverable)"),
            ));
        }
    }
    let header = header_block(text);
    let Ok(persona_re) = Regex::new(r"personas/([a-z][a-z0-9-]*)\.md") else {
        return out;
    };
    let linked: BTreeSet<String> = persona_re
        .captures_iter(&header)
        .filter_map(|capture| capture.get(1).map(|stem| stem.as_str().to_owned()))
        .collect();
    let expected_personas = ctx.personas.get(id).cloned().unwrap_or_default();
    if linked != expected_personas {
        out.push(finding(
            &loc,
            format!(
                "the persona links ({}) differ from the persona-journey matrix row ({})",
                linked.iter().cloned().collect::<Vec<_>>().join(", "),
                expected_personas
                    .iter()
                    .cloned()
                    .collect::<Vec<_>>()
                    .join(", ")
            ),
        ));
    }
    let copy_re = Regex::new(r"^[a-z0-9]+(-[a-z0-9]+)*$").ok();
    let error_re = Regex::new(r"ERR-[A-Z]+-\d{3}").ok();
    let mut step_screens: BTreeMap<String, String> = BTreeMap::new();
    let mut step_actions: BTreeMap<String, String> = BTreeMap::new();
    let mut step_order: Vec<String> = Vec::new();
    let mut screen_tokens: BTreeSet<String> = BTreeSet::new();
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
        match table_with_header(&tables, &wanted) {
            None => out.push(finding(
                &loc,
                "the `Steps` section has no table with columns Step | User action | System response | Screen | Data collected | Error path | Emotional state | Copy key | Metric (T-0016)",
            )),
            Some(table) => {
                let minimum = if id == "J-08" || id == "J-09" { 12 } else { 8 };
                if table.rows.len() < minimum {
                    out.push(finding(
                        &loc,
                        format!(
                            "the steps table has {} rows; at least {minimum} are required (A1)",
                            table.rows.len()
                        ),
                    ));
                }
                for (n, row) in &table.rows {
                    let at = format!("{loc}:{n}");
                    if row.len() < 9 {
                        out.push(finding(
                            &at,
                            "a steps row needs nine cells (T-0016)",
                        ));
                        continue;
                    }
                    if row.iter().any(|cell| cell.trim().is_empty()) {
                        out.push(finding(&at, "a steps row has an empty cell (T-0016)"));
                    }
                    let step = row.first().map_or("", |cell| cell.trim());
                    let screen_cell = row.get(3).map_or("", |cell| cell.trim());
                    let error_cell = row.get(5).map_or("", |cell| cell.trim());
                    let emotion = row.get(6).map_or("", |cell| cell.trim());
                    let copy_key = row.get(7).map_or("", |cell| cell.trim());
                    match screen_token(screen_cell) {
                        None => out.push(finding(
                            &at,
                            format!(
                                "screen `{screen_cell}` must be an S-nnn of B12.1, `data-plane: S-nnn` or `email` (A2)"
                            ),
                        )),
                        Some(token) => {
                            if token != "email" {
                                screen_tokens.insert(token.clone());
                                if !ctx.screens.contains(&token) {
                                    if ctx.patches.contains(&token) {
                                        // A proposed screen is allowed once spec-patches.md lists it.
                                    } else {
                                        out.push(finding(
                                            &at,
                                            format!(
                                                "screen `{token}` is not in B12.1 and is not listed in spec-patches.md (A5)"
                                            ),
                                        ));
                                    }
                                }
                            }
                            if step_screens
                                .insert(step.to_owned(), token)
                                .is_some()
                            {
                                out.push(finding(
                                    &at,
                                    format!("step `{step}` appears twice in the steps table"),
                                ));
                            } else {
                                let action = row.get(1).map_or("", |cell| cell.trim());
                                let system = row.get(2).map_or("", |cell| cell.trim());
                                step_actions.insert(step.to_owned(), format!("{action} {system}"));
                                step_order.push(step.to_owned());
                            }
                        }
                    }
                    if !EMOTIONAL_STATES.contains(&emotion) {
                        out.push(finding(
                            &at,
                            format!(
                                "emotional state `{emotion}` is not one of {}",
                                EMOTIONAL_STATES.join(", ")
                            ),
                        ));
                    }
                    if !copy_re.as_ref().is_some_and(|re| re.is_match(copy_key)) {
                        out.push(finding(
                            &at,
                            format!(
                                "copy key `{copy_key}` is not a hyphenated lowercase i18n key stem"
                            ),
                        ));
                    }
                    let codes = tokens_in(error_cell, r"ERR-[A-Z]+-\d{3}");
                    if codes.is_empty() {
                        out.push(finding(
                            &at,
                            "the error path cites no ERR- code of the B7 catalog (A3)",
                        ));
                    }
                    let declares_system = row
                        .iter()
                        .any(|cell| cell.to_lowercase().contains("system"));
                    if let Some(error_re) = error_re.as_ref() {
                        let found: Vec<regex::Match<'_>> = error_re.find_iter(error_cell).collect();
                        for (index, found_code) in found.iter().enumerate() {
                            let code = found_code.as_str();
                            match ctx.errors.get(code) {
                                None => out.push(finding(
                                    &at,
                                    format!("`{code}` is not a code of the B7 error catalog (A3)"),
                                )),
                                Some(status) if *status >= 500 && !declares_system => {
                                    out.push(finding(
                                        &at,
                                        format!(
                                            "`{code}` is a 5xx status ({status}) on a user error path; say `system` in the row or cite a 4xx code (T-0016)"
                                        ),
                                    ));
                                }
                                Some(_) => {}
                            }
                            let end = found
                                .get(index + 1)
                                .map_or(error_cell.len(), |next| next.start());
                            let after = error_cell
                                .get(found_code.end()..end)
                                .unwrap_or_default()
                                .trim();
                            let Some(sentence) = after.strip_prefix(':').map(str::trim) else {
                                out.push(finding(
                                    &at,
                                    format!(
                                        "the error path `{code}` has no sentence after the code (F-12)"
                                    ),
                                ));
                                continue;
                            };
                            let words = sentence.split_whitespace().count();
                            if words < 6 {
                                out.push(finding(
                                    &at,
                                    format!(
                                        "the error sentence for `{code}` has {words} words; at least six are required (F-12)"
                                    ),
                                ));
                                continue;
                            }
                            let sentence_words = content_words(sentence);
                            let b7 = ctx.error_text.get(code).map(String::as_str).unwrap_or_default();
                            if b7.is_empty() || content_words(b7).is_disjoint(&sentence_words) {
                                out.push(finding(
                                    &at,
                                    format!(
                                        "the error sentence for `{code}` shares no content word with the B7 title or note (F-12)"
                                    ),
                                ));
                            }
                            let action = row.get(1).map_or("", |cell| cell.trim());
                            let system = row.get(2).map_or("", |cell| cell.trim());
                            let screen_name = step_screens
                                .get(step)
                                .and_then(|screen| ctx.screen_names.get(screen))
                                .map(String::as_str)
                                .unwrap_or_default();
                            let step_text = format!("{action} {system} {screen_name}");
                            if content_words(&step_text).is_disjoint(&sentence_words) {
                                out.push(finding(
                                    &at,
                                    format!(
                                        "the error sentence for `{code}` shares no content word with the step (F-12)"
                                    ),
                                ));
                            }
                        }
                    }
                }
            }
        }
    }
    let mut changing: Vec<String> = Vec::new();
    let mut previous: Option<&String> = None;
    for step in &step_order {
        if let Some(screen) = step_screens.get(step) {
            if previous != Some(screen) {
                changing.push(step.clone());
            }
            previous = Some(screen);
        }
    }
    if let Some(body) = section_body(text, "Trust moments") {
        let tables = tables_in(&body);
        let wanted = ["step", "what the user must believe", "evidence we show"];
        match table_with_header(&tables, &wanted) {
            None => out.push(finding(
                &loc,
                "the `Trust moments` section has no table with columns Step | What the user must believe | Evidence we show (T-0016)",
            )),
            Some(table) => {
                if table.rows.len() < 2 {
                    out.push(finding(
                        &loc,
                        format!(
                            "the trust-moments table has {} rows; at least two are required (T-0016)",
                            table.rows.len()
                        ),
                    ));
                }
                for (n, row) in &table.rows {
                    if row.len() < 3 || row.iter().any(|cell| cell.trim().is_empty()) {
                        out.push(finding(
                            format!("{loc}:{n}"),
                            "a trust-moments row needs three non-empty cells (T-0016)",
                        ));
                    }
                }
            }
        }
    }
    if let Some(body) = section_body(text, "Security considerations") {
        let tables = tables_in(&body);
        let wanted = ["step", "risk", "control", "atk"];
        match table_with_header(&tables, &wanted) {
            None => out.push(finding(
                &loc,
                "the `Security considerations` section has no table with columns Step | Risk | Control | ATK (A4)",
            )),
            Some(table) => {
                if table.rows.is_empty() {
                    out.push(finding(
                        &loc,
                        "the security table has no rows (A4)",
                    ));
                }
                for (n, row) in &table.rows {
                    let at = format!("{loc}:{n}");
                    if row.len() < 4 || row.iter().any(|cell| cell.trim().is_empty()) {
                        out.push(finding(
                            &at,
                            "a security row needs four non-empty cells (A4)",
                        ));
                        continue;
                    }
                    let step = row.first().map_or("", |cell| cell.trim());
                    if !step_screens.contains_key(step) {
                        out.push(finding(
                            &at,
                            format!("security row names step `{step}`, which is not in the steps table"),
                        ));
                    }
                    let atks = tokens_in(row.get(3).map_or("", |cell| cell), r"ATK-\d{3}");
                    if atks.is_empty() {
                        out.push(finding(
                            &at,
                            "the security row cites no ATK- id of the C5 matrix (A4)",
                        ));
                    }
                    for atk in atks {
                        if !ctx.atks.contains(&atk) {
                            out.push(finding(
                                &at,
                                format!("`{atk}` is not an id of the C5 attack matrix (A4)"),
                            ));
                        }
                    }
                }
            }
        }
    }
    if let Some(body) = section_body(text, "Accessibility considerations") {
        let tables = tables_in(&body);
        let wanted = ["step", "focus target", "announcement", "keyboard"];
        match table_with_header(&tables, &wanted) {
            None => out.push(finding(
                &loc,
                "the `Accessibility considerations` section has no table with columns Step | Focus target | Announcement | Keyboard (A4)",
            )),
            Some(table) => {
                let mut announced: BTreeSet<String> = BTreeSet::new();
                for (n, row) in &table.rows {
                    let at = format!("{loc}:{n}");
                    if row.len() < 4 || row.iter().any(|cell| cell.trim().is_empty()) {
                        out.push(finding(
                            &at,
                            "an accessibility row needs four non-empty cells (A4)",
                        ));
                        continue;
                    }
                    let step = row.first().map_or("", |cell| cell.trim());
                    if !step_screens.contains_key(step) {
                        out.push(finding(
                            &at,
                            format!("accessibility row names step `{step}`, which is not in the steps table"),
                        ));
                    } else {
                        announced.insert(step.to_owned());
                    }
                }
                for step in &changing {
                    if !announced.contains(step) {
                        out.push(finding(
                            &loc,
                            format!(
                                "step {step} changes the screen but has no accessibility row (A4)"
                            ),
                        ));
                    }
                }
            }
        }
    }
    if matches!(id, "J-08" | "J-09") {
        match section_body(text, "Cutover safety") {
            None => out.push(finding(
                &loc,
                "no `## Cutover safety` section for a domain-cutover journey (T-0016)",
            )),
            Some(body) => {
                let tables = tables_in(&body);
                let wanted = ["step", "what could break the live site", "guard", "undo"];
                match table_with_header(&tables, &wanted) {
                    None => out.push(finding(
                        &loc,
                        "the `Cutover safety` section has no table with columns Step | What could break the live site | Guard | Undo (T-0016)",
                    )),
                    Some(table) => {
                        if table.rows.len() < 4 {
                            out.push(finding(
                                &loc,
                                format!(
                                    "the cutover-safety table has {} rows; at least four are required (T-0016)",
                                    table.rows.len()
                                ),
                            ));
                        }
                        let controls = [
                            "preview", "parity", "rollback", "undo", "revert", "snapshot", "monitor",
                            "propagat", "ttl", "dry-run", "dry run", "return path", "r-19",
                            "self-lockout", "backup", "plan",
                        ];
                        let names_control = |cell: &str| {
                            let lower = cell.to_lowercase();
                            controls.iter().any(|control| lower.contains(control))
                        };
                        let mut covered: BTreeSet<String> = BTreeSet::new();
                        for (n, row) in &table.rows {
                            let at = format!("{loc}:{n}");
                            if row.len() < 4 || row.iter().any(|cell| cell.trim().is_empty()) {
                                out.push(finding(
                                    &at,
                                    "a cutover-safety row needs four non-empty cells (T-0016)",
                                ));
                                continue;
                            }
                            let step = row.first().map_or("", |cell| cell.trim());
                            if !step_screens.contains_key(step) {
                                out.push(finding(
                                    &at,
                                    format!(
                                        "cutover-safety row names step `{step}`, which is not in the steps table"
                                    ),
                                ));
                            }
                            covered.insert(step.to_owned());
                            let guard = row.get(2).map_or("", |cell| cell.trim());
                            let undo = row.get(3).map_or("", |cell| cell.trim());
                            if !names_control(guard) {
                                out.push(finding(
                                    &at,
                                    "the `Guard` cell names no control that exists in the spec, such as a preview, a parity check or the R-19 return path (T-0016)",
                                ));
                            }
                            if !names_control(undo) {
                                out.push(finding(
                                    &at,
                                    "the `Undo` cell names no control that exists in the spec, such as rollback or the R-19 return path (T-0016)",
                                ));
                            }
                        }
                        let cutover_words = [
                            "dns",
                            "nameserver",
                            "delegation",
                            "proxy",
                            "routing",
                            "zone",
                            "cname",
                        ];
                        for (step, text) in &step_actions {
                            let lower = text.to_lowercase();
                            if cutover_words.iter().any(|word| lower.contains(word))
                                && !covered.contains(step)
                            {
                                out.push(finding(
                                    &loc,
                                    format!(
                                        "step {step} changes DNS or routing but has no `Cutover safety` row (T-0016)"
                                    ),
                                ));
                            }
                        }
                    }
                }
            }
        }
    }
    if let Some(body) = section_body(text, "Instrumentation") {
        let joined = body
            .iter()
            .map(|(_, line)| line.as_str())
            .collect::<Vec<_>>()
            .join("\n");
        let events = tokens_in(&joined, r"AUD-[a-z0-9_.]+");
        if events.is_empty() {
            out.push(finding(
                &loc,
                "the instrumentation section names no AUD- audit event from spec B8 (T-0016)",
            ));
        }
        for event in events {
            if !ctx.audits.contains(&event) {
                out.push(finding(
                    &loc,
                    format!("`{event}` is not an audit event of spec B8 (T-0016)"),
                ));
            }
        }
    }
    if let Some(body) = section_body(text, "Success and checks") {
        let joined = body
            .iter()
            .map(|(_, line)| line.as_str())
            .collect::<Vec<_>>()
            .join("\n");
        let checks = tokens_in(&joined, r"AC-\d{2}");
        for ac in ctx.acs.get(id).cloned().unwrap_or_default() {
            if !checks.contains(&ac) {
                out.push(finding(
                    &loc,
                    format!(
                        "the spec text names `{ac}` but `Success and checks` does not (T-0016)"
                    ),
                ));
            }
        }
    }
    let missing = missing_screens(text);
    for screen in &missing {
        if ctx.screens.contains(screen) {
            out.push(finding(
                &loc,
                format!("`Missing screens` lists `{screen}`, which already exists in B12.1 (A5)"),
            ));
        } else if !ctx.patches.contains(screen) {
            out.push(finding(
                &loc,
                format!("`Missing screens` lists `{screen}`, which spec-patches.md does not propose (A5)"),
            ));
        }
    }
    for screen in ctx.mentions.get(id).cloned().unwrap_or_default() {
        if !screen_tokens.contains(&screen) && !missing.contains(&screen) {
            out.push(finding(
                &loc,
                format!(
                    "the spec text mentions `{screen}` but the journey's Screen column and `Missing screens` do not (T-0016)"
                ),
            ));
        }
    }
    out
}

/// Checks of `docs/UX/spec-patches.md` (T-0016 A5).
pub fn patches_findings(
    text: &str,
    screens: &BTreeSet<String>,
    journeys: &BTreeSet<String>,
    needed: &BTreeMap<String, BTreeSet<String>>,
) -> Vec<Finding> {
    let loc = SPEC_PATCHES;
    let mut out = Vec::new();
    let lines: Vec<(usize, String)> = text
        .lines()
        .enumerate()
        .map(|(index, line)| (index + 1, line.to_owned()))
        .collect();
    let tables = tables_in(&lines);
    let wanted = ["proposed screen", "needed by", "reason", "status"];
    let Some(table) = table_with_header(&tables, &wanted) else {
        out.push(finding(
            loc,
            "no table with columns Proposed screen | Needed by | Reason | Status (A5)",
        ));
        return out;
    };
    let screen_re = Regex::new(r"^S-\d{3}$").ok();
    for (n, row) in &table.rows {
        let at = format!("{loc}:{n}");
        if row.len() < 4 {
            out.push(finding(&at, "a patch row needs four cells (A5)"));
            continue;
        }
        let proposed = row
            .first()
            .map_or("", |cell| cell.trim().trim_matches('`').trim());
        if !screen_re.as_ref().is_some_and(|re| re.is_match(proposed)) {
            out.push(finding(
                &at,
                format!("`{proposed}` is not an S-nnn screen id"),
            ));
            continue;
        }
        if screens.contains(proposed) {
            out.push(finding(
                &at,
                format!("`{proposed}` already exists in B12.1, so it cannot be proposed (A5)"),
            ));
        }
        let needed_by = tokens_in(row.get(1).map_or("", |cell| cell), r"J-\d{2}");
        if needed_by.is_empty() {
            out.push(finding(
                &at,
                "the `Needed by` cell names no journey id (A5)",
            ));
        }
        for journey in &needed_by {
            if !journeys.contains(journey) {
                out.push(finding(
                    &at,
                    format!("`Needed by` names `{journey}`, which is not a journey of spec B3"),
                ));
            }
        }
        let status = row.get(3).map_or("", |cell| cell.trim());
        if !status.eq_ignore_ascii_case("proposed") {
            out.push(finding(
                &at,
                format!("status `{status}` must be `proposed` (A5)"),
            ));
        }
        if row.get(2).is_none_or(|cell| cell.trim().is_empty()) {
            out.push(finding(&at, "the `Reason` cell is empty (A5)"));
        }
        let delivered = needed_by
            .iter()
            .any(|journey| JOURNEYS_IN_SCOPE.contains(&journey.as_str()));
        if delivered {
            let cited = needed_by.iter().any(|journey| {
                needed
                    .get(proposed)
                    .is_some_and(|listing| listing.contains(journey))
            });
            if !cited {
                out.push(finding(
                    &at,
                    format!(
                        "`{proposed}` is listed as needed by a delivered journey, but no journey's `Missing screens` names it (A5)"
                    ),
                ));
            }
        }
    }
    out
}

/// Whole check on the repository at `root`.
pub fn check(root: &Path) -> Vec<Finding> {
    let mut out = Vec::new();
    for (path, run) in [
        ("docs/UX/CHARTER.md", charter_findings as Checker),
        ("docs/UX/MEASURES.md", measures_findings),
    ] {
        match read_text(&root.join(path)) {
            Ok(t) => out.extend(run(&t)),
            Err(_) => out.push(finding(path, "the document does not exist")),
        }
    }
    for id in DECISIONS {
        let path = format!("docs/UX/decisions/{id}.md");
        match read_text(&root.join(&path)) {
            Ok(t) => out.extend(decision_findings(id, &t)),
            Err(_) => out.push(finding(
                &path,
                format!("the decision record {id} does not exist"),
            )),
        }
    }
    match read_text(&root.join("docs").join("OPERATOR-QUESTIONS.md")) {
        Ok(t) => out.extend(primary_persona_findings(&t)),
        Err(_) => out.push(finding(
            "docs/OPERATOR-QUESTIONS.md",
            "the question register does not exist",
        )),
    }
    let (registry, b11_11, declared, screens, components, permissions, classes, shortcuts) =
        match crate::spec::load_master(root) {
            Ok(spec) => {
                let ids = attack_registry(&spec);
                if ids.is_empty() {
                    out.push(finding(
                        "docs/SPEC.md",
                        "the attack coverage matrix (C5) has no ATK rows, so abuse-story ids cannot be checked",
                    ));
                }
                let criteria = b11_11_criteria(&spec);
                if criteria.is_empty() {
                    out.push(finding(
                        "docs/SPEC.md",
                        "the B11.11 accessibility table has no criterion rows, so persona mappings cannot be checked",
                    ));
                }
                let declared: BTreeMap<String, BTreeSet<String>> = PERSONA_HEADINGS
                    .iter()
                    .map(|(stem, heading)| ((*stem).to_owned(), key_journeys(&spec, heading)))
                    .collect();
                let screens = screen_ids(&spec);
                if screens.is_empty() {
                    out.push(finding(
                        "docs/SPEC.md",
                        "the B12.1 screen table has no screen rows, so design requirements cannot be checked",
                    ));
                }
                let components = component_names(&spec);
                if components.is_empty() {
                    out.push(finding(
                        "docs/SPEC.md",
                        "the B11.8 component inventory has no component rows, so design requirements cannot be checked",
                    ));
                }
                let permissions = permission_ids(&spec);
                if permissions.is_empty() {
                    out.push(finding(
                        "docs/SPEC.md",
                        "the B4.2 permission catalog has no permission rows, so route permissions cannot be checked",
                    ));
                }
                let classes = rate_limit_classes(&spec);
                if classes.is_empty() {
                    out.push(finding(
                        "docs/SPEC.md",
                        "the B6.1 rate-limit classes cannot be read, so route classes cannot be checked",
                    ));
                }
                let shortcuts = shortcut_list(&spec);
                if shortcuts.is_empty() {
                    out.push(finding(
                        "docs/SPEC.md",
                        "the B2.3 keyboard shortcuts cannot be read, so the navigation shortcut map cannot be checked",
                    ));
                }
                out.extend(content::check(root, &spec));
                out.extend(ftl_style::check(root, &spec));
                out.extend(a11y::check(root));
                out.extend(dataviz::check(root));
                out.extend(onboarding::check(root));
                out.extend(responsive::check(root));
                out.extend(security_ux::check(root));
                out.extend(errors::check(root, &spec));
                out.extend(i18n_plan::check(root, &spec));
                (
                    if ids.is_empty() { None } else { Some(ids) },
                    if criteria.is_empty() {
                        None
                    } else {
                        Some(criteria)
                    },
                    Some(declared),
                    Some(screens),
                    Some(components),
                    Some(permissions),
                    Some(classes),
                    Some(shortcuts),
                )
            }
            Err(e) => {
                out.push(finding(
                    "docs/SPEC.md",
                    format!(
                        "cannot read the attack coverage matrix (C5), the B11.11 accessibility table, the B12.1 screens, the B11.8 components, the B4.2 permissions, the B6.1 rate-limit classes, the B2.3 keyboard shortcuts and the key journeys from the master specification: {}",
                        e.0
                    ),
                ));
                (None, None, None, None, None, None, None, None)
            }
        };
    let mut persona_texts: BTreeMap<&str, String> = BTreeMap::new();
    let mut persona_journeys: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    for stem in PERSONAS {
        let path = format!("docs/UX/personas/{stem}.md");
        match read_text(&root.join(&path)) {
            Ok(text) => {
                out.extend(persona_findings(stem, &text, b11_11.as_ref()));
                out.extend(mojibake_findings(&path, &text));
                if stem == ADVERSARY {
                    out.extend(adversary_findings(&text, registry.as_ref()));
                } else {
                    persona_journeys.insert(stem.to_owned(), persona_journey_list(&text));
                }
                persona_texts.insert(stem, text);
            }
            Err(_) => out.push(finding(
                &path,
                "the persona file does not exist (T-0012 A1 to A4)",
            )),
        }
    }
    let matrix_text = match read_text(&root.join(MATRIX)) {
        Ok(text) => {
            out.extend(matrix_findings(&text));
            out.extend(mojibake_findings(MATRIX, &text));
            Some(text)
        }
        Err(_) => {
            out.push(finding(
                MATRIX,
                "the persona-journey matrix does not exist (T-0012 A2)",
            ));
            None
        }
    };
    let matrix_linked = matrix_text
        .as_ref()
        .is_some_and(|text| text.contains(PRIMARY_PERSONA_LINK));
    if let (Some(declared), Some(matrix_text)) = (&declared, &matrix_text) {
        let links = matrix_persona_links(matrix_text);
        out.extend(key_journey_findings(declared, &persona_journeys, &links));
    }
    let maya_linked = persona_texts
        .get("maya")
        .is_some_and(|text| text.contains(PRIMARY_PERSONA_LINK));
    if !matrix_linked && !maya_linked {
        out.push(finding(
            MATRIX,
            "the primary-persona question is linked from neither the matrix nor `personas/maya.md` (A5)",
        ));
    }
    let patterns_text = match read_text(&root.join(PATTERNS)) {
        Ok(text) => {
            out.extend(patterns_findings(&text));
            Some(text)
        }
        Err(_) => {
            out.push(finding(
                PATTERNS,
                "the document does not exist (T-0013 A1 to A5)",
            ));
            None
        }
    };
    match read_text(&root.join(DESIGN_REQUIREMENTS_FILE)) {
        Ok(text) => out.extend(design_requirement_findings(
            &text,
            patterns_text.as_deref(),
            screens.as_ref(),
            components.as_ref(),
        )),
        Err(_) => out.push(finding(
            DESIGN_REQUIREMENTS_FILE,
            "the document does not exist (T-0013 A4)",
        )),
    }
    let ia_text = match read_text(&root.join(IA)) {
        Ok(text) => {
            out.extend(ia_findings(&text));
            Some(text)
        }
        Err(_) => {
            out.push(finding(IA, "the document does not exist (T-0014)"));
            None
        }
    };
    let token_patterns = ia_text
        .as_deref()
        .map(token_route_patterns)
        .unwrap_or_default();
    let rate_exceptions = ia_text
        .as_deref()
        .map(rate_class_exceptions)
        .unwrap_or_default();
    let mut route_permissions: BTreeMap<String, String> = BTreeMap::new();
    match read_text(&root.join(ROUTES)) {
        Ok(text) => {
            if let Ok(file) = toml::from_str::<RoutesFile>(&text) {
                for route in file.route {
                    route_permissions
                        .entry(route.pattern)
                        .or_insert(route.permission);
                }
            }
            if let (Some(screens), Some(permissions), Some(classes)) =
                (screens.as_ref(), permissions.as_ref(), classes.as_ref())
            {
                out.extend(routes_findings(
                    &text,
                    screens,
                    permissions,
                    classes,
                    &token_patterns,
                    &rate_exceptions,
                ));
            }
        }
        Err(_) => out.push(finding(
            ROUTES,
            "the document does not exist (T-0014 A1, A2, A5)",
        )),
    }
    match read_text(&root.join(NAVIGATION)) {
        Ok(text) => {
            if let Some(shortcuts) = shortcuts.as_ref() {
                out.extend(navigation_findings(&text, &route_permissions, shortcuts));
            }
        }
        Err(_) => out.push(finding(
            NAVIGATION,
            "the document does not exist (T-0015 A1 to A5)",
        )),
    }
    if let Ok(spec) = crate::spec::load_master(root) {
        let titles = journey_headings(&spec);
        let errors = error_catalog(&spec);
        let error_text = error_descriptions(&spec);
        let screen_titles = screen_names(&spec);
        let atks = attack_registry(&spec);
        let audits = audit_ids(&spec);
        let personas = match read_text(&root.join(MATRIX)) {
            Ok(text) => matrix_personas(&text),
            Err(_) => BTreeMap::new(),
        };
        let patches_text = match read_text(&root.join(SPEC_PATCHES)) {
            Ok(text) => Some(text),
            Err(_) => {
                out.push(finding(
                    SPEC_PATCHES,
                    "the document does not exist (T-0016 A5)",
                ));
                None
            }
        };
        let patches = patches_text
            .as_deref()
            .map(proposed_screens)
            .unwrap_or_default();
        let screens = screen_ids(&spec);
        let mut mentions: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
        let mut acs: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
        for id in JOURNEYS_IN_SCOPE {
            let body = spec_section(&spec, id)
                .iter()
                .map(|(_, line)| *line)
                .collect::<Vec<_>>()
                .join("\n");
            mentions.insert(id.to_owned(), tokens_in(&body, r"S-\d{3}"));
            acs.insert(id.to_owned(), tokens_in(&body, r"AC-\d{2}"));
        }
        let journey_ids: BTreeSet<String> = titles.keys().cloned().collect();
        let ctx = JourneyContext {
            titles: &titles,
            personas: &personas,
            screens: &screens,
            mentions: &mentions,
            acs: &acs,
            errors: &errors,
            atks: &atks,
            audits: &audits,
            patches: &patches,
            error_text: &error_text,
            screen_names: &screen_titles,
        };
        let permissions = permission_ids(&spec);
        let ext = journeys_ext::ExtContext {
            screens: &screens,
            permissions: &permissions,
            audits: &audits,
        };
        let atk_text = journeys_ops::attack_texts(&spec);
        let mut needed: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
        let mut seen_journeys: Vec<(String, String)> = Vec::new();
        for id in JOURNEYS_IN_SCOPE {
            let path = format!("{JOURNEYS_DIR}/{id}.md");
            match read_text(&root.join(&path)) {
                Ok(text) => {
                    out.extend(journey_findings(&text, id, &ctx));
                    out.extend(journeys_ops::ops_findings(&text, id, &atk_text));
                    out.extend(journeys_ext::ext_findings(&text, id, &ext));
                    seen_journeys.push((id.to_owned(), text.clone()));
                    for screen in missing_screens(&text) {
                        needed.entry(screen).or_default().insert(id.to_owned());
                    }
                }
                Err(_) => out.push(finding(&path, "the journey file does not exist (T-0016)")),
            }
        }
        let scope_journeys: BTreeSet<String> = JOURNEYS_IN_SCOPE
            .iter()
            .map(|id| (*id).to_owned())
            .collect();
        match read_text(&root.join(journeys_ext::JOURNEY_DEPENDENCIES)) {
            Ok(text) => match crate::tasks::parse(&spec) {
                Ok(model) => match crate::tasks::order(&model) {
                    Ok(order) => out.extend(journeys_ext::dependencies_findings(
                        &text,
                        &scope_journeys,
                        &model,
                        &order,
                    )),
                    Err(e) => out.push(finding(
                        journeys_ext::JOURNEY_DEPENDENCIES,
                        format!(
                            "the task dependency graph of docs/SPEC.md is not acyclic: {}",
                            e.0
                        ),
                    )),
                },
                Err(e) => out.push(finding(
                    journeys_ext::JOURNEY_DEPENDENCIES,
                    format!(
                        "cannot read the task dependency graph from docs/SPEC.md: {}",
                        e.0
                    ),
                )),
            },
            Err(_) => out.push(finding(
                journeys_ext::JOURNEY_DEPENDENCIES,
                "the document does not exist (T-0018 A2)",
            )),
        }
        if let Ok(register) = read_text(&root.join("docs/OPERATOR-QUESTIONS.md")) {
            out.extend(journeys_ops::operator_questions_findings(
                &register,
                &seen_journeys,
            ));
        }
        if let Some(text) = patches_text {
            out.extend(patches_findings(&text, &screens, &journey_ids, &needed));
        }
    }
    let mut ux_docs: Vec<(String, String)> = Vec::new();
    for f in walk_files(&root.join("docs").join("UX")) {
        if !f.extension().is_some_and(|e| e.eq_ignore_ascii_case("md")) {
            continue;
        }
        let relative = rel(root, &f);
        match read_text(&f) {
            Ok(text) => {
                out.extend(broken_links(root, &PathBuf::from(&relative), &text));
                ux_docs.push((relative, text));
            }
            Err(e) => out.push(finding(relative, e.to_string())),
        }
    }
    let agents = root.join("AGENTS.md");
    if agents.is_file() {
        let relative = rel(root, &agents);
        match read_text(&agents) {
            Ok(text) => out.extend(broken_links(root, &PathBuf::from(&relative), &text)),
            Err(e) => out.push(finding(relative, e.to_string())),
        }
    }
    let doc_refs: Vec<(&str, &str)> = ux_docs
        .iter()
        .map(|(path, text)| (path.as_str(), text.as_str()))
        .collect();
    out.extend(self_copy_findings(&doc_refs));
    out
}

mod a11y;
mod content;
mod dataviz;
mod errors;
mod ftl_style;
mod i18n_plan;
mod journeys_ext;
mod journeys_ops;
mod onboarding;
mod responsive;
mod security_ux;

#[cfg(test)]
mod tests;
