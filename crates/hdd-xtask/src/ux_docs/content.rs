//! `ux-docs` content checks (T-0019 step 1 to 3 and 6 to 8): the content strategy, the microcopy guide and the glossary.
//!
//! Rules, all stated here because the module is the only place that enforces them:
//!
//! * `docs/UX/CONTENT.md` has the eight sections the task names: `Voice and tone`, `Vocabulary`,
//!   `Capitalization and punctuation`, `Number, date and unit formats`, `Message patterns`, `Visitor errors`,
//!   `Translation guidance` and `Review of B13`;
//! * `Voice and tone` carries a `Rule | Good | Bad` table with at least four rules, one good and one bad sentence
//!   each, and names active voice and second person;
//! * `Vocabulary` has the table `Concept | Canonical term | Avoid | Why`, at least ten rows, the four required
//!   distinctions (domain/site, proxied/orange cloud, block/deny, ban/jail entry), no canonical term inside any
//!   `Avoid` cell and no avoided term that is a canonical term; a term is matched as whole words, so `blocklist`
//!   is not `block`;
//! * `Message patterns` has the table `Pattern | Example text | i18n key`, at least ten examples covering the
//!   eight kinds (success, validation error, system error, destructive confirmation, empty state, limit reached,
//!   security notice, email subject line), a well-formed semantic hyphenated key per row and no repeated key;
//! * `Visitor errors` has the table `Forbidden disclosure | Why it is forbidden` with at least five rows and the
//!   section says that a block page never blames the visitor and never reveals detection logic;
//! * `Translation guidance` contains a Fluent plural example with `[one]` and `[other]`, a Fluent placeholder,
//!   the no-concatenation rule and the no-text-in-images rule;
//! * `Review of B13` has the table `Key stem | Result | Note`, lists every key stem of B13 in the master
//!   specification exactly once (B13 is read with [`b13_rows`] from the checksum-verified master), gives each key
//!   `pass` or a documented `exception:` and a note;
//! * `docs/UX/glossary.md` and `i18n/glossary.md` each have the table `Term | Plain definition | Do not translate`,
//!   define every term `T-0019` names, give each term exactly one sentence of at most thirty words, carry the same
//!   set of terms, use no uppercase jargon outside the glossary terms and contain no forbidden claims phrase.
//!
//! The checks are document linters, not spec parsers. B13 is the only registry they read; it comes from
//! [`crate::spec::load_master`] via the caller.

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

use regex::Regex;

use crate::claims;
use crate::util::{Finding, read_text};

use super::{column, section_body, section_table};

/// The content strategy and microcopy guide.
pub const CONTENT: &str = "docs/UX/CONTENT.md";
/// The interface glossary for the product.
pub const GLOSSARY: &str = "docs/UX/glossary.md";
/// The translator copy of the glossary.
pub const I18N_GLOSSARY: &str = "i18n/glossary.md";

/// The level-2 sections `docs/UX/CONTENT.md` must have, in the order the task names them.
pub const SECTIONS: [&str; 8] = [
    "Voice and tone",
    "Vocabulary",
    "Capitalization and punctuation",
    "Number, date and unit formats",
    "Message patterns",
    "Visitor errors",
    "Translation guidance",
    "Review of B13",
];

/// The message patterns the task names.
pub const MESSAGE_KINDS: [&str; 8] = [
    "success",
    "validation error",
    "system error",
    "destructive confirmation",
    "empty state",
    "limit reached",
    "security notice",
    "email subject line",
];

/// At least this many message examples (T-0019 A3).
pub const MIN_MESSAGE_EXAMPLES: usize = 10;
/// At least this many vocabulary rows (T-0019 step 1).
pub const MIN_VOCAB_ROWS: usize = 10;
/// At least this many forbidden visitor disclosures (T-0019 step 7).
pub const MIN_VISITOR_FORBIDDEN: usize = 5;
/// At least this many voice rules, each with a good and a bad sentence (T-0019 step 1).
pub const MIN_VOICE_ROWS: usize = 4;
/// The longest allowed glossary definition, in words (T-0019 A1).
pub const MAX_DEFINITION_WORDS: usize = 30;

/// The glossary terms the task names. Extras are allowed; these must all be present.
pub const GLOSSARY_TERMS: [&str; 16] = [
    "WAF",
    "SQL injection",
    "XSS",
    "DNS",
    "nameserver",
    "CNAME",
    "TLS",
    "HSTS",
    "origin",
    "ban",
    "challenge",
    "Ray ID",
    "proxied",
    "monitor mode",
    "block mode",
    "never-ban list",
];

/// The vocabulary distinctions the task names, as `(canonical term, avoided term)`.
pub const REQUIRED_DISTINCTIONS: [(&str, &str); 4] = [
    ("domain", "site"),
    ("proxied", "orange cloud"),
    ("block", "deny"),
    ("ban", "jail entry"),
];

/// Uppercase words a definition may use: the glossary terms themselves plus the product name.
const ALLOWED_ACRONYMS: [&str; 1] = ["HDD"];

/// Shape of a semantic i18n key stem: lowercase words, digits, single hyphens between words.
const KEY_SHAPE: &str = r"^[a-z0-9]+(-[a-z0-9]+)*$";

/// Lower-cased word tokens of `text`. A hyphen stays inside its token, so `never-ban` is one word and `ban`
/// does not match inside it.
fn tokens(text: &str) -> Vec<String> {
    text.split(|c: char| !(c.is_alphanumeric() || c == '-'))
        .filter(|t| !t.is_empty())
        .map(str::to_lowercase)
        .collect()
}

/// Whether `phrase` occurs in `text` as consecutive whole words (case-insensitive).
fn has_phrase(text: &str, phrase: &str) -> bool {
    let words = tokens(text);
    let needle = tokens(phrase);
    if needle.is_empty() || words.len() < needle.len() {
        return false;
    }
    words
        .windows(needle.len())
        .any(|window| window == needle.as_slice())
}

/// Trimmed value of a table cell with backticks removed.
fn plain(cell: &str) -> String {
    cell.trim().trim_matches('`').trim().to_owned()
}

/// A `ux-docs` finding at `location`.
fn at(location: impl Into<String>, message: impl Into<String>) -> Finding {
    Finding::new("ux-docs", location, message)
}

/// The B13 rows of the master specification: `(key stem, English text)` in table order.
///
/// The heading token of the master is `## B13.` (with the dot), which the section helper matches exactly; an
/// empty text cell is kept as an empty string so the copy-deck check can require the `# empty: needs text` comment.
pub fn b13_rows(spec: &str) -> Vec<(String, String)> {
    const HEADING: &str = "B13. Copy deck (canonical strings that tests and docs reference)";
    let Some((header, rows)) = section_table(spec, HEADING) else {
        return Vec::new();
    };
    if header.len() < 2 {
        return Vec::new();
    }
    rows.into_iter()
        .filter_map(|(_, row)| {
            let key = row.first().map(|c| plain(c)).unwrap_or_default();
            if key.is_empty() {
                return None;
            }
            Some((key, row.get(1).cloned().unwrap_or_default()))
        })
        .collect()
}

/// Structural findings for `docs/UX/CONTENT.md`. `b13_keys` are the key stems of B13; `claims_cfg` is kept in the
/// signature so the caller can extend the claims scan without a second document parse, and is used for the
/// message examples when it is supplied.
pub fn content_findings(
    text: &str,
    b13_keys: &[String],
    claims_cfg: Option<&claims::Config>,
) -> Vec<Finding> {
    let mut out = Vec::new();
    for section in SECTIONS {
        if section_body(text, section).is_none() {
            out.push(at(
                CONTENT,
                format!("the `## {section}` section is missing (T-0019 step 1 to 8)"),
            ));
        }
    }
    out.extend(voice_findings(text));
    out.extend(vocabulary_findings(text));
    out.extend(message_pattern_findings(text));
    out.extend(visitor_error_findings(text));
    out.extend(translation_findings(text));
    out.extend(b13_review_findings(text, b13_keys));
    if let Some(cfg) = claims_cfg {
        for finding in claims::scan_text(cfg, CONTENT, text) {
            out.push(finding);
        }
    }
    out
}

/// Trimmed cell at `index` of a table row, or an empty string when the row is shorter.
fn cell(row: &[String], index: usize) -> String {
    row.get(index)
        .map(|c| c.trim().to_owned())
        .unwrap_or_default()
}

/// `Voice and tone`: a `Rule | Good | Bad` table with a good and a bad sentence per rule, and the two voice
/// properties B11.12 requires.
fn voice_findings(text: &str) -> Vec<Finding> {
    let mut out = Vec::new();
    let Some(body) = section_body(text, "Voice and tone") else {
        return out;
    };
    let joined = body
        .iter()
        .map(|(_, line)| line.as_str())
        .collect::<Vec<_>>()
        .join("\n")
        .to_lowercase();
    for (needle, rule) in [
        ("active voice", "active voice"),
        ("second person", "second person"),
    ] {
        if !joined.contains(needle) {
            out.push(at(
                CONTENT,
                format!("the voice section must name {rule} (B11.12)"),
            ));
        }
    }
    let Some((header, rows)) = section_table(text, "Voice and tone") else {
        out.push(at(
            CONTENT,
            "the `## Voice and tone` section needs a `Rule | Good | Bad` table (T-0019 step 1)",
        ));
        return out;
    };
    let (Some(i_rule), Some(i_good), Some(i_bad)) = (
        column(&header, "Rule"),
        column(&header, "Good"),
        column(&header, "Bad"),
    ) else {
        out.push(at(
            CONTENT,
            "the voice table header must be `Rule | Good | Bad` (T-0019 step 1)",
        ));
        return out;
    };
    if rows.len() < MIN_VOICE_ROWS {
        out.push(at(
            CONTENT,
            format!(
                "the voice table has {} rules; at least {MIN_VOICE_ROWS} are required",
                rows.len()
            ),
        ));
    }
    for (n, row) in &rows {
        let rule = cell(row, i_rule);
        let good = cell(row, i_good);
        let bad = cell(row, i_bad);
        if rule.is_empty() || good.is_empty() || bad.is_empty() {
            out.push(at(
                CONTENT,
                format!(
                    "the voice row at line {n} needs a rule, a good sentence and a bad sentence"
                ),
            ));
        } else if good.eq_ignore_ascii_case(&bad) {
            out.push(at(
                CONTENT,
                format!("the voice row at line {n} uses the same good and bad sentence"),
            ));
        }
    }
    out
}

/// `Vocabulary`: the four-column table, at least ten rows, the four required distinctions and no term that is
/// both canonical and avoided. Terms are whole words, so `blocklist` is not `block`.
fn vocabulary_findings(text: &str) -> Vec<Finding> {
    let mut out = Vec::new();
    let Some((header, rows)) = section_table(text, "Vocabulary") else {
        out.push(at(
            CONTENT,
            "the `## Vocabulary` section needs a `Concept | Canonical term | Avoid | Why` table (T-0019 step 1)",
        ));
        return out;
    };
    let (Some(i_concept), Some(i_canonical), Some(i_avoid), Some(i_why)) = (
        column(&header, "Concept"),
        column(&header, "Canonical term"),
        column(&header, "Avoid"),
        column(&header, "Why"),
    ) else {
        out.push(at(
            CONTENT,
            "the vocabulary table header must be `Concept | Canonical term | Avoid | Why` (T-0019 step 1)",
        ));
        return out;
    };
    if rows.len() < MIN_VOCAB_ROWS {
        out.push(at(
            CONTENT,
            format!(
                "the vocabulary table has {} rows; at least {MIN_VOCAB_ROWS} are required (T-0019 step 1)",
                rows.len()
            ),
        ));
    }
    let mut canonical: Vec<(usize, String)> = Vec::new();
    let mut avoided: Vec<(usize, String)> = Vec::new();
    for (n, row) in &rows {
        let concept = cell(row, i_concept);
        let term = cell(row, i_canonical);
        let avoid = cell(row, i_avoid);
        let why = cell(row, i_why);
        if concept.is_empty() || term.is_empty() || avoid.is_empty() || why.is_empty() {
            out.push(at(
                CONTENT,
                format!("the vocabulary row at line {n} needs all four cells"),
            ));
        }
        canonical.push((*n, term));
        avoided.push((*n, avoid));
    }
    for (n, term) in &canonical {
        if term.is_empty() {
            continue;
        }
        for (m, avoid) in &avoided {
            if has_phrase(avoid, term) {
                out.push(at(
                    CONTENT,
                    format!(
                        "the canonical term \"{term}\" of the row at line {n} is also an avoided term in the `Avoid` cell at line {m}; each concept has one term (T-0019 step 1)"
                    ),
                ));
            }
        }
    }
    for (canonical_term, avoided_term) in REQUIRED_DISTINCTIONS {
        match rows
            .iter()
            .find(|(_, row)| cell(row, i_canonical).eq_ignore_ascii_case(canonical_term))
        {
            None => out.push(at(
                CONTENT,
                format!(
                    "the vocabulary has no `{canonical_term}` row, so the `{canonical_term}` vs `{avoided_term}` distinction is not made (T-0019 step 1)"
                ),
            )),
            Some((n, row)) => {
                if !has_phrase(&cell(row, i_avoid), avoided_term) {
                    out.push(at(
                        CONTENT,
                        format!(
                            "the `{canonical_term}` row at line {n} must avoid \"{avoided_term}\" (T-0019 step 1)"
                        ),
                    ));
                }
            }
        }
    }
    out
}

/// `Message patterns`: at least ten examples covering the eight kinds, one well-formed semantic hyphenated key
/// per row and no repeated key.
fn message_pattern_findings(text: &str) -> Vec<Finding> {
    let mut out = Vec::new();
    let Some((header, rows)) = section_table(text, "Message patterns") else {
        out.push(at(
            CONTENT,
            "the `## Message patterns` section needs a `Pattern | Example text | i18n key` table (T-0019 step 3)",
        ));
        return out;
    };
    let (Some(i_pattern), Some(i_example), Some(i_key)) = (
        column(&header, "Pattern"),
        column(&header, "Example text"),
        column(&header, "i18n key"),
    ) else {
        out.push(at(
            CONTENT,
            "the message table header must be `Pattern | Example text | i18n key` (T-0019 step 3)",
        ));
        return out;
    };
    if rows.len() < MIN_MESSAGE_EXAMPLES {
        out.push(at(
            CONTENT,
            format!(
                "the message table has {} examples; at least {MIN_MESSAGE_EXAMPLES} are required (T-0019 A3)",
                rows.len()
            ),
        ));
    }
    let key_shape = Regex::new(KEY_SHAPE).ok();
    if key_shape.is_none() {
        out.push(at(CONTENT, "cannot compile the i18n key pattern"));
    }
    let mut counts: BTreeMap<String, usize> = BTreeMap::new();
    for (n, row) in &rows {
        let example = cell(row, i_example);
        let key = cell(row, i_key);
        if example.is_empty() || key.is_empty() {
            out.push(at(
                CONTENT,
                format!("the message row at line {n} needs an example and an i18n key"),
            ));
            continue;
        }
        if let Some(re) = &key_shape
            && !re.is_match(&key)
        {
            out.push(at(
                CONTENT,
                format!(
                    "the i18n key \"{key}\" at line {n} is not a semantic hyphenated stem (`domain-add-step2-title`)"
                ),
            ));
        }
        *counts.entry(key).or_insert(0) += 1;
    }
    for kind in MESSAGE_KINDS {
        let covered = rows
            .iter()
            .any(|(_, row)| has_phrase(&cell(row, i_pattern), kind));
        if !covered {
            out.push(at(
                CONTENT,
                format!("no message example covers the \"{kind}\" pattern (T-0019 A3)"),
            ));
        }
    }
    for (key, count) in counts {
        if count > 1 {
            out.push(at(
                CONTENT,
                format!(
                    "the i18n key \"{key}\" is used {count} times; every example needs its own key"
                ),
            ));
        }
    }
    out
}

/// `Visitor errors`: at least five forbidden disclosures, a reason per row, and the two prohibitions of B11.12.
fn visitor_error_findings(text: &str) -> Vec<Finding> {
    let mut out = Vec::new();
    if let Some(body) = section_body(text, "Visitor errors") {
        let joined = body
            .iter()
            .map(|(_, line)| line.as_str())
            .collect::<Vec<_>>()
            .join("\n")
            .to_lowercase();
        for (needle, rule) in [
            ("blame", "never blame the visitor"),
            ("detect", "never reveal detection logic"),
        ] {
            if !joined.contains(needle) {
                out.push(at(
                    CONTENT,
                    format!("the visitor-error section must say it will {rule} (B11.12)"),
                ));
            }
        }
    }
    let Some((header, rows)) = section_table(text, "Visitor errors") else {
        out.push(at(
            CONTENT,
            "the `## Visitor errors` section needs a `Forbidden disclosure | Why it is forbidden` table (T-0019 step 7)",
        ));
        return out;
    };
    let (Some(i_disclosure), Some(i_why)) = (
        column(&header, "Forbidden disclosure"),
        column(&header, "Why it is forbidden"),
    ) else {
        out.push(at(
            CONTENT,
            "the visitor-error table header must be `Forbidden disclosure | Why it is forbidden` (T-0019 step 7)",
        ));
        return out;
    };
    if rows.len() < MIN_VISITOR_FORBIDDEN {
        out.push(at(
            CONTENT,
            format!(
                "the visitor-error table has {} disclosures; at least {MIN_VISITOR_FORBIDDEN} are required (T-0019 step 7)",
                rows.len()
            ),
        ));
    }
    let mut seen: BTreeSet<String> = BTreeSet::new();
    for (n, row) in &rows {
        let disclosure = cell(row, i_disclosure);
        let why = cell(row, i_why);
        if disclosure.is_empty() || why.is_empty() {
            out.push(at(
                CONTENT,
                format!("the visitor-error row at line {n} needs a disclosure and a reason"),
            ));
            continue;
        }
        if !seen.insert(disclosure.to_lowercase()) {
            out.push(at(
                CONTENT,
                format!("the disclosure at line {n} is listed twice"),
            ));
        }
    }
    out
}

/// `Translation guidance`: a Fluent plural selector with `[one]` and `[other]`, a Fluent placeholder, the
/// no-concatenation rule and the no-text-in-images rule.
fn translation_findings(text: &str) -> Vec<Finding> {
    let mut out = Vec::new();
    let Some(body) = section_body(text, "Translation guidance") else {
        out.push(at(
            CONTENT,
            "the `## Translation guidance` section is missing (T-0019 A4)",
        ));
        return out;
    };
    let joined = body
        .iter()
        .map(|(_, line)| line.as_str())
        .collect::<Vec<_>>()
        .join("\n");
    if !joined.contains("[one]") || !joined.contains("[other]") {
        out.push(at(
            CONTENT,
            "the translation guidance needs a Fluent selector with `[one]` and `[other]` (T-0019 A4)",
        ));
    }
    let forbids_concatenation = joined.lines().any(|line| {
        let words = tokens(line);
        words.iter().any(|w| w.starts_with("concatenat"))
            && words.iter().any(|w| w == "sentence" || w == "sentences")
    });
    if !forbids_concatenation {
        out.push(at(
            CONTENT,
            "the translation guidance must forbid concatenating sentence fragments (T-0019 A4)",
        ));
    }
    let placeholder = Regex::new(r"\{\s*\$[a-z_]+\s*\}")
        .ok()
        .is_some_and(|re| re.is_match(&joined));
    if !placeholder {
        out.push(at(
            CONTENT,
            "the translation guidance needs a Fluent placeholder such as `{$domain}`",
        ));
    }
    if !joined.to_lowercase().contains("image") {
        out.push(at(
            CONTENT,
            "the translation guidance must forbid text in images (T-0019 A4)",
        ));
    }
    out
}

/// `Review of B13`: every B13 key stem exactly once, `pass` or a documented `exception:`, and a real note.
fn b13_review_findings(text: &str, b13_keys: &[String]) -> Vec<Finding> {
    let mut out = Vec::new();
    let Some((header, rows)) = section_table(text, "Review of B13") else {
        out.push(at(
            CONTENT,
            "the `## Review of B13` section needs a `Key stem | Result | Note` table (T-0019 step 8)",
        ));
        return out;
    };
    let (Some(i_key), Some(i_result), Some(i_note)) = (
        column(&header, "Key stem"),
        column(&header, "Result"),
        column(&header, "Note"),
    ) else {
        out.push(at(
            CONTENT,
            "the B13 review table header must be `Key stem | Result | Note` (T-0019 step 8)",
        ));
        return out;
    };
    let mut counts: BTreeMap<String, usize> = BTreeMap::new();
    for (n, row) in &rows {
        let key = plain(&cell(row, i_key));
        let result = cell(row, i_result).to_lowercase();
        let note = cell(row, i_note);
        if key.is_empty() {
            out.push(at(
                CONTENT,
                format!("the B13 review row at line {n} has no key stem"),
            ));
            continue;
        }
        *counts.entry(key.clone()).or_insert(0) += 1;
        if note.is_empty() {
            out.push(at(
                CONTENT,
                format!("the B13 review row for \"{key}\" has no note"),
            ));
        }
        let documented_exception = result
            .strip_prefix("exception")
            .is_some_and(|rest| rest.trim_start().starts_with(':') && rest.trim().len() > 1);
        if result != "pass" && !documented_exception {
            out.push(at(
                CONTENT,
                format!(
                    "the result for \"{key}\" is \"{result}\"; it must be `pass` or `exception: <reason>` (T-0019 step 8)"
                ),
            ));
        }
    }
    for key in b13_keys {
        match counts.get(key) {
            None => out.push(at(
                CONTENT,
                format!("the B13 review is missing the key stem \"{key}\" (T-0019 step 8)"),
            )),
            Some(1) => {}
            Some(count) => out.push(at(
                CONTENT,
                format!(
                    "the B13 review lists \"{key}\" {count} times; it must appear exactly once"
                ),
            )),
        }
    }
    for key in counts.keys() {
        if !b13_keys.iter().any(|k| k == key) {
            out.push(at(
                CONTENT,
                format!("the B13 review lists \"{key}\", which the B13 copy deck does not have"),
            ));
        }
    }
    out
}

/// One glossary row parsed from the table.
struct GlossaryRow {
    /// 1-based line number of the row.
    line: usize,
    /// The term cell, backticks removed.
    term: String,
    /// The plain definition cell.
    definition: String,
    /// The `Do not translate` cell.
    translate: String,
}

/// The rows of the `## Terms` table of a glossary, or `None` when the section or a column is missing.
fn glossary_rows(text: &str) -> Option<Vec<GlossaryRow>> {
    let (header, rows) = section_table(text, "Terms")?;
    let i_term = column(&header, "Term")?;
    let i_definition = column(&header, "Plain definition")?;
    let i_translate = column(&header, "Do not translate")?;
    Some(
        rows.into_iter()
            .map(|(line, row)| GlossaryRow {
                line,
                term: plain(&cell(&row, i_term)),
                definition: cell(&row, i_definition),
                translate: cell(&row, i_translate),
            })
            .collect(),
    )
}

/// The words of a definition that are uppercase jargon (two or more uppercase letters and digits).
fn uppercase_words(text: &str) -> Vec<String> {
    let Ok(re) = Regex::new(r"\b[A-Z][A-Z0-9]{1,}\b") else {
        return Vec::new();
    };
    re.find_iter(text)
        .map(|m| m.as_str().to_lowercase())
        .collect()
}

/// Exactly one sentence: one terminal punctuation mark at the end and no sentence break inside the definition.
fn one_sentence(definition: &str) -> bool {
    let trimmed = definition.trim();
    let body = trimmed.trim_end_matches(['.', '!', '?']);
    !body.is_empty()
        && body.len() < trimmed.len()
        && !body.bytes().any(|b| matches!(b, b'.' | b'!' | b'?'))
}

/// Findings for the two glossary files. They carry the same terms; each definition is one sentence of at most
/// thirty words, uses no jargon outside the terms and no forbidden claims phrase.
pub fn glossary_findings(
    text: &str,
    i18n_text: &str,
    claims_cfg: Option<&claims::Config>,
) -> Vec<Finding> {
    let mut out = Vec::new();
    let Some(rows) = glossary_rows(text) else {
        out.push(at(
            GLOSSARY,
            "the glossary needs a `## Terms` table with `Term | Plain definition | Do not translate` (T-0019 step 2)",
        ));
        return out;
    };
    let Some(i18n_rows) = glossary_rows(i18n_text) else {
        out.push(at(
            I18N_GLOSSARY,
            "the translator glossary needs the same `## Terms` table (T-0019 step 2)",
        ));
        return out;
    };
    let terms: BTreeSet<String> = rows.iter().map(|r| r.term.to_lowercase()).collect();
    let i18n_terms: BTreeSet<String> = i18n_rows.iter().map(|r| r.term.to_lowercase()).collect();
    let mut allowed: BTreeSet<String> = terms
        .iter()
        .flat_map(|term| tokens(term))
        .collect::<BTreeSet<String>>();
    for term in &i18n_terms {
        allowed.extend(tokens(term));
    }
    allowed.extend(ALLOWED_ACRONYMS.iter().map(|a| a.to_lowercase()));
    for term in GLOSSARY_TERMS {
        if !terms.contains(&term.to_lowercase()) {
            out.push(at(
                GLOSSARY,
                format!("the glossary does not define \"{term}\" (T-0019 step 2)"),
            ));
        }
    }
    for term in terms.difference(&i18n_terms) {
        out.push(at(
            I18N_GLOSSARY,
            format!("the translator glossary does not carry the term \"{term}\""),
        ));
    }
    for term in i18n_terms.difference(&terms) {
        out.push(at(
            GLOSSARY,
            format!("the glossary lacks the term \"{term}\" that the translator copy has"),
        ));
    }
    for (location, list) in [(GLOSSARY, &rows), (I18N_GLOSSARY, &i18n_rows)] {
        for row in list {
            if row.definition.is_empty() {
                out.push(at(
                    location,
                    format!(
                        "the definition of \"{}\" at line {} is empty",
                        row.term, row.line
                    ),
                ));
                continue;
            }
            let words = row.definition.split_whitespace().count();
            if words > MAX_DEFINITION_WORDS {
                out.push(at(
                    location,
                    format!(
                        "the definition of \"{}\" at line {} has {words} words; at most {MAX_DEFINITION_WORDS} are allowed (T-0019 A1)",
                        row.term, row.line
                    ),
                ));
            }
            if !one_sentence(&row.definition) {
                out.push(at(
                    location,
                    format!(
                        "the definition of \"{}\" at line {} must be exactly one sentence (T-0019 A1)",
                        row.term, row.line
                    ),
                ));
            }
            for word in uppercase_words(&row.definition) {
                if !allowed.contains(&word) {
                    out.push(at(
                        location,
                        format!(
                            "the definition of \"{}\" at line {} uses the jargon \"{}\" that the glossary does not define",
                            row.term,
                            row.line,
                            word.to_uppercase()
                        ),
                    ));
                }
            }
            let do_not_translate = row.translate.to_lowercase();
            if do_not_translate != "yes" && do_not_translate != "no" {
                out.push(at(
                    location,
                    format!(
                        "the `Do not translate` cell of \"{}\" at line {} must be yes or no",
                        row.term, row.line
                    ),
                ));
            }
        }
    }
    if let Some(cfg) = claims_cfg {
        for row in &rows {
            for finding in claims::scan_text(
                cfg,
                &format!("{location}:{line}", location = GLOSSARY, line = row.line),
                &format!("{}\n", row.definition),
            ) {
                out.push(at(
                    format!("{}:{}", GLOSSARY, row.line),
                    format!("the definition of \"{}\": {}", row.term, finding.message),
                ));
            }
        }
    }
    out
}

/// Whole content check on the repository at `root`, with the master specification already loaded by the caller.
pub fn check(root: &Path, spec: &str) -> Vec<Finding> {
    let mut out = Vec::new();
    let b13 = b13_rows(spec);
    if b13.is_empty() {
        out.push(at(
            "docs/SPEC.md",
            "the B13 copy deck has no key rows, so the content documents cannot be checked against it",
        ));
    }
    let keys: Vec<String> = b13.into_iter().map(|(key, _)| key).collect();
    let claims_cfg = claims::load_config(root).ok();
    match read_text(&root.join(CONTENT)) {
        Ok(text) => out.extend(content_findings(&text, &keys, claims_cfg.as_ref())),
        Err(_) => out.push(at(
            CONTENT,
            "the document does not exist (T-0019 step 1 to 3)",
        )),
    }
    match read_text(&root.join(GLOSSARY)) {
        Ok(text) => match read_text(&root.join(I18N_GLOSSARY)) {
            Ok(i18n) => out.extend(glossary_findings(&text, &i18n, claims_cfg.as_ref())),
            Err(_) => out.push(at(
                I18N_GLOSSARY,
                "the translator glossary does not exist (T-0019 step 2)",
            )),
        },
        Err(_) => out.push(at(GLOSSARY, "the glossary does not exist (T-0019 step 2)")),
    }
    out
}

#[cfg(test)]
pub(crate) mod fixtures {
    //! Fixtures shared by the content tests and the `ux-docs` fixture tree.

    /// The B13 section of the fixture specification: four keys, in the master's table shape.
    pub(crate) fn b13_spec_section() -> &'static str {
        "## B13. Copy deck (canonical strings that tests and docs reference)\n\n\
         | Key stem | Text |\n| --- | --- |\n\
         | `tagline` | Put a firewall in front of your website. See what it blocks. Undo anything. |\n\
         | `signup-title` | Create your account |\n\
         | `success-saved` | Saved. Your change is live. |\n\
         | `readiness-footnote` | Measures configuration completeness, not security. |\n"
    }

    /// A content document that satisfies every rule.
    pub(crate) fn content() -> String {
        String::from(
            "# Content fixture\n\n\
             ## Voice and tone\n\n\
             Write short sentences in active voice and second person, and say what happened next.\n\n\
             | Rule | Good | Bad |\n| --- | --- | --- |\n\
             | Plain words | Monitor mode records what HDD would block. | The WAF operates in a non-blocking observation state. |\n\
             | Active voice | You added example.org. | The domain has been added by the system. |\n\
             | Numbers first | 412 requests were blocked in the last hour. | Many attacks were stopped. |\n\
             | Next action | Paste the TXT record at your provider. | The verification is incomplete. |\n\
             \n## Vocabulary\n\n\
             | Concept | Canonical term | Avoid | Why |\n| --- | --- | --- | --- |\n\
             | A name the owner adds | domain | site, web property | A domain is the unit the operator changes. |\n\
             | Traffic through HDD | proxied | orange cloud, on cloud | The state is about the record, not a product. |\n\
             | One refused request | block | deny, drop | The console and the block page use the same verb. |\n\
             | A timed address restriction | ban | jail entry, blocklist entry | A ban has a reason and a time limit. |\n\
             | The server behind HDD | origin | backend, upstream server | Lockdown must name one thing. |\n\
             | Recording mode | monitor mode | dry run, passive mode | The selector and the events use one name. |\n\
             | Enforcement mode | block mode | active mode, firewall mode | The mode names the visitor effect. |\n\
             | A visitor proof step | challenge | captcha, puzzle | Some challenges are not visual. |\n\
             | One request decision | event | hit, log line | Events are stored and filtered. |\n\
             | The request reference | Ray ID | request id, trace id | The block page and the appeal quote it. |\n\
             | Addresses exempt from bans | never-ban list | allowlist, whitelist | An allowlist admits; this list only exempts. |\n\
             | DNS servers for a domain | nameserver | name server, NS host | The wizard names the records it asks for. |\n\
             | Setup completeness | readiness | security score, grade | Readiness is not a security measure. |\n\
             | A group of matching rules | ruleset | signature set, policy pack | Rules ship in named groups. |\n\
             \n## Capitalization and punctuation\n\n\
             Sentence case for headings, labels and buttons. No period on a button. One space after a period.\n\n\
             ## Number, date and unit formats\n\n\
             | Item | Format | Example |\n| --- | --- | --- |\n\
             | Requests | whole number, grouped in threes | 1,204 requests |\n\
             | Dates | year first, month, day | 2026-10-19 |\n\
             | Times | 24-hour with the zone | 14:05 UTC |\n\
             | Durations | number and unit | 45 seconds |\n\
             \n## Message patterns\n\n\
             | Pattern | Example text | i18n key |\n| --- | --- | --- |\n\
             | Success | Domain added. DNS checks run every minute. | domain-add-success |\n\
             | Success | Two recovery codes copied. | recovery-codes-copied |\n\
             | Validation error | Enter a domain name, like example.org. | domain-name-invalid |\n\
             | Validation error | The code must be six digits. | mfa-code-format |\n\
             | System error | Something went wrong on our side. Try again in a moment. | system-error-retry |\n\
             | System error | The API is unavailable right now. The change was not saved. | api-unavailable |\n\
             | Destructive confirmation | This removes the domain and its history. Type the domain name to confirm. | domain-delete-confirm |\n\
             | Destructive confirmation | Block mode will ban the sending address. You can switch back. | block-mode-confirm |\n\
             | Empty state | No events yet. Requests appear here within seconds. | no-events-empty |\n\
             | Empty state | You have not added a domain yet. Add one to start. | no-domains-empty |\n\
             | Limit reached | You reached the 10 domain limit on this plan. | domains-limit-reached |\n\
             | Security notice | This account is read-only for support. Changes are disabled. | support-readonly-notice |\n\
             | Email subject line | Confirm your email address for HDD | email-verify-subject |\n\
             \n## Visitor errors\n\n\
             A block page never blames the visitor and never reveals how detection works.\n\n\
             | Forbidden disclosure | Why it is forbidden |\n| --- | --- |\n\
             | The rule name or id that matched | A visitor can tune the next request to that rule. |\n\
             | The matched payload or header value | It repeats an attack string on a public page. |\n\
             | The detection threshold or paranoia level | It tells an attacker how far a request may go. |\n\
             | The client address or its country | It exposes data about a third party. |\n\
             | The ban time or the next block step | It tells the reader when to retry. |\n\
             | The internal event id or operator note | It leaks console-only data. |\n\
             | Whether the address is shared with an attacker | The page cannot settle that dispute. |\n\
             \n## Translation guidance\n\n\
             - Never concatenate sentence fragments. One sentence is one message with its placeables.\n\
             - Use Fluent placeables such as `{$domain}` inside the sentence.\n\
             - A count uses a selector with `[one]` and `[other]`, and the translator writes both variants.\n\
             \n```fluent\n\
             events-count = { $count ->\n\
                 [one] { $count } event\n\
                *[other] { $count } events\n\
             }\n\
             ```\n\
             \n- Write gender-neutral wording: the owner, not he or she.\n\
             - Never put text in an image; every label is a string key.\n\
             \n## Review of B13\n\n\
             | Key stem | Result | Note |\n| --- | --- | --- |\n\
             | `tagline` | pass | Landing headline; three actions, no security claim. |\n\
             | `signup-title` | pass | Sign-up heading; sentence case and no exclamation mark. |\n\
             | `success-saved` | pass | Success confirmation; the exclamation is allowed but not used. |\n\
             | `readiness-footnote` | pass | Readiness footnote; says what the score measures and what it does not. |\n",
        )
    }

    /// A glossary that satisfies every rule; used for both glossary files in the fixture tree.
    pub(crate) fn glossary() -> String {
        String::from(
            "# Glossary fixture\n\n\
             ## Terms\n\n\
             | Term | Plain definition | Do not translate |\n| --- | --- | --- |\n\
             | WAF | A filter that inspects web requests and blocks those that match a rule. | yes |\n\
             | SQL injection | An attack that puts database commands into a request so the database runs them. | no |\n\
             | XSS | An attack that puts script into a page so it runs in a visitor's browser. | yes |\n\
             | DNS | The system that turns a domain name into the addresses of the servers that answer for it. | yes |\n\
             | nameserver | A DNS server that answers the records for a domain. | no |\n\
             | CNAME | A DNS record that points one name at another name instead of an address. | yes |\n\
             | TLS | The protocol that encrypts traffic between a visitor and a website. | yes |\n\
             | HSTS | A rule that tells browsers to use TLS only for a domain after the first visit. | yes |\n\
             | origin | The server that hosts the website behind HDD. | no |\n\
             | ban | A timed restriction placed on an address after a matching request. | no |\n\
             | challenge | A short automatic step that a visitor passes before a request continues. | no |\n\
             | Ray ID | The identifier that links a blocked request on the page to one event in the console. | yes |\n\
             | proxied | A record state in which traffic for that name passes through HDD. | no |\n\
             | monitor mode | A mode that records the requests HDD would block and lets them through. | no |\n\
             | block mode | A mode that blocks matching requests and bans the sending address. | no |\n\
             | never-ban list | A list of addresses that HDD never bans, even during an attack. | no |\n",
        )
    }

    /// A copy deck for the four fixture B13 keys, with values equal to the fixture specification.
    pub(crate) fn copy_deck() -> &'static str {
        "# Copy deck fixture. Key naming: lowercase semantic words joined by hyphens.\n\
         tagline = Put a firewall in front of your website. See what it blocks. Undo anything.\n\
         signup-title = Create your account\n\
         success-saved = Saved. Your change is live.\n\
         readiness-footnote = Measures configuration completeness, not security.\n"
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used, clippy::unwrap_used, reason = "tests")]

    use super::fixtures::{b13_spec_section, content, glossary};
    use super::*;

    fn keys() -> Vec<String> {
        b13_rows(b13_spec_section())
            .into_iter()
            .map(|(key, _)| key)
            .collect()
    }

    fn messages(findings: &[Finding]) -> String {
        findings
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>()
            .join("\n")
    }

    fn content_messages(text: &str) -> String {
        messages(&content_findings(text, &keys(), None))
    }

    fn glossary_messages(text: &str, i18n: &str) -> String {
        messages(&glossary_findings(text, i18n, None))
    }

    #[test]
    fn b13_rows_are_read_from_the_table_and_keep_empty_text() {
        let rows = b13_rows(b13_spec_section());
        assert_eq!(rows.len(), 4, "{rows:?}");
        assert_eq!(rows.first().map(|(k, _)| k.as_str()), Some("tagline"));
        assert!(b13_rows("no copy deck here\n").is_empty());
        let with_empty = "## B13. Copy deck (canonical strings that tests and docs reference)\n\n\
             | Key stem | Text |\n| --- | --- |\n| `empty-key` |  |\n";
        assert_eq!(
            b13_rows(with_empty),
            vec![("empty-key".to_owned(), String::new())]
        );
    }

    #[test]
    fn a_complete_content_fixture_passes() {
        let findings = content_findings(&content(), &keys(), None);
        assert!(findings.is_empty(), "{}", messages(&findings));
    }

    #[test]
    fn every_required_content_section_is_named() {
        let text = content().replace("## Translation guidance", "## Translation notes");
        let m = content_messages(&text);
        assert!(m.contains("Translation guidance"), "{m}");
    }

    #[test]
    fn each_voice_rule_needs_a_good_and_a_bad_sentence() {
        let text = content().replace(
            "| Plain words | Monitor mode records what HDD would block. |",
            "| Plain words |  |",
        );
        let m = content_messages(&text);
        assert!(m.contains("voice"), "{m}");
        assert!(m.contains("Good") || m.contains("good"), "{m}");
        let no_active = content()
            .replace("in active voice and second person", "in second person")
            .replace(
                "| Active voice | You added example.org. |",
                "| Style | You added example.org. |",
            );
        assert!(
            content_messages(&no_active).contains("active voice"),
            "{}",
            content_messages(&no_active)
        );
    }

    #[test]
    fn vocabulary_needs_ten_rows_and_the_required_distinctions() {
        let short = content()
            .replace("| A group of matching rules | ruleset | signature set, policy pack | Rules ship in named groups. |\n", "")
            .replace("| Setup completeness | readiness | security score, grade | Readiness is not a security measure. |\n", "")
            .replace("| DNS servers for a domain | nameserver | name server, NS host | The wizard names the records it asks for. |\n", "")
            .replace("| Addresses exempt from bans | never-ban list | allowlist, whitelist | An allowlist admits; this list only exempts. |\n", "")
            .replace("| The request reference | Ray ID | request id, trace id | The block page and the appeal quote it. |\n", "");
        assert!(
            content_messages(&short).contains("at least 10"),
            "{}",
            content_messages(&short)
        );
        let no_block = content().replace(
            "| One refused request | block | deny, drop |",
            "| One refused request | refuse | deny, drop |",
        );
        let m = content_messages(&no_block);
        assert!(m.contains("block"), "{m}");
        assert!(m.contains("deny"), "{m}");
    }

    #[test]
    fn a_canonical_term_may_not_be_an_avoided_term() {
        let text = content().replace(
            "| A group of matching rules | ruleset | signature set, policy pack | Rules ship in named groups. |",
            "| A refusal | deny | block, drop | A refusal names the answer, not the action. |",
        );
        let m = content_messages(&text);
        assert!(m.contains("canonical") || m.contains("block"), "{m}");
    }

    #[test]
    fn avoided_terms_are_whole_words_not_substrings() {
        let substring = content().replace(
            "| A group of matching rules | ruleset | signature set, policy pack | Rules ship in named groups. |",
            "| A group of matching rules | ruleset | blocklist entry | Rules ship in named groups. |",
        );
        assert!(
            content_findings(&substring, &keys(), None).is_empty(),
            "{}",
            content_messages(&substring)
        );
        let whole = content().replace(
            "| A group of matching rules | ruleset | signature set, policy pack | Rules ship in named groups. |",
            "| A group of matching rules | ruleset | block list | Rules ship in named groups. |",
        );
        let m = content_messages(&whole);
        assert!(m.contains("block"), "{m}");
    }

    #[test]
    fn message_patterns_need_ten_examples_and_all_eight_kinds() {
        let short = content()
            .replace("| Success | Two recovery codes copied. | recovery-codes-copied |\n", "")
            .replace("| Validation error | The code must be six digits. | mfa-code-format |\n", "")
            .replace("| Empty state | You have not added a domain yet. Add one to start. | no-domains-empty |\n", "")
            .replace("| Email subject line | Confirm your email address for HDD | email-verify-subject |\n", "");
        assert!(
            content_messages(&short).contains("at least 10"),
            "{}",
            content_messages(&short)
        );
        let no_limit = content().replace(
            "| Limit reached | You reached the 10 domain limit on this plan. | domains-limit-reached |\n",
            "",
        );
        let m = content_messages(&no_limit);
        assert!(m.contains("limit reached"), "{m}");
    }

    #[test]
    fn message_keys_are_semantic_hyphenated_stems() {
        let text = content().replace("domain-add-success", "Domain added successfully");
        let m = content_messages(&text);
        assert!(m.contains("i18n key") || m.contains("key"), "{m}");
        let repeated = content().replace("recovery-codes-copied", "domain-add-success");
        let m = content_messages(&repeated);
        assert!(m.contains("used") || m.contains("repeat"), "{m}");
    }

    #[test]
    fn visitor_errors_need_five_forbidden_disclosures() {
        let text = content()
            .replace("| The rule name or id that matched | A visitor can tune the next request to that rule. |\n", "")
            .replace("| The client address or its country | It exposes data about a third party. |\n", "")
            .replace("| The internal event id or operator note | It leaks console-only data. |\n", "");
        let m = content_messages(&text);
        assert!(m.contains("five") || m.contains("at least 5"), "{m}");
        let no_blame = content().replace(
            "A block page never blames the visitor and never reveals how detection works.",
            "A block page explains the refusal.",
        );
        let m = content_messages(&no_blame);
        assert!(m.contains("blame") || m.contains("detection"), "{m}");
    }

    #[test]
    fn translation_guidance_needs_fluent_plurals_and_the_no_concatenation_rule() {
        let no_other = content().replace("[other]", "other");
        let m = content_messages(&no_other);
        assert!(m.contains("[other]") || m.contains("other"), "{m}");
        let no_rule = content().replace(
            "- Never concatenate sentence fragments. One sentence is one message with its placeables.\n",
            "",
        );
        let m = content_messages(&no_rule);
        assert!(m.contains("concatenat") || m.contains("sentence"), "{m}");
        let no_placeholder = content().replace("`{$domain}`", "the domain");
        let m = content_messages(&no_placeholder);
        assert!(m.contains("placeholder") || m.contains("placeable"), "{m}");
    }

    #[test]
    fn b13_review_lists_every_key_exactly_once() {
        let missing = content().replace(
            "| `tagline` | pass | Landing headline; three actions, no security claim. |\n",
            "",
        );
        let m = content_messages(&missing);
        assert!(m.contains("tagline"), "{m}");
        let twice = content().replace(
            "| `signup-title` | pass | Sign-up heading; sentence case and no exclamation mark. |",
            "| `tagline` | pass | A second row for the same key. |",
        );
        let m = content_messages(&twice);
        assert!(m.contains("signup-title") || m.contains("twice"), "{m}");
        let extra = content().replace(
            "| `success-saved` | pass | Success confirmation; the exclamation is allowed but not used. |",
            "| `not-in-b13` | pass | A key the specification does not have. |",
        );
        let m = content_messages(&extra);
        assert!(m.contains("not-in-b13"), "{m}");
    }

    #[test]
    fn b13_review_result_is_pass_or_a_documented_exception() {
        let text = content().replace(
            "| `tagline` | pass | Landing headline; three actions, no security claim. |",
            "| `tagline` | done | Landing headline; three actions, no security claim. |",
        );
        let m = content_messages(&text);
        assert!(m.contains("pass") || m.contains("exception"), "{m}");
        let documented = content().replace(
            "| `tagline` | pass | Landing headline; three actions, no security claim. |",
            "| `tagline` | exception: the legal review owns this string | Landing headline. |",
        );
        assert!(
            content_findings(&documented, &keys(), None).is_empty(),
            "{}",
            content_messages(&documented)
        );
    }

    #[test]
    fn glossary_definitions_are_one_sentence_of_at_most_thirty_words() {
        let two = glossary().replace(
            "A filter that inspects web requests and blocks those that match a rule.",
            "A filter that inspects web requests. It blocks matching requests.",
        );
        assert!(
            glossary_messages(&two, &glossary()).contains("one sentence"),
            "{}",
            glossary_messages(&two, &glossary())
        );
        let long = format!("A filter that inspects {} rules.", "many ".repeat(30));
        let over = glossary().replace(
            "A filter that inspects web requests and blocks those that match a rule.",
            &long,
        );
        assert!(
            glossary_messages(&over, &glossary()).contains("30"),
            "{}",
            glossary_messages(&over, &glossary())
        );
    }

    #[test]
    fn every_required_glossary_term_is_defined() {
        let no_xss = glossary().replace(
            "| XSS | An attack that puts script into a page so it runs in a visitor's browser. | yes |\n",
            "",
        );
        assert!(
            glossary_messages(&no_xss, &no_xss).contains("XSS"),
            "{}",
            glossary_messages(&no_xss, &no_xss)
        );
    }

    #[test]
    fn the_two_glossaries_carry_the_same_terms() {
        let i18n = glossary().replace(
            "| WAF | A filter that inspects web requests and blocks those that match a rule. | yes |\n",
            "",
        );
        assert!(
            glossary_messages(&glossary(), &i18n)
                .to_lowercase()
                .contains("waf"),
            "{}",
            glossary_messages(&glossary(), &i18n)
        );
    }

    #[test]
    fn a_glossary_definition_with_a_forbidden_claim_fails() {
        let cfg: claims::Config = toml::from_str(include_str!("../../../../docs/claims-lint.toml"))
            .expect("shipped config");
        let text = glossary().replace(
            "A filter that inspects web requests and blocks those that match a rule.",
            "A rule that gives absolute protection to every request.",
        );
        let findings = glossary_findings(&text, &text, Some(&cfg));
        let m = messages(&findings);
        assert!(m.contains("absolute protection"), "{m}");
    }
}
