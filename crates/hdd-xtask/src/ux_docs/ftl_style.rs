//! `ux-docs` style checks for the Fluent copy deck (T-0019 step 5, A2).
//!
//! The rules, stated here because this module enforces them on `i18n/en/copy-deck.ftl`:
//!
//! * every key matches `^[a-z0-9]+(-[a-z0-9]+)*$` (a semantic hyphenated stem, never a sentence);
//! * a key is defined once, and the file contains exactly the key stems of B13: none missing, none added;
//! * the value of a key equals the English text of its B13 row in the master specification; an empty value is allowed
//!   only above the comment `# empty: needs text`;
//! * no value contains an emoji, `<` markup, or a duplicate of another value;
//! * an exclamation mark appears only in a key that starts with `success-` or ends with `-success`;
//! * a message that uses the `$count` variable has a selector with both `[one]` and `[other]`;
//! * no value contains a forbidden claims phrase (the existing [`crate::claims`] scanner runs on the value at the
//!   copy-deck path, so the context rules of `docs/claims-lint.toml` apply too).
//!
//! The `i18n check` stub (T-0082) is untouched: this check runs as part of `cargo xtask ux-docs`.

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

use regex::Regex;

use crate::claims;
use crate::util::{Finding, read_text};

use super::content::b13_rows;

/// The English copy deck.
pub const COPY_DECK: &str = "i18n/en/copy-deck.ftl";
/// The comment that must sit above an intentionally empty value.
pub const EMPTY_COMMENT: &str = "empty: needs text";

/// Shape of a semantic i18n key stem.
const KEY_SHAPE: &str = r"^[a-z0-9]+(-[a-z0-9]+)*$";

/// One message line of the Fluent file.
struct Message {
    /// 1-based line number.
    line: usize,
    /// The key on the left of `=`.
    key: String,
    /// The value on the right of `=`, trimmed.
    value: String,
}

/// A `ux-docs` finding at `location`.
fn at(location: impl Into<String>, message: impl Into<String>) -> Finding {
    Finding::new("ux-docs", location, message)
}

/// Parse the messages of a Fluent file: comment and blank lines are skipped; every other line must be `key = value`.
fn parse(text: &str) -> Vec<Message> {
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

/// True when `text` contains a character that renders as an emoji or a decorative dingbat.
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

/// Findings of the style rules for one parsed deck.
fn style_findings(
    messages: &[Message],
    b13: &[(String, String)],
    text: &str,
    claims_cfg: Option<&claims::Config>,
) -> Vec<Finding> {
    let mut out = Vec::new();
    let key_shape = Regex::new(KEY_SHAPE).ok();
    if key_shape.is_none() {
        out.push(at(COPY_DECK, "cannot compile the i18n key pattern"));
    }
    let lines: Vec<&str> = text.lines().collect();
    let mut key_counts: BTreeMap<String, usize> = BTreeMap::new();
    let mut values: BTreeMap<String, Vec<String>> = BTreeMap::new();
    for m in messages {
        if m.key.is_empty() {
            out.push(at(
                COPY_DECK,
                format!("line {} is not a `key = value` message", m.line),
            ));
            continue;
        }
        if let Some(re) = &key_shape
            && !re.is_match(&m.key)
        {
            out.push(at(
                COPY_DECK,
                format!(
                    "the i18n key \"{}\" at line {} is not a semantic hyphenated stem",
                    m.key, m.line
                ),
            ));
        }
        *key_counts.entry(m.key.clone()).or_insert(0) += 1;
        if m.value.is_empty() {
            let commented = m
                .line
                .checked_sub(2)
                .and_then(|index| lines.get(index))
                .is_some_and(|line| line.contains(EMPTY_COMMENT));
            if !commented {
                out.push(at(
                    COPY_DECK,
                    format!(
                        "the key \"{}\" at line {} has an empty value without the `# {EMPTY_COMMENT}` comment above it",
                        m.key, m.line
                    ),
                ));
            }
            continue;
        }
        if has_emoji(&m.value) {
            out.push(at(
                COPY_DECK,
                format!(
                    "the value of \"{}\" at line {} contains an emoji",
                    m.key, m.line
                ),
            ));
        }
        if m.value.contains('!') && !(m.key.starts_with("success-") || m.key.ends_with("-success"))
        {
            out.push(at(
                COPY_DECK,
                format!(
                    "the exclamation mark in \"{}\" at line {} is only allowed in a `success-` key",
                    m.key, m.line
                ),
            ));
        }
        if m.value.contains('<') {
            out.push(at(
                COPY_DECK,
                format!(
                    "the value of \"{}\" at line {} contains `<` markup",
                    m.key, m.line
                ),
            ));
        }
        if m.value.contains("$count") && !(m.value.contains("[one]") && m.value.contains("[other]"))
        {
            out.push(at(
                COPY_DECK,
                format!(
                    "the key \"{}\" at line {} uses `$count` without a selector with `[one]` and `[other]`",
                    m.key, m.line
                ),
            ));
        }
        values
            .entry(m.value.clone())
            .or_default()
            .push(m.key.clone());
    }
    for (key, count) in &key_counts {
        if *count > 1 {
            out.push(at(
                COPY_DECK,
                format!("the key \"{key}\" is defined {count} times; it must appear exactly once"),
            ));
        }
    }
    for (value, keys) in &values {
        if keys.len() > 1 {
            out.push(at(
                COPY_DECK,
                format!(
                    "the keys {} share the same value \"{value}\", so a translator cannot tell them apart",
                    keys.join(", ")
                ),
            ));
        }
    }
    let expected: BTreeSet<&str> = b13.iter().map(|(key, _)| key.as_str()).collect();
    for (key, expected_value) in b13 {
        if !key_counts.contains_key(key) {
            out.push(at(
                COPY_DECK,
                format!("the copy deck is missing the B13 key \"{key}\""),
            ));
            continue;
        }
        let want = expected_value.trim();
        for message in messages.iter().filter(|message| &message.key == key) {
            if want.is_empty() {
                if !message.value.is_empty() {
                    out.push(at(
                        COPY_DECK,
                        format!(
                            "the B13 row \"{key}\" has no text, so its value at line {} must be empty",
                            message.line
                        ),
                    ));
                }
            } else if message.value != want {
                out.push(at(
                    COPY_DECK,
                    format!(
                        "the value of \"{key}\" at line {} differs from the B13 text in the master specification",
                        message.line
                    ),
                ));
            }
        }
    }
    for key in key_counts.keys() {
        if !expected.contains(key.as_str()) {
            out.push(at(
                COPY_DECK,
                format!("the key \"{key}\" is not in the B13 copy deck"),
            ));
        }
    }
    if let Some(cfg) = claims_cfg {
        for message in messages {
            if message.value.is_empty() {
                continue;
            }
            for finding in claims::scan_text(cfg, COPY_DECK, &format!("{}\n", message.value)) {
                out.push(at(
                    format!("{COPY_DECK}:{}", message.line),
                    format!("the value of \"{}\": {}", message.key, finding.message),
                ));
            }
        }
    }
    out
}

/// Whole style check on the repository at `root`, with the master specification already loaded by the caller.
pub fn check(root: &Path, spec: &str) -> Vec<Finding> {
    let b13 = b13_rows(spec);
    let claims_cfg = claims::load_config(root).ok();
    let text = match read_text(&root.join(COPY_DECK)) {
        Ok(text) => text,
        Err(_) => {
            return vec![at(
                COPY_DECK,
                "the copy deck does not exist (T-0019 step 5)",
            )];
        }
    };
    let mut out = Vec::new();
    if b13.is_empty() {
        out.push(at(
            "docs/SPEC.md",
            "the B13 copy deck has no key rows, so the copy deck cannot be checked against it",
        ));
    }
    out.extend(style_findings(
        &parse(&text),
        &b13,
        &text,
        claims_cfg.as_ref(),
    ));
    out
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used, clippy::unwrap_used, reason = "tests")]

    use super::super::content::fixtures::{b13_spec_section, copy_deck};
    use super::*;

    fn fixture_b13() -> Vec<(String, String)> {
        b13_rows(b13_spec_section())
    }

    fn messages(findings: &[Finding]) -> String {
        findings
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>()
            .join("\n")
    }

    fn deck_findings(deck: &str, b13: &[(String, String)]) -> String {
        messages(&style_findings(&parse(deck), b13, deck, None))
    }

    fn one(key: &str, text: &str) -> Vec<(String, String)> {
        vec![(key.to_owned(), text.to_owned())]
    }

    #[test]
    fn a_complete_fixture_deck_passes() {
        let findings = style_findings(&parse(copy_deck()), &fixture_b13(), copy_deck(), None);
        assert!(findings.is_empty(), "{}", messages(&findings));
    }

    #[test]
    fn keys_are_semantic_hyphenated_stems() {
        let m = deck_findings("Signup Title = Create your account\n", &fixture_b13());
        assert!(m.contains("key"), "{m}");
        let m = deck_findings(
            "two--hyphens = A value.\n",
            &one("two--hyphens", "A value."),
        );
        assert!(m.contains("key"), "{m}");
    }

    #[test]
    fn a_key_is_defined_once() {
        let b13 = one("tagline", "One value.");
        let m = deck_findings("tagline = One value.\ntagline = One value.\n", &b13);
        assert!(m.contains("twice") || m.contains("once"), "{m}");
    }

    #[test]
    fn no_value_contains_an_emoji() {
        let b13 = vec![("tagline".to_owned(), "Create your account 🚀".to_owned())];
        let m = deck_findings("tagline = Create your account 🚀\n", &b13);
        assert!(m.contains("emoji"), "{m}");
    }

    #[test]
    fn an_exclamation_mark_is_only_allowed_in_a_success_key() {
        assert!(
            deck_findings("success-saved = Saved!\n", &one("success-saved", "Saved!")).is_empty()
        );
        let m = deck_findings("tagline = Saved!\n", &one("tagline", "Saved!"));
        assert!(m.contains("exclamation"), "{m}");
        let m = deck_findings("saved-success = Saved!\n", &one("saved-success", "Saved!"));
        assert!(m.is_empty(), "{m}");
    }

    #[test]
    fn no_value_contains_angle_bracket_markup() {
        let m = deck_findings(
            "tagline = A <b>bold</b> claim.\n",
            &one("tagline", "A <b>bold</b> claim."),
        );
        assert!(m.contains("<"), "{m}");
    }

    #[test]
    fn a_count_variable_needs_both_plural_categories() {
        let good =
            "events-count = { $count -> [one] { $count } event *[other] { $count } events }\n";
        assert!(
            deck_findings(
                good,
                &one(
                    "events-count",
                    "{ $count -> [one] { $count } event *[other] { $count } events }"
                )
            )
            .is_empty()
        );
        let bad = "events-count = { $count } events\n";
        let m = deck_findings(bad, &one("events-count", "{ $count } events"));
        assert!(m.contains("[one]") || m.contains("count"), "{m}");
    }

    #[test]
    fn two_keys_may_not_share_a_value() {
        let b13 = vec![
            ("first-key".to_owned(), "Same text.".to_owned()),
            ("second-key".to_owned(), "Same text.".to_owned()),
        ];
        let m = deck_findings("first-key = Same text.\nsecond-key = Same text.\n", &b13);
        assert!(m.contains("same value") || m.contains("duplicate"), "{m}");
    }

    #[test]
    fn every_b13_key_is_required_and_no_other_key_is_allowed() {
        let m = deck_findings("", &fixture_b13());
        assert!(m.contains("missing"), "{m}");
        let b13 = one("tagline", "One value.");
        let m = deck_findings("tagline = One value.\nnot-in-b13 = Another value.\n", &b13);
        assert!(m.contains("not-in-b13"), "{m}");
    }

    #[test]
    fn the_value_equals_the_specification_text() {
        let m = deck_findings(
            "tagline = A different sentence.\n",
            &one("tagline", "One value."),
        );
        assert!(m.contains("differs"), "{m}");
    }

    #[test]
    fn an_empty_value_needs_the_empty_comment() {
        let b13 = one("empty-key", "");
        let m = deck_findings("empty-key =\n", &b13);
        assert!(m.contains("empty"), "{m}");
        let m = deck_findings("# empty: needs text\nempty-key =\n", &b13);
        assert!(m.is_empty(), "{m}");
    }

    #[test]
    fn forbidden_claims_are_checked_on_every_value() {
        let cfg: claims::Config = toml::from_str(include_str!("../../../../docs/claims-lint.toml"))
            .expect("shipped config");
        let b13 = one("tagline", "A rule that gives absolute protection.");
        let findings = style_findings(
            &parse("tagline = A rule that gives absolute protection.\n"),
            &b13,
            "tagline = A rule that gives absolute protection.\n",
            Some(&cfg),
        );
        let m = messages(&findings);
        assert!(m.contains("absolute protection"), "{m}");
    }
}
