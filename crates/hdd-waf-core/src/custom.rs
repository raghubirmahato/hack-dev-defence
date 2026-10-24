//! Operator-provided custom rules (HK1 demo track, `CustomRule` in `types.rs`): a literal `contains` match or a
//! linear-time `regex` match over the normalised value. The proxy validates rules when the site configuration loads;
//! `inspect` never fails because of a malformed pattern (an invalid rule simply never fires).
//!
//! `Verdict::rule_id` is a frozen `Option<&'static str>`, so custom rule ids are interned once per distinct id into a
//! bounded process-wide cache (at most [`MAX_INTERNED_IDS`] ids; ids beyond the cap are reported as `"custom"`).

use std::collections::HashMap;
use std::sync::{Mutex, OnceLock};

use regex::RegexBuilder;

use crate::normalize::Normalized;
use crate::types::{Action, CustomRule, Vector};

/// The bound on the number of distinct custom rule ids interned for the process lifetime.
const MAX_INTERNED_IDS: usize = 256;

/// The bound on a custom pattern in bytes (both `contains` and `regex`); longer patterns are rejected at validation.
const MAX_PATTERN_BYTES: usize = 1024;

/// The bound on the regex crate's compiled program and DFA caches, so a pathological pattern cannot grow without
/// bound (the regex crate itself is linear-time, never backtracking).
const REGEX_SIZE_LIMIT: usize = 1 << 20;

static INTERNED_IDS: OnceLock<Mutex<HashMap<String, &'static str>>> = OnceLock::new();

/// Intern a custom rule id for the frozen `&'static str` rule-id field. Bounded and fallible-safe: on lock poisoning
/// or beyond the cap it reports `"custom"` rather than panicking.
pub(crate) fn intern_rule_id(id: &str) -> &'static str {
    let trimmed = id.trim();
    if trimmed.is_empty() {
        return "custom";
    }
    let cache = INTERNED_IDS.get_or_init(|| Mutex::new(HashMap::new()));
    let Ok(mut cache) = cache.lock() else {
        return "custom";
    };
    if let Some(existing) = cache.get(trimmed).copied() {
        return existing;
    }
    if cache.len() >= MAX_INTERNED_IDS {
        return "custom";
    }
    let interned: &'static str = Box::leak(trimmed.to_owned().into_boxed_str());
    cache.insert(trimmed.to_owned(), interned);
    interned
}

/// Validate one operator rule before it is installed in a site configuration.
///
/// # Errors
/// Returns a human-readable message when the id is empty or too long, when neither or both of `contains`/`regex` are
/// set, when a pattern is empty or too long, or when the regular expression does not compile.
pub fn validate_custom_rule(rule: &CustomRule) -> Result<(), String> {
    let id = rule.id.trim();
    if id.is_empty() {
        return Err("custom rule id must not be empty".to_owned());
    }
    if id.len() > 64 {
        return Err(format!("custom rule id {id:?} must be at most 64 bytes"));
    }
    match (rule.contains.as_deref(), rule.regex.as_deref()) {
        (Some(contains), None) => {
            if contains.trim().is_empty() {
                return Err(format!("custom rule {id:?} has an empty contains pattern"));
            }
            if contains.len() > MAX_PATTERN_BYTES {
                return Err(format!("custom rule {id:?} contains pattern is too long"));
            }
            Ok(())
        }
        (None, Some(regex)) => {
            if regex.trim().is_empty() {
                return Err(format!("custom rule {id:?} has an empty regex pattern"));
            }
            if regex.len() > MAX_PATTERN_BYTES {
                return Err(format!("custom rule {id:?} regex pattern is too long"));
            }
            match RegexBuilder::new(regex)
                .case_insensitive(true)
                .size_limit(REGEX_SIZE_LIMIT)
                .dfa_size_limit(REGEX_SIZE_LIMIT)
                .build()
            {
                Ok(_) => Ok(()),
                Err(error) => Err(format!(
                    "custom rule {id:?} regex does not compile: {error}"
                )),
            }
        }
        (Some(_), Some(_)) => Err(format!(
            "custom rule {id:?} must set exactly one of contains or regex, not both"
        )),
        (None, None) => Err(format!(
            "custom rule {id:?} must set one of contains or regex"
        )),
    }
}

/// Whether a rule matches a normalised value. Returns the rule's action, or `None` when it does not match.
pub(crate) fn matched_action(
    rule: &CustomRule,
    vector: Vector,
    normalized: &Normalized,
) -> Option<Action> {
    if let Some(wanted) = rule.vector
        && wanted != vector
    {
        return None;
    }
    let text = normalized.text.as_str();
    if let Some(contains) = rule.contains.as_deref() {
        let needle = contains.trim().to_ascii_lowercase();
        if needle.is_empty() {
            return None;
        }
        return text.contains(&needle).then_some(rule.action);
    }
    if let Some(pattern) = rule.regex.as_deref() {
        if pattern.trim().is_empty() {
            return None;
        }
        let built = RegexBuilder::new(pattern)
            .case_insensitive(true)
            .size_limit(REGEX_SIZE_LIMIT)
            .dfa_size_limit(REGEX_SIZE_LIMIT)
            .build();
        if let Ok(regex) = built
            && regex.is_match(text)
        {
            return Some(rule.action);
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rule(id: &str, contains: Option<&str>, regex: Option<&str>) -> CustomRule {
        CustomRule {
            id: id.to_owned(),
            vector: None,
            contains: contains.map(str::to_owned),
            regex: regex.map(str::to_owned),
            action: Action::Block,
            description: "operator rule".to_owned(),
        }
    }

    #[test]
    fn validation_accepts_one_well_formed_pattern() {
        assert!(validate_custom_rule(&rule("C-1", Some("union select"), None)).is_ok());
        assert!(validate_custom_rule(&rule("C-2", None, Some(r"admin'\s*--"))).is_ok());
    }

    #[test]
    fn validation_rejects_malformed_rules() {
        assert!(validate_custom_rule(&rule("", Some("x"), None)).is_err());
        assert!(validate_custom_rule(&rule("C-1", None, None)).is_err());
        assert!(validate_custom_rule(&rule("C-1", Some("x"), Some("y"))).is_err());
        assert!(validate_custom_rule(&rule("C-1", Some("   "), None)).is_err());
        assert!(validate_custom_rule(&rule("C-1", None, Some("("))).is_err());
    }

    #[test]
    fn interning_is_stable() {
        let first = intern_rule_id("demo-day-rule");
        let second = intern_rule_id("demo-day-rule");
        assert_eq!(first, second);
        assert_eq!(first, "demo-day-rule");
    }
}
