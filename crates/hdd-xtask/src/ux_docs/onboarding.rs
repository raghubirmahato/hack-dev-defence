//! `ux-docs` checks for T-0026 (onboarding and activation design, checklist and readiness semantics).
//!
//! The module checks the two deliverables of T-0026 against the master specification:
//!
//! * `docs/UX/ONBOARDING.md` carries the twelve onboarding stages of step 1, each with the screen the
//!   stage uses, the user goal, the reason we ask, the exit criterion and the drop-off risk; the
//!   checklist structure (persisted on S-040, resumable, ordered, optional items, no dead ends); the
//!   deterministic next-best-action decision list of step 3 with its evaluated examples; the nudges
//!   with numeric caps and an opt-out of step 4; the empty states of step 5; the monitor-to-block
//!   summary of step 6 (would-have-blocked counts, sample events, false-positive review path, the
//!   48-hour readiness hint and the typed confirmation); the local-only measures of step 7; and the
//!   four activation emails of step 8 (welcome, verify, first domain, weekly summary);
//! * `docs/UX/READINESS-MODEL.md` carries the six categories, the complete check catalog with a whole
//!   number weight, a data source from the B5 data model, a refresh interval and a real B12.1 screen
//!   as the remediation link, the weights summing to 100 (A2), the partial-credit rule, the unknown
//!   rule (unknown never counts as a pass), the exact B13 `readiness-footnote` text placed on S-044
//!   and in the `ReadinessRing` component, and a worked scoring example that this module evaluates.
//! * F-28 (review round 2): every key in a `Copy key` column of `docs/UX/ONBOARDING.md` is defined
//!   exactly once in the B13 copy deck (`i18n/en/copy-deck.ftl`) or `i18n/en/onboarding.ftl`, and the
//!   new copy file passes the Fluent style rules and the claims scanner. The four activation-email
//!   key stems stay declared `new` and will live in `i18n/en/onboarding.ftl` when their tasks land.
//!
//! The readiness model is about configuration completeness only, never about security, and the
//! documents say so in the exact B13 wording rather than in a paraphrase.
//!
//! Rules are document linters: every registry value (the B12.1 screens, the B13 rows, the B8 audit
//! events and the B9 metrics) is read from the checksum-verified master text passed to [`check`], and
//! no id is hard-coded from memory. Missing or malformed input is reported as a finding, never as a
//! panic: a missing document, an empty section, a table without the required columns or a rule whose
//! fixture cannot be evaluated all end in a finding.
//!
//! The only values this module knows by itself are the design decisions the task asks for: the twelve
//! stages and their screens, the six category weights, the 23 checks with their weights and the
//! expected remediation screen from the readiness table of `docs/UX/journeys/J-25.md`, the eight
//! next-best-action rules and their examples, the nudge caps and the four email outlines. Those are
//! design content, not registry data; the registry ids are checked against the master.

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

use regex::Regex;

use crate::claims;
use crate::util::{Finding, read_text};

use super::content::b13_rows;
use super::ftl_style::EMPTY_COMMENT;
use super::{column, finding, screen_ids, section_body, section_table};

/// The onboarding document (T-0026 deliverable).
pub const ONBOARDING: &str = "docs/UX/ONBOARDING.md";
/// The readiness model (T-0026 deliverable).
pub const READINESS_MODEL: &str = "docs/UX/READINESS-MODEL.md";
/// The journey whose readiness table T-0026 step 2 must agree with.
pub const JOURNEY_READINESS: &str = "docs/UX/journeys/J-25.md";
/// The B13 copy deck, one of the three sources a `Copy key` of `docs/UX/ONBOARDING.md` may be defined in.
pub const COPY_DECK: &str = "i18n/en/copy-deck.ftl";
/// The onboarding copy file (F-28): the empty-state strings B13 does not define and, later, the four
/// activation-email key stems.
pub const ONBOARDING_FTL: &str = "i18n/en/onboarding.ftl";

/// Shape of a semantic i18n key stem (the same rule the copy deck applies).
const KEY_SHAPE: &str = r"^[a-z0-9]+(-[a-z0-9]+)*$";

/// The level-2 sections `docs/UX/ONBOARDING.md` must have, in the order the steps are named.
pub const ONBOARDING_SECTIONS: [&str; 8] = [
    "Stage map",
    "Checklist structure",
    "Next best action",
    "Nudges and reminders",
    "Empty states",
    "Monitor-to-block decision",
    "Measures",
    "Activation emails",
];

/// The level-2 sections `docs/UX/READINESS-MODEL.md` must have.
pub const READINESS_SECTIONS: [&str; 7] = [
    "Categories",
    "Check catalog",
    "B12.2 mapping",
    "Scoring rules",
    "Unknown handling",
    "Honesty footnote",
    "Worked scoring example",
];

/// The twelve onboarding stages of T-0026 step 1 and the B12.1 screen the stage is designed around.
/// The order is the order of the checklist.
pub const STAGES: [(&str, &str); 12] = [
    ("account", "S-020"),
    ("org", "S-035"),
    ("MFA nudge", "S-030"),
    ("first domain", "S-041"),
    ("DNS connect", "S-047"),
    ("verify", "S-042"),
    ("origin", "S-052"),
    ("monitor mode", "S-054"),
    ("first events", "S-065"),
    ("block-mode decision", "S-055"),
    ("alerts", "S-076"),
    ("team", "S-082"),
];

/// The six categories of B12.2 with their weights; they sum to 100.
pub const CATEGORIES: [(&str, u8); 6] = [
    ("Traffic", 20),
    ("Encryption", 15),
    ("Origin", 20),
    ("Detection", 25),
    ("Abuse controls", 10),
    ("Operations", 10),
];

/// One check of the readiness catalog.
#[allow(
    dead_code,
    reason = "the data source, refresh interval and remediation are read by the fixture generator under cfg(test)"
)]
struct Check {
    /// Stable check id, used by the decision list and the scoring example.
    id: &'static str,
    /// The check name used by the readiness table of `docs/UX/journeys/J-25.md`.
    name: &'static str,
    /// Whole number weight; the 23 weights sum to 100.
    weight: u8,
    /// Category of B12.2.
    category: &'static str,
    /// Real B5 data source.
    source: &'static str,
    /// Refresh interval (a duration or an event-driven refresh).
    refresh: &'static str,
    /// Real B12.1 screen that fixes the check.
    remediation: &'static str,
}

/// The complete readiness catalog of T-0026 step 2, matching the readiness table of J-25.
const CHECKS: [Check; 23] = [
    Check {
        id: "RD-TRAFFIC",
        name: "Traffic flows through HDD",
        weight: 8,
        category: "Traffic",
        source: "`waf_events` (the last proxied request for the site)",
        refresh: "60 s",
        remediation: "S-043",
    },
    Check {
        id: "RD-DELEGATION",
        name: "Delegation or CNAME verified",
        weight: 7,
        category: "Traffic",
        source: "`delegation_checks` (`matches`) and `domain_verifications`",
        refresh: "5 min",
        remediation: "S-099",
    },
    Check {
        id: "RD-GREY",
        name: "No grey web record exposes a hostname",
        weight: 5,
        category: "Traffic",
        source: "`dns_records` (`proxied`)",
        refresh: "on change, then 15 min",
        remediation: "S-045",
    },
    Check {
        id: "RD-CERT",
        name: "Certificate valid beyond a quarter of its lifetime",
        weight: 5,
        category: "Encryption",
        source: "`certificates` (`not_after`, `status`)",
        refresh: "hourly",
        remediation: "S-051",
    },
    Check {
        id: "RD-HTTPS",
        name: "HTTPS redirect is on",
        weight: 3,
        category: "Encryption",
        source: "`sites` (`ssl_mode`, `min_tls`)",
        refresh: "on change",
        remediation: "S-050",
    },
    Check {
        id: "RD-ORIGIN-VERIFY",
        name: "Origin verification is strict",
        weight: 3,
        category: "Encryption",
        source: "`origins` (`tls_verify_mode`)",
        refresh: "on change",
        remediation: "S-052",
    },
    Check {
        id: "RD-HSTS",
        name: "HSTS is enabled",
        weight: 4,
        category: "Encryption",
        source: "`sites` (`hsts`)",
        refresh: "on change",
        remediation: "S-050",
    },
    Check {
        id: "RD-LOCKDOWN",
        name: "Origin lockdown applied",
        weight: 6,
        category: "Origin",
        source: "`config_revisions` snapshot (`lockdown_state`) and `audit_log` (`AUD-origin.lockdown_applied`)",
        refresh: "on change",
        remediation: "S-098",
    },
    Check {
        id: "RD-SECRET",
        name: "Secret origin header verified",
        weight: 5,
        category: "Origin",
        source: "`origins` (`secret_header_enc`, `secret_rotated_at`) and `audit_log` (`AUD-origin.secret_verified`)",
        refresh: "on change, then 24 h",
        remediation: "S-052",
    },
    Check {
        id: "RD-ORIGIN-EXPOSURE",
        name: "Origin address absent from own DNS and headers",
        weight: 5,
        category: "Origin",
        source: "`dns_records` (MX, SPF and DKIM), `zone_versions` (published A and AAAA values) and `mail_outbox` (mail headers of recorded mail)",
        refresh: "on change, then 6 h",
        remediation: "S-138",
    },
    Check {
        id: "RD-ORIGIN-HEALTH",
        name: "Origin health check passing",
        weight: 4,
        category: "Origin",
        source: "`origin_health` (`ok`)",
        refresh: "5 min",
        remediation: "S-053",
    },
    Check {
        id: "RD-WAF-MODE",
        name: "WAF in block mode",
        weight: 8,
        category: "Detection",
        source: "`sites` (`waf_mode`)",
        refresh: "on change",
        remediation: "S-055",
    },
    Check {
        id: "RD-SHIELD",
        name: "SQL injection shield enabled",
        weight: 6,
        category: "Detection",
        source: "`waf_policies` (`shield`)",
        refresh: "on change",
        remediation: "S-057",
    },
    Check {
        id: "RD-HARD-CATEGORIES",
        name: "All hard categories on",
        weight: 5,
        category: "Detection",
        source: "`waf_policies` (`category_actions`)",
        refresh: "on change",
        remediation: "S-056",
    },
    Check {
        id: "RD-AUTH-ENDPOINTS",
        name: "Authentication endpoints declared",
        weight: 3,
        category: "Detection",
        source: "`auth_endpoints`",
        refresh: "on change",
        remediation: "S-057",
    },
    Check {
        id: "RD-OUTBOUND",
        name: "Outbound filter on",
        weight: 3,
        category: "Detection",
        source: "`sites` (`outbound_mode`) and `waf_policies` (`outbound`)",
        refresh: "on change",
        remediation: "S-097",
    },
    Check {
        id: "RD-RATE-LIMITS",
        name: "Rate limits on authentication endpoints",
        weight: 4,
        category: "Abuse controls",
        source: "`rate_limit_rules`",
        refresh: "on change",
        remediation: "S-061",
    },
    Check {
        id: "RD-CHALLENGE",
        name: "Challenge configured",
        weight: 3,
        category: "Abuse controls",
        source: "`waf_policies` (`challenge`)",
        refresh: "on change",
        remediation: "S-062",
    },
    Check {
        id: "RD-SCANNER",
        name: "Scanner policy on",
        weight: 3,
        category: "Abuse controls",
        source: "`waf_policies` (`bots`)",
        refresh: "on change",
        remediation: "S-062",
    },
    Check {
        id: "RD-ALERT-TESTED",
        name: "Alert channel tested",
        weight: 3,
        category: "Operations",
        source: "`alert_rules` and `integrations` (`last_ok_at`)",
        refresh: "hourly",
        remediation: "S-076",
    },
    Check {
        id: "RD-MFA",
        name: "MFA required for the organisation",
        weight: 2,
        category: "Operations",
        source: "`orgs` (`require_mfa`)",
        refresh: "on change",
        remediation: "S-086",
    },
    Check {
        id: "RD-DNS-BACKUP",
        name: "DNS backup exported",
        weight: 2,
        category: "Operations",
        source: "`zone_versions` (`snapshot_hash`) and `audit_log` (`AUD-dns.exported`)",
        refresh: "on change, then 24 h",
        remediation: "S-048",
    },
    Check {
        id: "RD-APPEALS",
        name: "Appeals enabled",
        weight: 3,
        category: "Operations",
        source: "`block_page_settings` (`appeals_enabled`)",
        refresh: "on change",
        remediation: "S-069",
    },
];

/// Design value for F-19a: B12.2 says monitor mode gives partial credit for `RD-WAF-MODE`. The ratio
/// is a design decision of this model; T-0172 confirms it when the engine implements the check.
const WAF_MONITOR_RATIO: f64 = 0.5;

/// F-20b: the distinct card outcome when every readiness check passes. The unconditional last rule
/// returns this exact sentence instead of a remediation task.
pub const ALL_PASS_OUTCOME: &str = "Nothing to do now.";

/// Tables of the B5 data model that a readiness check may read. A data-source cell must name at
/// least one of them as a whole token.
const TABLES: [&str; 44] = [
    "users",
    "user_sessions",
    "mfa_totp",
    "orgs",
    "memberships",
    "invitations",
    "sites",
    "site_hostnames",
    "domain_verifications",
    "origins",
    "origin_pools",
    "origin_health",
    "zones",
    "dns_records",
    "zone_versions",
    "zone_imports",
    "dns_scans",
    "delegation_checks",
    "certificates",
    "waf_policies",
    "waf_rules",
    "waf_exceptions",
    "auth_endpoints",
    "rate_limit_rules",
    "access_entries",
    "block_page_settings",
    "config_revisions",
    "waf_events",
    "ip_bans",
    "ban_appeals",
    "rollup_minute",
    "rollup_hour",
    "rollup_day",
    "reports",
    "report_runs",
    "notifications",
    "notification_prefs",
    "alert_rules",
    "integrations",
    "webhooks",
    "webhook_deliveries",
    "mail_outbox",
    "audit_log",
    "security_events",
];

/// Forbidden claims phrases of the claims policy (section 4). The scanner is a Safety net for the two
/// documents; `cargo xtask claims-lint` remains the authoritative check. The finding never repeats the
/// phrase, so an evidence file that quotes the finding stays clean.
const FORBIDDEN_CLAIMS: [&str; 14] = [
    "structurally impossible",
    "cannot be bypassed",
    "nothing reaches the origin",
    "unhackable",
    "unbreakable",
    "100% secure",
    "100% protection",
    "fully secure",
    "completely secure",
    "guaranteed protection",
    "stops all attacks",
    "blocks all attacks",
    "immune to",
    "ddos-proof",
];

/// Third-party analytics names that must not appear in the onboarding measures.
const THIRD_PARTY: [&str; 10] = [
    "google analytics",
    "matomo",
    "plausible",
    "posthog",
    "mixpanel",
    "amplitude",
    "hotjar",
    "fullstory",
    "facebook pixel",
    "segment.io",
];

/// The four activation emails of T-0026 step 8.
pub const EMAILS: [&str; 4] = ["welcome", "verify", "first domain", "weekly summary"];

/// One condition of a next-best-action rule: an ordinary `CHECK is STATUS` test, or the generic
/// `any check is not Pass` test of the one rule that catches every remaining non-Pass check.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Condition {
    /// The named check has exactly this status.
    Check { id: String, status: Status },
    /// At least one check of the catalog is not `Pass`.
    AnyNotPass,
}

/// Everything the rule needs about a next-best-action rule from the ordered decision list.
#[derive(Debug, Clone)]
struct DecisionRule {
    /// The unique priority stated in the rule.
    priority: usize,
    /// The conditions of the rule; an empty list is the unconditional all-Pass outcome.
    conditions: Vec<Condition>,
    /// The action text after `then`.
    action: String,
}

/// The status of one readiness check.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Status {
    /// The check passes.
    Pass,
    /// The check is partly met; the ratio is given separately.
    Partial,
    /// The check fails.
    Fail,
    /// The data is unknown; the reason is shown.
    Unknown,
}

/// A `ux-docs` finding at a document location.
fn at(location: impl Into<String>, message: impl Into<String>) -> Finding {
    finding(location, message)
}

/// A character that can continue a check id, a screen id or a table name.
fn is_token_char(c: char) -> bool {
    c.is_alphanumeric() || c == '_' || c == '-'
}

/// True when `text` contains `token` as a whole token: the character before and after it is not a
/// letter, a digit, `_` or `-`. A screen id inside `XS-0440` or a check id inside `RD-TRAFFIC-OLD`
/// is not a reference to the token (review lesson 1).
fn has_token(text: &str, token: &str) -> bool {
    for (start, _) in text.match_indices(token) {
        let end = start + token.len();
        let before = text.get(..start).and_then(|rest| rest.chars().next_back());
        let after = text.get(end..).and_then(|rest| rest.chars().next());
        if !before.is_some_and(is_token_char) && !after.is_some_and(is_token_char) {
            return true;
        }
    }
    false
}

/// The `S-nnn` ids of `text`, as whole tokens with exactly three digits.
fn screen_tokens(text: &str) -> Vec<String> {
    let bytes = text.as_bytes();
    let mut out = Vec::new();
    let mut index = 0usize;
    while index + 5 <= bytes.len() {
        let is_prefix = bytes.get(index) == Some(&b'S') && bytes.get(index + 1) == Some(&b'-');
        let digits = (
            bytes.get(index + 2),
            bytes.get(index + 3),
            bytes.get(index + 4),
        );
        if is_prefix
            && let (Some(a), Some(b), Some(c)) = digits
            && a.is_ascii_digit()
            && b.is_ascii_digit()
            && c.is_ascii_digit()
        {
            let before_ok = index == 0
                || !bytes.get(index.wrapping_sub(1)).is_some_and(|byte| {
                    byte.is_ascii_alphanumeric() || *byte == b'_' || *byte == b'-'
                });
            let after_ok = !bytes
                .get(index + 5)
                .is_some_and(|byte| byte.is_ascii_digit());
            if before_ok && after_ok {
                out.push(format!(
                    "S-{}{}{}",
                    char::from(*a),
                    char::from(*b),
                    char::from(*c)
                ));
            }
            index += 5;
            continue;
        }
        index += 1;
    }
    out
}

/// The ids of `text` with `prefix` (`AUD-`, `MET-`, `onboarding.`), as whole tokens.
fn ids_with_prefix(text: &str, prefix: &str) -> Vec<String> {
    text.split(|c: char| !(c.is_ascii_alphanumeric() || c == '_' || c == '-' || c == '.'))
        .filter(|token| token.starts_with(prefix))
        .map(str::to_owned)
        .collect()
}

/// The backticked inline-code spans of `text`.
fn backticked(text: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut in_code = false;
    let mut current = String::new();
    for c in text.chars() {
        if c == '`' {
            if in_code && !current.is_empty() {
                out.push(current.clone());
            }
            current.clear();
            in_code = !in_code;
        } else if in_code {
            current.push(c);
        }
    }
    out
}

/// A well-formed semantic hyphenated i18n key: lower-case letters and digits, at least two hyphen
/// separated parts, no empty part.
fn well_formed_key(key: &str) -> bool {
    let parts: Vec<&str> = key.split('-').collect();
    parts.len() >= 2
        && parts.iter().all(|part| {
            !part.is_empty()
                && part
                    .chars()
                    .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit())
        })
        && key.chars().next().is_some_and(|c| c.is_ascii_lowercase())
}

/// A well-formed local counter name: the `onboarding.` prefix and dot-separated lower-case segments.
fn well_formed_counter(token: &str) -> bool {
    let Some(rest) = token.strip_prefix("onboarding.") else {
        return false;
    };
    !rest.is_empty()
        && rest.split('.').all(|part| {
            !part.is_empty()
                && part
                    .chars()
                    .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_')
        })
}

/// A duration or an event-driven refresh, for example `60 s`, `5 min`, `24 h`, `hourly` or
/// `on change, then 15 min`.
fn duration_like(cell: &str) -> bool {
    let lower = cell.to_lowercase();
    if lower.contains("on change") || lower.contains("hourly") || lower.contains("daily") {
        return true;
    }
    let digits = lower.chars().any(|c| c.is_ascii_digit());
    digits
        && (lower.contains(" s")
            || lower.contains("sec")
            || lower.contains("min")
            || lower.contains(" hour")
            || lower.contains(" h")
            || lower.contains(" day")
            || lower.contains(" d"))
}

/// The B13 text of `key`, when the master specification has it.
fn b13_value<'a>(b13: &'a [(String, String)], key: &str) -> Option<&'a str> {
    b13.iter()
        .find(|(stem, _)| stem == key)
        .map(|(_, text)| text.as_str())
}

/// The text of a section, joined into one string.
fn section_text(text: &str, title: &str) -> String {
    section_body(text, title)
        .unwrap_or_default()
        .iter()
        .map(|(_, line)| line.as_str())
        .collect::<Vec<_>>()
        .join("\n")
}

/// The weight of `row` in the `Weight` column, parsed as a whole non-negative integer.
fn row_weight(header: &[String], row: &[String]) -> Option<u32> {
    let index = column(header, "Weight")?;
    row.get(index)?.trim().parse::<u32>().ok()
}

/// The check id named by a catalog row's `Check` cell.
fn check_id_in(cell: &str) -> Option<&'static str> {
    CHECKS
        .iter()
        .find(|check| has_token(cell, check.id))
        .map(|check| check.id)
}

/// The catalog rows of the readiness model as `(line, check id, weight)`, skipping malformed rows.
fn catalog_weights(text: &str) -> BTreeMap<String, u32> {
    let mut out = BTreeMap::new();
    let Some((header, rows)) = section_table(text, "Check catalog") else {
        return out;
    };
    for (_, row) in rows {
        let Some(check_cell) = row.first() else {
            continue;
        };
        let Some(id) = check_id_in(check_cell) else {
            continue;
        };
        if let Some(weight) = row_weight(&header, &row) {
            out.insert(id.to_owned(), weight);
        }
    }
    out
}

/// Parse a status word of the decision list.
fn parse_status(text: &str) -> Option<Status> {
    match text.trim() {
        "Pass" => Some(Status::Pass),
        "Partial" => Some(Status::Partial),
        "Fail" => Some(Status::Fail),
        "Unknown" => Some(Status::Unknown),
        _ => None,
    }
}

/// Parse the conditions of one decision-list rule: `CHECK is STATUS` parts joined by ` and `, the
/// generic `any check is not Pass` condition, or `always` for the unconditional last rule.
fn parse_conditions(text: &str, line: usize, out: &mut Vec<Finding>) -> Vec<Condition> {
    let mut conditions = Vec::new();
    if text.trim().eq_ignore_ascii_case("always") {
        return conditions;
    }
    for part in text.split(" and ") {
        if part.trim().eq_ignore_ascii_case("any check is not Pass") {
            conditions.push(Condition::AnyNotPass);
            continue;
        }
        let Some((id, status)) = part.split_once(" is ") else {
            out.push(at(
                format!("{ONBOARDING}:{line}"),
                format!(
                    "the condition `{part}` does not follow `<CHECK> is <STATUS>` or `any check is not Pass` (T-0026 step 3)"
                ),
            ));
            continue;
        };
        let id = id.trim();
        let Some(status) = parse_status(status) else {
            out.push(at(
                format!("{ONBOARDING}:{line}"),
                format!("the condition status `{status}` is not Pass, Partial, Fail or Unknown (T-0026 step 3)"),
            ));
            continue;
        };
        if !CHECKS.iter().any(|check| check.id == id) {
            out.push(at(
                format!("{ONBOARDING}:{line}"),
                format!(
                    "the condition `{id}` is not a check of the readiness model (T-0026 step 3)"
                ),
            ));
            continue;
        }
        conditions.push(Condition::Check {
            id: id.to_owned(),
            status,
        });
    }
    if conditions
        .iter()
        .any(|condition| matches!(condition, Condition::AnyNotPass))
        && conditions.len() > 1
    {
        out.push(at(
            format!("{ONBOARDING}:{line}"),
            "the generic condition `any check is not Pass` must stand alone in its rule (F-20a)",
        ));
    }
    conditions
}

/// The state of the example evaluations: every check passes unless the input overrides it.
fn example_state(inputs: &str, partial: &mut BTreeMap<String, f64>) -> BTreeMap<String, Status> {
    let mut state: BTreeMap<String, Status> = CHECKS
        .iter()
        .map(|check| (check.id.to_owned(), Status::Pass))
        .collect();
    if inputs.to_lowercase().contains("every check unknown") {
        for status in state.values_mut() {
            *status = Status::Unknown;
        }
        return state;
    }
    for part in inputs.split(';') {
        let part = part.trim();
        if part.is_empty()
            || part.eq_ignore_ascii_case("none")
            || part.eq_ignore_ascii_case("others=Pass")
        {
            continue;
        }
        let split = part
            .split_once('=')
            .or_else(|| part.split_once(char::is_whitespace));
        let Some((id, status)) = split else {
            continue;
        };
        let id = id.trim();
        let status = status.trim();
        if let Some(rest) = status
            .strip_prefix("Partial(")
            .and_then(|rest| rest.strip_suffix(')'))
        {
            if let Ok(ratio) = rest.parse::<f64>() {
                state.insert(id.to_owned(), Status::Partial);
                partial.insert(id.to_owned(), ratio.clamp(0.0, 1.0));
            }
        } else if let Some(status) = parse_status(status) {
            state.insert(id.to_owned(), status);
        }
    }
    state
}

/// True for the generic rule, whose one condition is `any check is not Pass` (F-20a).
fn rule_is_generic(rule: &DecisionRule) -> bool {
    rule.conditions.len() == 1
        && rule
            .conditions
            .first()
            .is_some_and(|condition| matches!(condition, Condition::AnyNotPass))
}

/// True for the unconditional last rule that returns the distinct all-Pass outcome (F-20b).
fn rule_is_unconditional(rule: &DecisionRule) -> bool {
    rule.conditions.is_empty()
}

/// True when `state` satisfies the conditions of `rule`; the unconditional last rule always matches.
fn rule_matches(rule: &DecisionRule, state: &BTreeMap<String, Status>) -> bool {
    if rule_is_unconditional(rule) {
        return true;
    }
    if rule_is_generic(rule) {
        return state.values().any(|status| *status != Status::Pass);
    }
    rule.conditions.iter().all(|condition| match condition {
        Condition::Check { id, status } => state.get(id) == Some(status),
        Condition::AnyNotPass => false,
    })
}

/// The first check of the catalog, in catalog order, whose state is not `Pass` (F-20a).
fn first_non_pass(state: &BTreeMap<String, Status>) -> Option<&'static Check> {
    CHECKS
        .iter()
        .find(|check| state.get(check.id).copied() != Some(Status::Pass))
}

/// The action a rule returns in `state`: the fixed sentence of an ordinary rule, or the expanded
/// remediation sentence of the generic rule that names the first non-Pass check in catalog order.
fn rule_action(rule: &DecisionRule, state: &BTreeMap<String, Status>) -> String {
    if rule_is_generic(rule) {
        return match first_non_pass(state) {
            Some(check) => format!(
                "Open the remediation link for {} at {}.",
                check.id, check.remediation
            ),
            None => rule.action.clone(),
        };
    }
    rule.action.clone()
}

/// The first rule whose conditions all hold, with the action it returns in this state (T-0026 step 3).
fn evaluate<'a>(
    rules: &'a [DecisionRule],
    state: &BTreeMap<String, Status>,
) -> Option<(&'a DecisionRule, String)> {
    rules
        .iter()
        .find(|rule| rule_matches(rule, state))
        .map(|rule| (rule, rule_action(rule, state)))
}

/// The pure scoring function of the readiness model: Pass 1, Partial its ratio, Fail and Unknown 0,
/// the weighted total rounded down, plus the number of Unknown checks.
fn score(
    weights: &BTreeMap<String, u32>,
    state: &BTreeMap<String, Status>,
    partial: &BTreeMap<String, f64>,
) -> (u32, usize) {
    let mut total = 0.0_f64;
    let mut unknown = 0_usize;
    for (id, weight) in weights {
        match state.get(id).copied().unwrap_or(Status::Unknown) {
            Status::Pass => total += f64::from(*weight),
            Status::Partial => {
                total += f64::from(*weight) * partial.get(id).copied().unwrap_or(0.0);
            }
            Status::Fail => {}
            Status::Unknown => unknown += 1,
        }
    }
    (total.floor() as u32, unknown)
}

/// Compare an action sentence ignoring case and a trailing full stop.
fn same_action(left: &str, right: &str) -> bool {
    left.trim().trim_end_matches('.').to_lowercase()
        == right.trim().trim_end_matches('.').to_lowercase()
}

/// Collapse the whitespace of a table cell and lower-case it, for phrase comparison.
fn normalized_cell(cell: &str) -> String {
    cell.split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
        .to_lowercase()
}

/// The `(category, phrase)` pairs of the six B12.2 bullet lists of `#### S-044 Protection readiness`,
/// in specification order. Each bullet is one category; its phrases are comma separated.
fn b122_phrases(spec: &str) -> Vec<(String, String)> {
    let mut out = Vec::new();
    let mut inside = false;
    for raw in spec.lines() {
        let text = raw.trim_start();
        if text.starts_with('#') {
            if inside {
                break;
            }
            inside = text
                .trim_start_matches('#')
                .trim_start()
                .eq_ignore_ascii_case("S-044 Protection readiness");
            continue;
        }
        if !inside {
            continue;
        }
        let Some(rest) = text.strip_prefix("- **") else {
            continue;
        };
        let Some((category, rest)) = rest.split_once("** (") else {
            continue;
        };
        let Some((_weight, phrases)) = rest.split_once("): ") else {
            continue;
        };
        for phrase in phrases.trim_end_matches('.').trim().split(", ") {
            let phrase = phrase.trim();
            if !phrase.is_empty() {
                out.push((category.trim().to_owned(), phrase.to_owned()));
            }
        }
    }
    out
}

/// The Partial ratio stated for `id` in an example override cell, for example `RD-WAF-MODE
/// Partial(0.5)`.
fn partial_ratio(text: &str, id: &str) -> Option<f64> {
    for part in text.split(';') {
        let part = part.trim();
        let Some(rest) = part.strip_prefix(id) else {
            continue;
        };
        let Some(rest) = rest.trim_start().strip_prefix("Partial(") else {
            continue;
        };
        let Some((ratio, _)) = rest.split_once(')') else {
            continue;
        };
        return ratio.trim().parse::<f64>().ok();
    }
    None
}

/// F-19c: every B12.2 S-044 check phrase has exactly one row in the mapping table of
/// `docs/UX/READINESS-MODEL.md`, each row names exactly one model check of the phrase's category, and
/// every catalog check is mapped exactly once. The six bullet lists are read from the master text.
pub fn b122_mapping_findings(model: &str, spec: &str) -> Vec<Finding> {
    let mut out = Vec::new();
    let phrases = b122_phrases(spec);
    if phrases.is_empty() {
        return vec![at(
            "docs/SPEC.md",
            "the master specification has no B12.2 S-044 bullet lists, so the mapping cannot be compared (F-19c)",
        )];
    }
    if phrases.len() != CHECKS.len() {
        out.push(at(
            "docs/SPEC.md",
            format!(
                "the six B12.2 S-044 bullet lists name {} checks but the readiness model has {} (F-19c)",
                phrases.len(),
                CHECKS.len()
            ),
        ));
    }
    let Some((header, rows)) = section_table(model, "B12.2 mapping") else {
        return vec![at(
            READINESS_MODEL,
            "no `## B12.2 mapping` table that maps each B12.2 check phrase to one model check (F-19c)",
        )];
    };
    let (Some(phrase_index), Some(category_index), Some(check_index)) = (
        column(&header, "B12.2 check phrase"),
        column(&header, "B12.2 category"),
        column(&header, "Model check"),
    ) else {
        return vec![at(
            READINESS_MODEL,
            "the `## B12.2 mapping` table needs the `B12.2 check phrase`, `B12.2 category` and `Model check` columns (F-19c)",
        )];
    };
    let mut parsed: Vec<(usize, String, String, Vec<&'static str>)> = Vec::new();
    for (line, row) in &rows {
        let phrase = row
            .get(phrase_index)
            .map_or("", String::as_str)
            .trim()
            .to_owned();
        let category = row
            .get(category_index)
            .map_or("", String::as_str)
            .trim()
            .to_owned();
        let check_cell = row.get(check_index).map_or("", String::as_str);
        let ids: Vec<&'static str> = CHECKS
            .iter()
            .filter(|check| has_token(check_cell, check.id))
            .map(|check| check.id)
            .collect();
        parsed.push((*line, phrase, category, ids));
    }
    for (line, phrase, category, ids) in &parsed {
        let location = format!("{READINESS_MODEL}:{line}");
        if ids.is_empty() {
            out.push(at(
                location,
                format!("the mapping row `{phrase}` names no model check (F-19c)"),
            ));
            continue;
        }
        if ids.len() > 1 {
            out.push(at(
                location,
                format!(
                    "the mapping row `{phrase}` names {} model checks, not exactly one (F-19c)",
                    ids.len()
                ),
            ));
            continue;
        }
        let Some(check) = ids
            .first()
            .and_then(|id| CHECKS.iter().find(|check| check.id == *id))
        else {
            continue;
        };
        if !check.category.eq_ignore_ascii_case(category) {
            out.push(at(
                location,
                format!(
                    "the mapping row `{phrase}` lists the check `{}` under `{category}` but its catalog category is `{}` (F-19c)",
                    check.id, check.category
                ),
            ));
        }
    }
    for (category, phrase) in &phrases {
        let key = normalized_cell(phrase);
        let matches: Vec<&(usize, String, String, Vec<&'static str>)> = parsed
            .iter()
            .filter(|(_, row_phrase, ..)| normalized_cell(row_phrase) == key)
            .collect();
        if matches.is_empty() {
            out.push(at(
                READINESS_MODEL,
                format!(
                    "the B12.2 check phrase `{phrase}` has no row in the mapping table (F-19c)"
                ),
            ));
            continue;
        }
        if matches.len() > 1 {
            out.push(at(
                READINESS_MODEL,
                format!(
                    "the B12.2 check phrase `{phrase}` has {} rows in the mapping table, not exactly one (F-19c)",
                    matches.len()
                ),
            ));
            continue;
        }
        let Some((line, _, row_category, ids)) = matches.first().copied() else {
            continue;
        };
        if !row_category.eq_ignore_ascii_case(category) {
            out.push(at(
                format!("{READINESS_MODEL}:{line}"),
                format!(
                    "the mapping row `{phrase}` is listed under `{row_category}` but B12.2 puts it in `{category}` (F-19c)"
                ),
            ));
        }
        if let Some(id) = ids.first()
            && !CHECKS
                .iter()
                .any(|check| check.id == *id && check.category.eq_ignore_ascii_case(category))
        {
            out.push(at(
                format!("{READINESS_MODEL}:{line}"),
                format!(
                    "the B12.2 phrase `{phrase}` maps to `{id}`, which is not a check of the `{category}` category (F-19c)"
                ),
            ));
        }
    }
    let mut count_by_check: BTreeMap<&'static str, usize> = BTreeMap::new();
    for (_, _, _, ids) in &parsed {
        for id in ids {
            *count_by_check.entry(*id).or_default() += 1;
        }
    }
    for check in CHECKS {
        let count = count_by_check.get(check.id).copied().unwrap_or(0);
        if count != 1 {
            out.push(at(
                READINESS_MODEL,
                format!(
                    "the model check `{}` has {count} B12.2 mapping rows, not exactly one (F-19c)",
                    check.id
                ),
            ));
        }
    }
    let spec_phrases: BTreeSet<String> = phrases
        .iter()
        .map(|(_, phrase)| normalized_cell(phrase))
        .collect();
    for (line, phrase, _, _) in &parsed {
        if !spec_phrases.contains(&normalized_cell(phrase)) {
            out.push(at(
                format!("{READINESS_MODEL}:{line}"),
                format!(
                    "the mapping row `{phrase}` is not a check phrase of the B12.2 S-044 bullet lists (F-19c)"
                ),
            ));
        }
    }
    out
}

/// F-19a: B12.2 says monitor mode gives partial credit for the WAF mode check. The scoring rules must
/// state the monitor-mode ratio as a design value confirmed in T-0172, and the worked example's case
/// F must use that same ratio.
pub fn waf_partial_findings(model: &str) -> Vec<Finding> {
    let mut out = Vec::new();
    let rules = section_text(model, "Scoring rules");
    let lower = rules.to_lowercase();
    if !(lower.contains("rd-waf-mode")
        && lower.contains("monitor")
        && lower.contains("confirmed in t-0172"))
    {
        out.push(at(
            READINESS_MODEL,
            "the scoring rules must state the monitor-mode Partial ratio of the `RD-WAF-MODE` check as a design value, confirmed in T-0172 (F-19a)",
        ));
    }
    if !rules.contains("0.5") {
        out.push(at(
            READINESS_MODEL,
            format!(
                "the scoring rules must state the monitor-mode ratio {WAF_MONITOR_RATIO} for `RD-WAF-MODE` (F-19a)"
            ),
        ));
    }
    let Some((header, rows)) = section_table(model, "Worked scoring example") else {
        out.push(at(
            READINESS_MODEL,
            "no worked scoring example table, so the monitor-mode case F cannot be checked (F-19a)",
        ));
        return out;
    };
    let (Some(case_index), Some(overrides_index)) = (
        column(&header, "Case"),
        column(&header, "Status overrides (all other checks Pass)"),
    ) else {
        out.push(at(
            READINESS_MODEL,
            "the worked scoring example has no Case and status-overrides columns (F-19a)",
        ));
        return out;
    };
    let mut case_f = None;
    for (line, row) in &rows {
        let case_cell = row.get(case_index).map_or("", String::as_str).trim();
        if case_cell.eq_ignore_ascii_case("F") {
            case_f = Some((*line, row.get(overrides_index).map_or("", String::as_str)));
        }
    }
    let Some((line, overrides)) = case_f else {
        out.push(at(
            READINESS_MODEL,
            "the worked scoring example has no case F for the monitor-mode Partial ratio (F-19a)",
        ));
        return out;
    };
    let location = format!("{READINESS_MODEL}:{line}");
    if !has_token(overrides, "RD-WAF-MODE") || !overrides.to_lowercase().contains("partial") {
        out.push(at(
            location,
            "case F must override `RD-WAF-MODE` with `Partial` for monitor mode (F-19a)",
        ));
        return out;
    }
    match partial_ratio(overrides, "RD-WAF-MODE") {
        Some(ratio) if (ratio - WAF_MONITOR_RATIO).abs() < f64::EPSILON => {}
        Some(ratio) => out.push(at(
            location,
            format!(
                "case F uses the ratio {ratio} but the monitor-mode design value is {WAF_MONITOR_RATIO} (F-19a)"
            ),
        )),
        None => out.push(at(
            location,
            "case F does not state the Partial ratio for `RD-WAF-MODE` (F-19a)",
        )),
    }
    out
}

/// F-19b: the B12.2 origin-exposure phrase says "origin IP not found in own DNS/headers/mail", so
/// `RD-ORIGIN-EXPOSURE` must cover MX, SPF and DKIM records and mail headers, not only A/AAAA values.
pub fn origin_mail_findings(model: &str) -> Vec<Finding> {
    let Some((header, rows)) = section_table(model, "Check catalog") else {
        return vec![at(
            READINESS_MODEL,
            "no check catalog, so the origin-exposure data source cannot be checked (F-19b)",
        )];
    };
    let Some(source_index) = column(&header, "Data source") else {
        return vec![at(
            READINESS_MODEL,
            "the readiness catalog has no `Data source` column (F-19b)",
        )];
    };
    let mut found = None;
    for (line, row) in &rows {
        if row
            .first()
            .is_some_and(|cell| has_token(cell, "RD-ORIGIN-EXPOSURE"))
        {
            found = Some((*line, row.get(source_index).map_or("", String::as_str)));
        }
    }
    let Some((line, source)) = found else {
        return vec![at(
            READINESS_MODEL,
            "the readiness catalog has no `RD-ORIGIN-EXPOSURE` row (F-19b)",
        )];
    };
    let mut missing = Vec::new();
    for token in ["MX", "SPF", "DKIM"] {
        if !has_token(source, token) {
            missing.push(token);
        }
    }
    if !source.to_lowercase().contains("mail header") {
        missing.push("mail headers");
    }
    if !has_token(source, "mail_outbox") {
        missing.push("mail_outbox");
    }
    let mut out = Vec::new();
    if !missing.is_empty() {
        out.push(at(
            format!("{READINESS_MODEL}:{line}"),
            format!(
                "the `RD-ORIGIN-EXPOSURE` data source must cover the mail part of the B12.2 phrase: MX, SPF and DKIM records, mail headers and the `mail_outbox` source; missing {missing:?} (F-19b)"
            ),
        ));
    }
    out
}

/// T-0026 step 2: the readiness model and `docs/UX/journeys/J-25.md` name the same checks, with the
/// same weights and the same remediation screen, and both weight sets sum to 100. The names are
/// compared as whole cells (the model prefixes each name with its `RD-` id, which is stripped); a
/// mismatch, a missing check or a wrong sum is a finding.
pub fn journey_readiness_findings(model: &str, journey: &str) -> Vec<Finding> {
    let Some((model_header, model_rows)) = section_table(model, "Check catalog") else {
        return Vec::new();
    };
    let Some((journey_header, journey_rows)) = section_table(journey, "Readiness score") else {
        return vec![at(
            JOURNEY_READINESS,
            "no `## Readiness score` table (T-0026 step 2)",
        )];
    };
    let (Some(model_check), Some(model_weight), Some(model_fix)) = (
        column(&model_header, "Check"),
        column(&model_header, "Weight"),
        column(&model_header, "Remediation link"),
    ) else {
        return vec![at(
            READINESS_MODEL,
            "the `## Check catalog` table has no Check, Weight and Remediation link columns (T-0026 step 2)",
        )];
    };
    let (Some(journey_check), Some(journey_weight), Some(journey_fix)) = (
        column(&journey_header, "Check"),
        column(&journey_header, "Weight"),
        column(&journey_header, "Fix link"),
    ) else {
        return vec![at(
            JOURNEY_READINESS,
            "the `## Readiness score` table has no Check, Weight and Fix link columns (T-0026 step 2)",
        )];
    };
    let mut out = Vec::new();
    let normalize = |cell: &str| {
        cell.split_once('·')
            .map_or(cell, |(_, name)| name)
            .trim()
            .to_lowercase()
    };
    let mut model_checks: BTreeMap<String, (u32, String)> = BTreeMap::new();
    let mut model_total = 0u32;
    for (_, row) in &model_rows {
        let Some(cell) = row.get(model_check) else {
            continue;
        };
        let Some(weight) = row
            .get(model_weight)
            .and_then(|cell| cell.trim().parse::<u32>().ok())
        else {
            continue;
        };
        let fix = row
            .get(model_fix)
            .map(|cell| cell.trim().to_owned())
            .unwrap_or_default();
        model_total = model_total.saturating_add(weight);
        model_checks.insert(normalize(cell), (weight, fix));
    }
    if model_checks.is_empty() {
        return vec![at(
            READINESS_MODEL,
            "the `## Check catalog` table has no parseable check rows (T-0026 step 2)",
        )];
    }
    let mut journey_total = 0u32;
    for (line, row) in &journey_rows {
        let location = format!("{JOURNEY_READINESS}:{line}");
        let Some(cell) = row.get(journey_check) else {
            continue;
        };
        let Some(weight) = row
            .get(journey_weight)
            .and_then(|cell| cell.trim().parse::<u32>().ok())
        else {
            out.push(at(
                &location,
                "the readiness row has no whole-number weight (T-0026 step 2)",
            ));
            continue;
        };
        journey_total = journey_total.saturating_add(weight);
        let fix = row
            .get(journey_fix)
            .map(|cell| cell.trim().to_owned())
            .unwrap_or_default();
        let name = normalize(cell);
        match model_checks.remove(&name) {
            None => out.push(at(
                &location,
                format!(
                    "the J-25 readiness check `{}` is not in the readiness model (T-0026 step 2)",
                    cell.trim()
                ),
            )),
            Some((model_weight, model_fix)) => {
                if weight != model_weight {
                    out.push(at(
                        &location,
                        format!(
                            "the J-25 weight {weight} of `{}` differs from the model weight {model_weight} (T-0026 step 2)",
                            cell.trim()
                        ),
                    ));
                }
                if !model_fix.is_empty() && !fix.is_empty() && fix != model_fix {
                    out.push(at(
                        &location,
                        format!(
                            "the J-25 fix link `{fix}` of `{}` differs from the model remediation link `{model_fix}` (T-0026 step 2)",
                            cell.trim()
                        ),
                    ));
                }
            }
        }
    }
    for (name, (weight, _)) in &model_checks {
        out.push(at(
            READINESS_MODEL,
            format!(
                "the model check `{name}` (weight {weight}) is not in the J-25 readiness table (T-0026 step 2)"
            ),
        ));
    }
    if journey_total != 100 {
        out.push(at(
            JOURNEY_READINESS,
            format!("the J-25 readiness weights sum to {journey_total}, not 100 (T-0026 A2)"),
        ));
    }
    if model_total != journey_total {
        out.push(at(
            READINESS_MODEL,
            format!(
                "the readiness model weights sum to {model_total} but the J-25 table sums to {journey_total} (T-0026 A2)"
            ),
        ));
    }
    out
}

/// Whole T-0026 check on the repository at `root`, reading the checksum-verified master specification.
pub fn check(root: &Path) -> Vec<Finding> {
    match crate::spec::load_master(root) {
        Ok(spec) => check_with_spec(root, &spec),
        Err(e) => vec![super::finding(
            "docs/SPEC.md",
            format!("cannot read the master specification: {}", e.0),
        )],
    }
}

/// Whole T-0026 check on the repository at `root`, with the master specification text.
pub fn check_with_spec(root: &Path, spec: &str) -> Vec<Finding> {
    let screens = screen_ids(spec);
    let b13 = b13_rows(spec);
    let mut out = Vec::new();
    if screens.is_empty() {
        out.push(at(
            "docs/SPEC.md",
            "the B12.1 screen table has no screen rows, so the T-0026 screens cannot be checked",
        ));
    }
    if b13.is_empty() {
        out.push(at(
            "docs/SPEC.md",
            "the B13 copy deck has no rows, so the readiness footnote cannot be compared",
        ));
    }
    let onboarding = load(root, ONBOARDING, &mut out);
    let readiness = load(root, READINESS_MODEL, &mut out);
    let journey = load(root, JOURNEY_READINESS, &mut out);
    // F-28: the two copy sources a `Copy key` of ONBOARDING.md may be defined in. The copy deck's
    // own completeness is checked by `ux_docs::ftl_style`; here its lines are only counted.
    let copy_deck = read_text(&root.join(COPY_DECK)).unwrap_or_default();
    let onboarding_ftl = match read_text(&root.join(ONBOARDING_FTL)) {
        Ok(text) => {
            if text.starts_with('\u{feff}') {
                out.push(at(
                    ONBOARDING_FTL,
                    "the file starts with a byte-order mark; UTF-8 without BOM is required (F-28)",
                ));
            }
            text
        }
        Err(error) => {
            out.push(at(
                ONBOARDING_FTL,
                format!(
                    "the file cannot be read ({error}); the empty-state strings and the four activation emails' stems live here (F-28)"
                ),
            ));
            String::new()
        }
    };
    let claims_cfg = claims::load_config(root).ok();
    // The new copy file is style-checked whenever it exists, independently of the two documents.
    out.extend(ftl_value_findings(
        ONBOARDING_FTL,
        &onboarding_ftl,
        claims_cfg.as_ref(),
    ));
    if let Some(text) = &onboarding {
        out.extend(structure_findings(ONBOARDING, text, &ONBOARDING_SECTIONS));
        out.extend(stage_findings(text, &screens));
        out.extend(checklist_findings(text, &screens));
        out.extend(next_action_findings(text, &screens));
        out.extend(nudge_findings(text, &screens));
        out.extend(empty_state_findings(text, &screens, &b13));
        out.extend(copy_key_definition_findings(
            text,
            &copy_deck,
            &onboarding_ftl,
            &b13,
        ));
        out.extend(monitor_findings(text, &screens));
        out.extend(measure_findings(text, spec));
        out.extend(email_findings(text, &b13));
        out.extend(claim_findings(text));
    }
    if let Some(text) = &readiness {
        out.extend(structure_findings(
            READINESS_MODEL,
            text,
            &READINESS_SECTIONS,
        ));
        out.extend(category_findings(text));
        out.extend(catalog_findings(text, &screens));
        out.extend(b122_mapping_findings(text, spec));
        out.extend(waf_partial_findings(text));
        out.extend(origin_mail_findings(text));
        out.extend(weight_findings(text));
        out.extend(unknown_findings(text, &b13));
        out.extend(footnote_findings(text, &b13, &screens));
        out.extend(scoring_findings(text));
        out.extend(claim_findings(text));
        if let Some(journey) = &journey {
            out.extend(journey_readiness_findings(text, journey));
        }
    }
    out
}

/// Read one deliverable; a missing file or a byte-order mark is a finding.
fn load(root: &Path, path: &str, out: &mut Vec<Finding>) -> Option<String> {
    match read_text(&root.join(path)) {
        Ok(text) => {
            if text.starts_with('\u{feff}') {
                out.push(at(
                    path,
                    "the document starts with a byte-order mark; UTF-8 without BOM is required",
                ));
            }
            Some(text)
        }
        Err(error) => {
            out.push(at(
                path,
                format!("the document cannot be read ({error}); T-0026 requires it"),
            ));
            None
        }
    }
}

/// Structure of one deliverable: it exists, is UTF-8 without a byte-order mark, and has every required
/// section with a non-empty body (T-0026 deliverables, A1 to A5).
pub fn structure_findings(path: &str, text: &str, required: &[&str]) -> Vec<Finding> {
    let mut out = Vec::new();
    if text.trim().is_empty() {
        out.push(at(path, "the document is empty (T-0026 deliverables)"));
        return out;
    }
    for title in required {
        match section_body(text, title) {
            None => out.push(at(
                path,
                format!("the `## {title}` section is missing (T-0026 deliverables, A1 to A5)"),
            )),
            Some(body) => {
                let has_content = body.iter().any(|(_, line)| {
                    let trimmed = line.trim();
                    !trimmed.is_empty() && !trimmed.starts_with('#')
                });
                if !has_content {
                    out.push(at(
                        path,
                        format!("the `## {title}` section has no content (T-0026 deliverables)"),
                    ));
                }
            }
        }
    }
    out
}

/// T-0026 step 1: the twelve stages appear exactly once, in order, and each names its expected real
/// B12.1 screen.
pub fn stage_findings(text: &str, screens: &BTreeSet<String>) -> Vec<Finding> {
    let mut out = Vec::new();
    let Some((header, rows)) = section_table(text, "Stage map") else {
        return vec![at(
            ONBOARDING,
            "no `## Stage map` table with the twelve onboarding stages (T-0026 step 1)",
        )];
    };
    let Some(stage_index) = column(&header, "Stage") else {
        return vec![at(
            ONBOARDING,
            "the stage map has no `Stage` column (T-0026 step 1)",
        )];
    };
    for required in [
        "Screen",
        "User goal",
        "Why we ask",
        "Exit criterion",
        "Drop-off risk",
    ] {
        if column(&header, required).is_none() {
            out.push(at(
                ONBOARDING,
                format!("the stage map has no `{required}` column (T-0026 step 1)"),
            ));
        }
    }
    if rows.len() != STAGES.len() {
        out.push(at(
            ONBOARDING,
            format!(
                "the stage map has {} rows but T-0026 step 1 names {} stages",
                rows.len(),
                STAGES.len()
            ),
        ));
    }
    let mut present = BTreeSet::new();
    for (line, row) in &rows {
        let Some(cell) = row.get(stage_index) else {
            out.push(at(
                format!("{ONBOARDING}:{line}"),
                "the stage row has no stage cell (T-0026 step 1)",
            ));
            continue;
        };
        let name = cell.trim();
        let normalized = name.to_lowercase();
        let Some((stage, expected_screen)) = STAGES
            .iter()
            .find(|(stage, _)| stage.to_lowercase() == normalized)
        else {
            out.push(at(
                format!("{ONBOARDING}:{line}"),
                format!("`{name}` is not one of the twelve stages of T-0026 step 1"),
            ));
            continue;
        };
        if !present.insert(stage.to_lowercase()) {
            out.push(at(
                format!("{ONBOARDING}:{line}"),
                format!("the stage `{stage}` appears more than once (T-0026 step 1)"),
            ));
        }
        let screen_cell = column(&header, "Screen")
            .and_then(|index| row.get(index))
            .map_or("", String::as_str);
        let tokens = screen_tokens(screen_cell);
        if tokens.is_empty() {
            out.push(at(
                format!("{ONBOARDING}:{line}"),
                format!("the stage `{stage}` names no B12.1 screen (T-0026 step 1)"),
            ));
        }
        for token in &tokens {
            if !screens.contains(token) {
                out.push(at(
                    format!("{ONBOARDING}:{line}"),
                    format!("the stage `{stage}` names `{token}`, which is not a B12.1 screen (T-0026 step 1)"),
                ));
            }
        }
        if !tokens.iter().any(|token| token == expected_screen) {
            out.push(at(
                format!("{ONBOARDING}:{line}"),
                format!(
                    "the stage `{stage}` must name the B12.1 screen `{expected_screen}` for its user goal (T-0026 step 1)"
                ),
            ));
        }
        for required in ["User goal", "Why we ask", "Exit criterion", "Drop-off risk"] {
            let empty = column(&header, required)
                .and_then(|index| row.get(index))
                .is_none_or(|value| value.trim().is_empty());
            if empty {
                out.push(at(
                    format!("{ONBOARDING}:{line}"),
                    format!("the stage `{stage}` has an empty `{required}` cell (T-0026 step 1)"),
                ));
            }
        }
    }
    for (stage, _) in STAGES {
        if !present.contains(&stage.to_lowercase()) {
            out.push(at(
                ONBOARDING,
                format!("the stage `{stage}` is missing from the stage map (T-0026 step 1)"),
            ));
        }
    }
    out
}

/// T-0026 step 1 and T-0143: the checklist persists on S-040, resumes, is ordered, marks optional
/// items and has no dead ends.
pub fn checklist_findings(text: &str, screens: &BTreeSet<String>) -> Vec<Finding> {
    let mut out = Vec::new();
    let Some((header, rows)) = section_table(text, "Checklist structure") else {
        return vec![at(
            ONBOARDING,
            "no `## Checklist structure` table (T-0026 step 1)",
        )];
    };
    let Some(property_index) = column(&header, "Property") else {
        return vec![at(
            ONBOARDING,
            "the checklist table has no `Property` column (T-0026 step 1)",
        )];
    };
    let Some(rule_index) = column(&header, "Rule") else {
        return vec![at(
            ONBOARDING,
            "the checklist table has no `Rule` column (T-0026 step 1)",
        )];
    };
    let required = [
        "Derived state",
        "Persistence",
        "Resume",
        "Ordering",
        "Optional items",
        "Dismissal and return",
        "No dead ends",
    ];
    let mut rules: BTreeMap<String, String> = BTreeMap::new();
    for (line, row) in &rows {
        let property = row
            .get(property_index)
            .map_or("", String::as_str)
            .trim()
            .to_lowercase();
        let rule = row.get(rule_index).map_or("", String::as_str).trim();
        if rule.is_empty() {
            out.push(at(
                format!("{ONBOARDING}:{line}"),
                format!("the checklist property `{property}` has an empty rule (T-0026 step 1)"),
            ));
        }
        if !property.is_empty() {
            rules.insert(property, rule.to_owned());
        }
    }
    for property in required {
        let key = property.to_lowercase();
        if !rules.contains_key(&key) {
            out.push(at(
                ONBOARDING,
                format!("the checklist has no `{property}` property (T-0026 step 1)"),
            ));
        }
    }
    if let Some(rule) = rules.get("persistence") {
        if !has_token(rule, "S-040") || !screens.contains("S-040") {
            out.push(at(
                ONBOARDING,
                "the checklist persistence rule must name the B12.1 screen S-040 (T-0026 step 1, T-0143)",
            ));
        }
        if !rule.to_lowercase().contains("dismiss") {
            out.push(at(
                ONBOARDING,
                "the checklist persistence rule must say the checklist stays until done or dismissed (T-0143)",
            ));
        }
    }
    if let Some(rule) = rules.get("resume")
        && !rule.to_lowercase().contains("unfinished")
    {
        out.push(at(
            ONBOARDING,
            "the checklist resume rule must return to the first unfinished item (T-0143)",
        ));
    }
    if let Some(rule) = rules.get("optional items")
        && !rule.to_lowercase().contains("optional")
    {
        out.push(at(
            ONBOARDING,
            "the optional-items rule must say which item is optional (T-0143)",
        ));
    }
    if let Some(rule) = rules.get("no dead ends") {
        let tokens = screen_tokens(rule);
        if tokens.is_empty() {
            out.push(at(
                ONBOARDING,
                "the no-dead-ends rule must name the fix-link screen (T-0026 step 1)",
            ));
        }
        for token in &tokens {
            if !screens.contains(token) {
                out.push(at(
                    ONBOARDING,
                    format!("the no-dead-ends rule names `{token}`, which is not a B12.1 screen"),
                ));
            }
        }
    }
    let joined = section_text(text, "Checklist structure").to_lowercase();
    if !joined.contains("never blocks product use") {
        out.push(at(
            ONBOARDING,
            "the checklist section must say that the checklist never blocks product use (T-0143 notes)",
        ));
    }
    out
}

/// T-0026 step 3 and A3: the next-best-action rules are a numbered decision list with explicit
/// first-match semantics, unique priorities, real screens and example rows this module evaluates.
pub fn next_action_findings(text: &str, screens: &BTreeSet<String>) -> Vec<Finding> {
    let mut out = Vec::new();
    let Some(body) = section_body(text, "Next best action") else {
        return vec![at(
            ONBOARDING,
            "no `## Next best action` section with the decision list (T-0026 step 3)",
        )];
    };
    let joined = section_text(text, "Next best action");
    if !joined.to_lowercase().contains("first match wins") {
        out.push(at(
            ONBOARDING,
            "the decision list must state that the first match wins (T-0026 step 3, A3)",
        ));
    }
    let Ok(rule_re) = Regex::new(r"^(\d+)\.\s+rule\s+(\d+):\s+if\s+(.+?)\s+then\s+(.+)$") else {
        return vec![at(
            ONBOARDING,
            "the module pattern for the decision-list grammar does not compile",
        )];
    };
    let mut rules: Vec<DecisionRule> = Vec::new();
    for (line, raw) in &body {
        let trimmed = raw.trim();
        if !trimmed.chars().next().is_some_and(|c| c.is_ascii_digit()) {
            continue;
        }
        let Some(captures) = rule_re.captures(trimmed) else {
            out.push(at(
                format!("{ONBOARDING}:{line}"),
                "a numbered rule does not follow `rule N: if <conditions> then <action>` (T-0026 step 3)",
            ));
            continue;
        };
        let ordinal = captures
            .get(1)
            .and_then(|value| value.as_str().parse::<usize>().ok());
        let priority = captures
            .get(2)
            .and_then(|value| value.as_str().parse::<usize>().ok());
        let Some(priority) = priority else {
            out.push(at(
                format!("{ONBOARDING}:{line}"),
                "a rule has no numeric priority (T-0026 step 3)",
            ));
            continue;
        };
        if ordinal != Some(priority) {
            out.push(at(
                format!("{ONBOARDING}:{line}"),
                format!(
                    "rule `{priority}` is not listed at its own priority position (T-0026 step 3)"
                ),
            ));
        }
        let conditions = captures
            .get(3)
            .map(|value| parse_conditions(value.as_str(), *line, &mut out))
            .unwrap_or_default();
        let action = captures
            .get(4)
            .map(|value| value.as_str().trim().to_owned())
            .unwrap_or_default();
        let generic = conditions.len() == 1
            && conditions
                .first()
                .is_some_and(|condition| matches!(condition, Condition::AnyNotPass));
        let unconditional = conditions.is_empty();
        if generic {
            let lower = action.to_lowercase();
            if !lower.contains("first non-pass check in catalog order")
                || !lower.contains("remediation link")
            {
                out.push(at(
                    format!("{ONBOARDING}:{line}"),
                    "the generic rule must say that it opens the remediation link of the first non-Pass check in catalog order (F-20a)",
                ));
            }
        } else if !unconditional {
            let tokens = screen_tokens(&action);
            if tokens.is_empty() {
                out.push(at(
                    format!("{ONBOARDING}:{line}"),
                    format!("rule `{priority}` has no B12.1 screen in its action (T-0026 step 3)"),
                ));
            }
            for token in &tokens {
                if !screens.contains(token) {
                    out.push(at(
                        format!("{ONBOARDING}:{line}"),
                        format!("rule `{priority}` names `{token}`, which is not a B12.1 screen"),
                    ));
                }
            }
        }
        rules.push(DecisionRule {
            priority,
            conditions,
            action,
        });
    }
    if rules.len() < 8 {
        out.push(at(
            ONBOARDING,
            format!(
                "the decision list has {} rules; T-0026 step 3 needs at least eight (A3)",
                rules.len()
            ),
        ));
    }
    let mut seen = BTreeSet::new();
    let mut last = 0_usize;
    for rule in &rules {
        if !seen.insert(rule.priority) {
            out.push(at(
                ONBOARDING,
                format!(
                    "the priority {} appears more than once (T-0026 A3)",
                    rule.priority
                ),
            ));
        }
        if rule.priority <= last {
            out.push(at(
                ONBOARDING,
                format!(
                    "the priorities are not in increasing order at rule {} (T-0026 A3)",
                    rule.priority
                ),
            ));
        }
        last = rule.priority;
    }
    let generic_index = rules.iter().position(rule_is_generic);
    let unconditional_index = rules.iter().position(rule_is_unconditional);
    let generic_count = rules.iter().filter(|rule| rule_is_generic(rule)).count();
    if generic_count != 1 {
        out.push(at(
            ONBOARDING,
            format!(
                "the decision list has {generic_count} generic rules; exactly one rule must carry the condition `any check is not Pass` (F-20a)"
            ),
        ));
    }
    let unconditional_count = rules
        .iter()
        .filter(|rule| rule_is_unconditional(rule))
        .count();
    if unconditional_count != 1 {
        out.push(at(
            ONBOARDING,
            format!(
                "the decision list has {unconditional_count} unconditional rules; exactly one last rule must return the all-Pass outcome (F-20b)"
            ),
        ));
    }
    if let Some(last_rule) = rules.last()
        && !rule_is_unconditional(last_rule)
    {
        out.push(at(
            ONBOARDING,
            "the last rule must be the unconditional rule that returns the distinct all-Pass outcome (F-20b)",
        ));
    }
    if let (Some(generic_position), Some(unconditional_position)) =
        (generic_index, unconditional_index)
        && generic_position > unconditional_position
    {
        out.push(at(
            ONBOARDING,
            "the generic rule must come before the unconditional all-Pass rule, otherwise a non-Pass check ends at the all-Pass outcome (F-20a)",
        ));
    }
    let Some((header, rows)) = section_table(text, "Next best action") else {
        out.push(at(
            ONBOARDING,
            "no example table under `## Next best action` (T-0026 Tests)",
        ));
        return out;
    };
    let columns = ["Inputs", "Expected rule", "Expected action"];
    let mut missing = false;
    for required in columns {
        if column(&header, required).is_none() {
            out.push(at(
                ONBOARDING,
                format!(
                    "the next-best-action example table has no `{required}` column (T-0026 Tests)"
                ),
            ));
            missing = true;
        }
    }
    if missing {
        return out;
    }
    if rows.len() < 8 {
        out.push(at(
            ONBOARDING,
            format!(
                "the example table has {} rows; T-0026 Tests needs at least eight (A3)",
                rows.len()
            ),
        ));
    }
    let mut multi_condition_rows = 0_usize;
    for (line, row) in &rows {
        let inputs = column(&header, "Inputs")
            .and_then(|index| row.get(index))
            .map_or("", String::as_str);
        let expected_rule = column(&header, "Expected rule")
            .and_then(|index| row.get(index))
            .and_then(|value| value.trim().parse::<usize>().ok());
        let expected_action = column(&header, "Expected action")
            .and_then(|index| row.get(index))
            .map_or("", String::as_str);
        let Some(expected_rule) = expected_rule else {
            out.push(at(
                format!("{ONBOARDING}:{line}"),
                "an example row has no numeric expected rule (T-0026 Tests)",
            ));
            continue;
        };
        let explicit_conditions = inputs
            .split(';')
            .map(str::trim)
            .filter(|part| {
                !part.is_empty()
                    && !part.eq_ignore_ascii_case("none")
                    && !part.eq_ignore_ascii_case("others=Pass")
                    && !part.to_lowercase().contains("every check unknown")
            })
            .count();
        if explicit_conditions >= 2 {
            multi_condition_rows += 1;
        }
        let mut partial = BTreeMap::new();
        let state = example_state(inputs, &mut partial);
        match evaluate(&rules, &state) {
            None => out.push(at(
                format!("{ONBOARDING}:{line}"),
                format!(
                    "the example input `{inputs}` matches no rule of the decision list (T-0026 Tests)"
                ),
            )),
            Some((rule, action)) => {
                if rule.priority != expected_rule {
                    out.push(at(
                        format!("{ONBOARDING}:{line}"),
                        format!(
                            "the example `{inputs}` matches the first-match rule {} but the table expects rule {expected_rule} (T-0026 Tests)",
                            rule.priority
                        ),
                    ));
                }
                if !same_action(&action, expected_action) {
                    out.push(at(
                        format!("{ONBOARDING}:{line}"),
                        format!(
                            "the example expects the action `{}` but rule {} returns `{action}` (T-0026 Tests)",
                            expected_action.trim(),
                            rule.priority
                        ),
                    ));
                }
            }
        }
    }
    if multi_condition_rows < 6 {
        out.push(at(
            ONBOARDING,
            format!(
                "the example table has {multi_condition_rows} multi-condition rows; F-20c needs at least six states with two or more check conditions to test the priority order"
            ),
        ));
    }
    let all_pass: BTreeMap<String, Status> = CHECKS
        .iter()
        .map(|check| (check.id.to_owned(), Status::Pass))
        .collect();
    match evaluate(&rules, &all_pass) {
        Some((_, action)) if same_action(&action, ALL_PASS_OUTCOME) => {}
        Some((rule, action)) => out.push(at(
            ONBOARDING,
            format!(
                "the all-Pass state must return the distinct outcome `{ALL_PASS_OUTCOME}`, but rule {} returns `{action}` (F-20b)",
                rule.priority
            ),
        )),
        None => out.push(at(
            ONBOARDING,
            "the all-Pass state matches no rule, so the card has no all-Pass outcome (F-20b)",
        )),
    }
    for check in CHECKS {
        for status in [Status::Fail, Status::Unknown, Status::Partial] {
            let mut state = all_pass.clone();
            state.insert(check.id.to_owned(), status);
            let status_name = match status {
                Status::Pass => "Pass",
                Status::Partial => "Partial",
                Status::Fail => "Fail",
                Status::Unknown => "Unknown",
            };
            match evaluate(&rules, &state) {
                None => out.push(at(
                    ONBOARDING,
                    format!(
                        "the catalog check `{}` with status `{status_name}` is not reachable by any rule (F-20a)",
                        check.id
                    ),
                )),
                Some((rule, action)) => {
                    if rule_is_unconditional(rule) || same_action(&action, ALL_PASS_OUTCOME) {
                        out.push(at(
                            ONBOARDING,
                            format!(
                                "the catalog check `{}` with status `{status_name}` ends at the all-Pass outcome instead of a remediation, so every catalog id is not reachable (F-20a)",
                                check.id
                            ),
                        ));
                        continue;
                    }
                    if rule_is_generic(rule)
                        && (!has_token(&action, check.id)
                            || !has_token(&action, check.remediation))
                    {
                        out.push(at(
                            ONBOARDING,
                            format!(
                                "the generic rule must open the remediation link for `{}` at `{}` (F-20a)",
                                check.id, check.remediation
                            ),
                        ));
                    }
                    if !rule_is_generic(rule)
                        && !rule.conditions.iter().any(|condition| {
                            matches!(
                                condition,
                                Condition::Check { id, status: condition_status }
                                    if id == check.id && *condition_status == status
                            )
                        })
                    {
                        out.push(at(
                            ONBOARDING,
                            format!(
                                "rule {} matches the check `{}` with status `{status_name}` without naming it as a condition (F-20a)",
                                rule.priority, check.id
                            ),
                        ));
                    }
                }
            }
        }
    }
    if let Some(mfa_rule) = rules.iter().find(|rule| {
        rule.conditions
            .iter()
            .any(|condition| matches!(condition, Condition::Check { id, .. } if id == "RD-MFA"))
    }) {
        let action_lower = mfa_rule.action.to_lowercase();
        if !action_lower.contains("owner") || !action_lower.contains("admin") {
            out.push(at(
                ONBOARDING,
                "the MFA rule (rule 11) must name who can perform the enrolment: an owner or an admin enrols MFA for the organisation (F-20d)",
            ));
        }
    } else {
        out.push(at(
            ONBOARDING,
            "no rule handles the RD-MFA check, so the card cannot name who can enrol MFA (F-20d)",
        ));
    }
    if !joined.to_lowercase().contains("non-owner") {
        out.push(at(
            ONBOARDING,
            "the next-best-action section must say that a non-owner role's card names who can perform the step (F-20d)",
        ));
    }
    out
}

/// T-0026 step 4 and A4: every nudge has a numeric frequency cap and an opt-out.
pub fn nudge_findings(text: &str, screens: &BTreeSet<String>) -> Vec<Finding> {
    let mut out = Vec::new();
    let Some((header, rows)) = section_table(text, "Nudges and reminders") else {
        return vec![at(
            ONBOARDING,
            "no `## Nudges and reminders` table (T-0026 step 4, A4)",
        )];
    };
    for required in ["Nudge", "Channel", "Frequency cap", "Opt-out"] {
        if column(&header, required).is_none() {
            out.push(at(
                ONBOARDING,
                format!("the nudge table has no `{required}` column (T-0026 step 4, A4)"),
            ));
        }
    }
    if rows.len() < 4 {
        out.push(at(
            ONBOARDING,
            format!(
                "the nudge table has {} rows; in-app and email nudges need at least four (T-0026 step 4)",
                rows.len()
            ),
        ));
    }
    let mut opt_out_screen = false;
    for (line, row) in &rows {
        let cap = column(&header, "Frequency cap")
            .and_then(|index| row.get(index))
            .map_or("", String::as_str);
        let cap_lower = cap.to_lowercase();
        let mut cap_ok = true;
        for fragment in cap_lower.split(" and ") {
            let has_number = fragment.chars().any(|c| c.is_ascii_digit());
            let has_unit = fragment.contains("hour")
                || fragment.contains("day")
                || fragment.contains("week")
                || fragment.contains("month")
                || fragment.contains("total");
            if !has_number || !has_unit {
                cap_ok = false;
            }
        }
        if !cap_ok {
            out.push(at(
                format!("{ONBOARDING}:{line}"),
                "every nudge needs a numeric frequency cap with a time unit (T-0026 step 4, A4)",
            ));
        }
        let opt_out = column(&header, "Opt-out")
            .and_then(|index| row.get(index))
            .map_or("", String::as_str);
        let opt_out_lower = opt_out.to_lowercase();
        let can_opt_out = opt_out_lower.contains("opt out")
            || opt_out_lower.contains("opt-out")
            || opt_out_lower.contains("dismiss")
            || opt_out_lower.contains("unsubscribe");
        if !can_opt_out {
            out.push(at(
                format!("{ONBOARDING}:{line}"),
                "every nudge needs an opt-out or a dismissal path (T-0026 step 4, A4)",
            ));
        }
        let tokens = screen_tokens(opt_out);
        if tokens.iter().any(|token| screens.contains(token)) {
            opt_out_screen = true;
        }
    }
    if !opt_out_screen {
        out.push(at(
            ONBOARDING,
            "the opt-out must name the real preference screen (T-0026 step 4, A4)",
        ));
    }
    let joined = section_text(text, "Nudges and reminders").to_lowercase();
    if !joined.contains("notification preferences") {
        out.push(at(
            ONBOARDING,
            "the nudge section must name the notification preferences screen (T-0026 step 4)",
        ));
    }
    if !joined.contains("quiet hours") {
        out.push(at(
            ONBOARDING,
            "the nudge section must state the quiet hours (T-0026 step 4)",
        ));
    }
    out
}

/// T-0026 step 5: every empty state names a real B12.1 screen and an honest copy key.
pub fn empty_state_findings(
    text: &str,
    screens: &BTreeSet<String>,
    b13: &[(String, String)],
) -> Vec<Finding> {
    let mut out = Vec::new();
    let Some((header, rows)) = section_table(text, "Empty states") else {
        return vec![at(ONBOARDING, "no `## Empty states` table (T-0026 step 5)")];
    };
    for required in ["Screen", "Empty state", "Copy key", "Next action"] {
        if column(&header, required).is_none() {
            out.push(at(
                ONBOARDING,
                format!("the empty-state table has no `{required}` column (T-0026 step 5)"),
            ));
        }
    }
    if rows.len() < 8 {
        out.push(at(
            ONBOARDING,
            format!(
                "the empty-state table has {} rows; T-0026 step 5 covers each major screen (at least eight)",
                rows.len()
            ),
        ));
    }
    let b13_keys: BTreeSet<&str> = b13.iter().map(|(key, _)| key.as_str()).collect();
    let mut named = BTreeSet::new();
    for (line, row) in &rows {
        let screen_cell = column(&header, "Screen")
            .and_then(|index| row.get(index))
            .map_or("", String::as_str);
        let tokens = screen_tokens(screen_cell);
        if tokens.is_empty() {
            out.push(at(
                format!("{ONBOARDING}:{line}"),
                "the empty state names no B12.1 screen (T-0026 step 5)",
            ));
        }
        for token in &tokens {
            if !screens.contains(token) {
                out.push(at(
                    format!("{ONBOARDING}:{line}"),
                    format!("the empty state names `{token}`, which is not a B12.1 screen"),
                ));
            } else {
                named.insert(token.clone());
            }
        }
        let copy_cell = column(&header, "Copy key")
            .and_then(|index| row.get(index))
            .map_or("", String::as_str);
        let keys = backticked(copy_cell);
        if keys.is_empty() {
            out.push(at(
                format!("{ONBOARDING}:{line}"),
                "the empty state names no copy key (T-0026 step 5)",
            ));
        }
        for key in &keys {
            if !well_formed_key(key) {
                out.push(at(
                    format!("{ONBOARDING}:{line}"),
                    format!("the copy key `{key}` is not a well-formed semantic key (T-0019)"),
                ));
            }
            if b13_keys.contains(key.as_str()) && !key.starts_with("empty-") {
                out.push(at(
                    format!("{ONBOARDING}:{line}"),
                    format!("the well-formed B13 key `{key}` belongs to another string and cannot be an empty-state key (T-0026 step 5)"),
                ));
            }
            if !b13_keys.contains(key.as_str()) && !key.starts_with("empty-") {
                out.push(at(
                    format!("{ONBOARDING}:{line}"),
                    format!(
                        "the new empty-state key `{key}` must start with `empty-` (T-0026 step 5)"
                    ),
                ));
            }
        }
        let next = column(&header, "Next action")
            .and_then(|index| row.get(index))
            .map_or("", String::as_str);
        if next.trim().is_empty() {
            out.push(at(
                format!("{ONBOARDING}:{line}"),
                "the empty state names no next action (T-0144 A2)",
            ));
        }
    }
    for major in [
        "S-035", "S-040", "S-041", "S-044", "S-054", "S-065", "S-076", "S-082",
    ] {
        if !named.contains(major) {
            out.push(at(
                ONBOARDING,
                format!("the empty states do not cover the major screen {major} (T-0026 step 5)"),
            ));
        }
    }
    let joined = section_text(text, "Empty states").to_lowercase();
    if !joined.contains("t-0144") || !joined.contains("copy deck") {
        out.push(at(
            ONBOARDING,
            "the empty-state section must say that the new keys are registered with T-0144 and not added to the copy deck here (T-0026 step 5)",
        ));
    }
    out
}

/// One message line of a Fluent file: `key = value`.
struct FtlMessage {
    /// 1-based line number.
    line: usize,
    /// The key on the left of `=`.
    key: String,
    /// The value on the right of `=`, trimmed.
    value: String,
}

/// Parse the messages of a Fluent file: comment and blank lines are skipped; every other line must be
/// `key = value`.
fn parse_ftl(text: &str) -> Vec<FtlMessage> {
    let mut out = Vec::new();
    for (n, line) in text.lines().enumerate() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        match trimmed.split_once('=') {
            Some((key, value)) => out.push(FtlMessage {
                line: n + 1,
                key: key.trim().to_owned(),
                value: value.trim().to_owned(),
            }),
            None => out.push(FtlMessage {
                line: n + 1,
                key: String::new(),
                value: trimmed.to_owned(),
            }),
        }
    }
    out
}

/// True when `text` contains a character that renders as an emoji or a decorative dingbat (the same
/// ranges the copy-deck style rule uses).
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

/// F-28 (review round 2): the keys named by every `Copy key` column of `docs/UX/ONBOARDING.md`.
///
/// The scan is generic on purpose: the rule covers the column wherever it appears, not only in
/// `## Empty states`, so a later table cannot cite a key that exists nowhere. A key is the whole
/// content of one inline-code span; a cell may name one key only.
pub fn copy_key_references(text: &str) -> Vec<(usize, String)> {
    let lines: Vec<(usize, String)> = super::prose_lines(text)
        .into_iter()
        .map(|(n, line)| (n, line.to_owned()))
        .collect();
    let mut out = Vec::new();
    for table in super::tables_in(&lines) {
        let Some(index) = column(&table.header, "Copy key") else {
            continue;
        };
        for (n, row) in &table.rows {
            let cell = row.get(index).map_or("", String::as_str);
            for key in backticked(cell) {
                out.push((*n, key));
            }
        }
    }
    out
}

/// F-28 (review round 2): every `Copy key` of `docs/UX/ONBOARDING.md` is defined exactly once across
/// the B13 copy deck (`i18n/en/copy-deck.ftl`, which implements the B13 table) and
/// `i18n/en/onboarding.ftl`. A key defined nowhere, twice in one file, in both files, or without text
/// is a finding.
///
/// The B13 table and the copy deck are one definition, not two: the deck implements the table, and the
/// deck-vs-B13 equality is enforced by `ux_docs::ftl_style`. A key that is in B13 or in the deck is
/// therefore canonical, and only a second definition in `onboarding.ftl` makes it a duplicate.
pub fn copy_key_definition_findings(
    onboarding: &str,
    copy_deck: &str,
    onboarding_ftl: &str,
    b13: &[(String, String)],
) -> Vec<Finding> {
    let mut out = Vec::new();
    let references = copy_key_references(onboarding);
    if references.is_empty() {
        out.push(at(
            ONBOARDING,
            "no `Copy key` column names a copy key, so the copy keys cannot be checked (F-28)",
        ));
        return out;
    }
    let b13_keys: BTreeSet<&str> = b13.iter().map(|(key, _)| key.as_str()).collect();
    let deck = parse_ftl(copy_deck);
    let ftl = parse_ftl(onboarding_ftl);
    let mut deck_counts: BTreeMap<&str, usize> = BTreeMap::new();
    for message in &deck {
        *deck_counts.entry(message.key.as_str()).or_insert(0) += 1;
    }
    let mut ftl_counts: BTreeMap<&str, usize> = BTreeMap::new();
    for message in &ftl {
        *ftl_counts.entry(message.key.as_str()).or_insert(0) += 1;
    }

    // A key defined twice inside the new file.
    for (key, count) in &ftl_counts {
        if *count > 1 {
            out.push(at(
                ONBOARDING_FTL,
                format!(
                    "the key \"{key}\" is defined {count} times; it must appear exactly once (F-28)"
                ),
            ));
        }
    }
    // A key the new file shares with the B13 copy deck: two definitions of one string.
    for key in ftl_counts.keys() {
        if b13_keys.contains(key) || deck_counts.get(key).copied().unwrap_or(0) > 0 {
            out.push(at(
                ONBOARDING_FTL,
                format!(
                    "the key \"{key}\" is also defined in the B13 copy deck, so it is defined twice (F-28)"
                ),
            ));
        }
    }

    let mut deck_duplicates: BTreeSet<&str> = BTreeSet::new();
    for (line, key) in &references {
        let deck_count = deck_counts.get(key.as_str()).copied().unwrap_or(0);
        if deck_count > 1 && deck_duplicates.insert(key.as_str()) {
            out.push(at(
                COPY_DECK,
                format!("the key \"{key}\" is defined {deck_count} times; it must appear exactly once (F-28)"),
            ));
        }
        let canonical = b13_keys.contains(key.as_str()) || deck_count > 0;
        let ftl_count = ftl_counts.get(key.as_str()).copied().unwrap_or(0);
        if !canonical && ftl_count == 0 {
            out.push(at(
                format!("{ONBOARDING}:{line}"),
                format!(
                    "the copy key `{key}` is not defined in B13, {COPY_DECK} or {ONBOARDING_FTL} (F-28)"
                ),
            ));
            continue;
        }
        if !canonical
            && ftl
                .iter()
                .filter(|m| m.key == *key)
                .all(|m| m.value.is_empty())
        {
            out.push(at(
                ONBOARDING_FTL,
                format!("the copy key \"{key}\" is defined without text (F-28)"),
            ));
        }
    }
    out
}

/// F-28 (review round 2): the Fluent style rules the repository applies to a copy file, on
/// `i18n/en/onboarding.ftl`: semantic hyphenated keys, one definition per key, no empty value
/// without the `# empty: needs text` comment, no emoji, no `<` markup, an exclamation mark only in
/// a `success-` key, no duplicate values, and the existing claims scanner on every value.
pub fn ftl_value_findings(
    path: &str,
    text: &str,
    claims_cfg: Option<&claims::Config>,
) -> Vec<Finding> {
    let mut out = Vec::new();
    let messages = parse_ftl(text);
    let key_shape = Regex::new(KEY_SHAPE).ok();
    if key_shape.is_none() {
        out.push(at(path, "cannot compile the i18n key pattern (F-28)"));
    }
    let lines: Vec<&str> = text.lines().collect();
    let mut counts: BTreeMap<String, usize> = BTreeMap::new();
    let mut values: BTreeMap<String, Vec<String>> = BTreeMap::new();
    for message in &messages {
        let loc = format!("{path}:{}", message.line);
        if message.key.is_empty() {
            out.push(at(&loc, "the line is not a `key = value` message (F-28)"));
            continue;
        }
        if let Some(re) = &key_shape
            && !re.is_match(&message.key)
        {
            out.push(at(
                &loc,
                format!(
                    "the i18n key \"{}\" is not a semantic hyphenated stem (F-28)",
                    message.key
                ),
            ));
        }
        *counts.entry(message.key.clone()).or_insert(0) += 1;
        if message.value.is_empty() {
            let commented = message
                .line
                .checked_sub(2)
                .and_then(|index| lines.get(index))
                .is_some_and(|line| line.contains(EMPTY_COMMENT));
            if !commented {
                out.push(at(
                    &loc,
                    format!(
                        "the key \"{}\" has an empty value without the `# {EMPTY_COMMENT}` comment above it (F-28)",
                        message.key
                    ),
                ));
            }
            continue;
        }
        if has_emoji(&message.value) {
            out.push(at(
                &loc,
                format!("the value of \"{}\" contains an emoji (F-28)", message.key),
            ));
        }
        if message.value.contains('!')
            && !(message.key.starts_with("success-") || message.key.ends_with("-success"))
        {
            out.push(at(
                &loc,
                format!(
                    "the exclamation mark in \"{}\" is only allowed in a `success-` key (F-28)",
                    message.key
                ),
            ));
        }
        if message.value.contains('<') {
            out.push(at(
                &loc,
                format!(
                    "the value of \"{}\" contains `<` markup (F-28)",
                    message.key
                ),
            ));
        }
        if message.value.contains("$count")
            && !(message.value.contains("[one]") && message.value.contains("[other]"))
        {
            out.push(at(
                &loc,
                format!(
                    "the key \"{}\" uses `$count` without a selector with `[one]` and `[other]` (F-28)",
                    message.key
                ),
            ));
        }
        values
            .entry(message.value.clone())
            .or_default()
            .push(message.key.clone());
    }
    for (key, count) in &counts {
        if *count > 1 {
            out.push(at(
                path,
                format!(
                    "the key \"{key}\" is defined {count} times; it must appear exactly once (F-28)"
                ),
            ));
        }
    }
    for (value, keys) in &values {
        if keys.len() > 1 {
            out.push(at(
                path,
                format!(
                    "the keys {} share the same value \"{value}\", so a translator cannot tell them apart (F-28)",
                    keys.join(", ")
                ),
            ));
        }
    }
    if let Some(cfg) = claims_cfg {
        for message in &messages {
            if message.value.is_empty() {
                continue;
            }
            for finding in claims::scan_text(cfg, path, &format!("{}\n", message.value)) {
                out.push(at(
                    format!("{path}:{}", message.line),
                    format!("the value of \"{}\": {}", message.key, finding.message),
                ));
            }
        }
    }
    out
}

/// T-0026 step 6: the monitor summary carries the would-have-blocked counts, sample events, the
/// false-positive review path, the 48-hour readiness hint and the typed confirmation.
pub fn monitor_findings(text: &str, screens: &BTreeSet<String>) -> Vec<Finding> {
    let mut out = Vec::new();
    let Some((header, rows)) = section_table(text, "Monitor-to-block decision") else {
        return vec![at(
            ONBOARDING,
            "no `## Monitor-to-block decision` table (T-0026 step 6)",
        )];
    };
    for required in ["Item", "What the screen shows", "Rule"] {
        if column(&header, required).is_none() {
            out.push(at(
                ONBOARDING,
                format!("the monitor summary has no `{required}` column (T-0026 step 6)"),
            ));
        }
    }
    let required_items = [
        "would-have-blocked",
        "sample events",
        "false-positive",
        "48-hour",
        "typed confirmation",
    ];
    let mut found = BTreeSet::new();
    for (line, row) in &rows {
        let item = column(&header, "Item")
            .and_then(|index| row.get(index))
            .map_or("", String::as_str)
            .trim()
            .to_lowercase();
        if let Some(expected) = required_items
            .iter()
            .find(|expected| item.contains(**expected))
        {
            found.insert(*expected);
        }
        for required in ["What the screen shows", "Rule"] {
            let empty = column(&header, required)
                .and_then(|index| row.get(index))
                .is_none_or(|value| value.trim().is_empty());
            if empty {
                out.push(at(
                    format!("{ONBOARDING}:{line}"),
                    format!(
                        "the monitor summary item has an empty `{required}` cell (T-0026 step 6)"
                    ),
                ));
            }
        }
        let screen_cell = column(&header, "What the screen shows")
            .and_then(|index| row.get(index))
            .map_or("", String::as_str);
        for token in screen_tokens(screen_cell) {
            if !screens.contains(&token) {
                out.push(at(
                    format!("{ONBOARDING}:{line}"),
                    format!("the monitor summary names `{token}`, which is not a B12.1 screen"),
                ));
            }
        }
    }
    for expected in required_items {
        if !found.contains(expected) {
            out.push(at(
                ONBOARDING,
                format!("the monitor summary is missing the `{expected}` item (T-0026 step 6)"),
            ));
        }
    }
    let joined = section_text(text, "Monitor-to-block decision");
    let lower = joined.to_lowercase();
    if !lower.contains("48 hours") {
        out.push(at(
            ONBOARDING,
            "the monitor summary must state the 48-hour readiness hint (T-0026 step 6, J-16)",
        ));
    }
    if !lower.contains("type the domain name") {
        out.push(at(
            ONBOARDING,
            "the monitor summary must require typing the domain name before block mode (T-0026 step 6, R-28)",
        ));
    }
    let tokens = screen_tokens(&joined);
    for required in ["S-054", "S-055", "S-065"] {
        if !tokens.iter().any(|token| token == required) || !screens.contains(required) {
            out.push(at(
                ONBOARDING,
                format!(
                    "the monitor summary must name the B12.1 screen {required} (T-0026 step 6)"
                ),
            ));
        }
    }
    if !tokens
        .iter()
        .any(|token| token == "S-064" || token == "S-069")
    {
        out.push(at(
            ONBOARDING,
            "the monitor summary must name the false-positive review screen S-064 or S-069 (T-0026 step 6)",
        ));
    }
    out
}

/// T-0026 step 7: the measures use local counters and existing audit or metric ids only, and name no
/// third-party analytics.
pub fn measure_findings(text: &str, spec: &str) -> Vec<Finding> {
    let mut out = Vec::new();
    let Some((header, rows)) = section_table(text, "Measures") else {
        return vec![at(ONBOARDING, "no `## Measures` table (T-0026 step 7)")];
    };
    for required in ["Measure", "Counter or event", "Source", "Privacy"] {
        if column(&header, required).is_none() {
            out.push(at(
                ONBOARDING,
                format!("the measures table has no `{required}` column (T-0026 step 7)"),
            ));
        }
    }
    if rows.len() < 5 {
        out.push(at(
            ONBOARDING,
            format!(
                "the measures table has {} rows; T-0026 step 7 needs at least five (success and drop-off)",
                rows.len()
            ),
        ));
    }
    let audits = super::audit_ids(spec);
    let b9 = super::spec_section(spec, "B9.")
        .iter()
        .map(|(_, line)| *line)
        .collect::<Vec<_>>()
        .join("\n");
    let metrics: BTreeSet<String> = ids_with_prefix(&b9, "MET-").into_iter().collect();
    if audits.is_empty() {
        out.push(at(
            "docs/SPEC.md",
            "the B8 audit event table has no rows, so the onboarding measures cannot be checked",
        ));
    }
    if metrics.is_empty() {
        out.push(at(
            "docs/SPEC.md",
            "the B9 metrics catalog has no rows, so the onboarding measures cannot be checked",
        ));
    }
    for (line, row) in &rows {
        let counter = column(&header, "Counter or event")
            .and_then(|index| row.get(index))
            .map_or("", String::as_str);
        let mut tokens = ids_with_prefix(counter, "onboarding.");
        tokens.extend(ids_with_prefix(counter, "AUD-"));
        tokens.extend(ids_with_prefix(counter, "MET-"));
        if tokens.is_empty() {
            out.push(at(
                format!("{ONBOARDING}:{line}"),
                "the measure names no local counter, audit event or metric id (T-0026 step 7)",
            ));
        }
        for token in &tokens {
            if token.starts_with("AUD-") && !audits.contains(token) {
                out.push(at(
                    format!("{ONBOARDING}:{line}"),
                    format!("`{token}` is not a B8 audit event (T-0026 step 7)"),
                ));
            }
            if token.starts_with("MET-") && !metrics.contains(token) {
                out.push(at(
                    format!("{ONBOARDING}:{line}"),
                    format!("`{token}` is not a B9 metric (T-0026 step 7)"),
                ));
            }
            if token.starts_with("onboarding.") && !well_formed_counter(token) {
                out.push(at(
                    format!("{ONBOARDING}:{line}"),
                    format!("the local counter `{token}` is not a well-formed counter name (T-0026 step 7)"),
                ));
            }
        }
        let source = column(&header, "Source")
            .and_then(|index| row.get(index))
            .map_or("", String::as_str);
        let source_lower = source.to_lowercase();
        let real_source = TABLES.iter().any(|table| has_token(source, table))
            || source_lower.contains("counter")
            || source_lower.contains("b9");
        if !real_source {
            out.push(at(
                format!("{ONBOARDING}:{line}"),
                "the measure source must name a real table, the local counter or B9 (T-0026 step 7)",
            ));
        }
        let privacy = column(&header, "Privacy")
            .and_then(|index| row.get(index))
            .map_or("", String::as_str);
        if privacy.trim().is_empty() {
            out.push(at(
                format!("{ONBOARDING}:{line}"),
                "the measure has no privacy note (T-0026 step 7, R-25)",
            ));
        }
    }
    let lower = section_text(text, "Measures").to_lowercase();
    if !lower.contains("local") || !lower.contains("no third-party analytics") {
        out.push(at(
            ONBOARDING,
            "the measures section must say that it uses local counters only and no third-party analytics (T-0026 step 7)",
        ));
    }
    let whole = text.to_lowercase();
    for name in THIRD_PARTY {
        if whole.contains(name) {
            out.push(at(
                ONBOARDING,
                "the onboarding document names a third-party analytics product; the measures use local counters only (T-0026 step 7, UXD-003)",
            ));
        }
    }
    out
}

/// T-0026 step 8: the four activation emails have a subject and a structure, and their key stems are
/// well formed and absent from B13.
pub fn email_findings(text: &str, b13: &[(String, String)]) -> Vec<Finding> {
    let mut out = Vec::new();
    let Some((header, rows)) = section_table(text, "Activation emails") else {
        return vec![at(
            ONBOARDING,
            "no `## Activation emails` table (T-0026 step 8)",
        )];
    };
    for required in ["Email", "Subject", "Structure", "i18n key stems"] {
        if column(&header, required).is_none() {
            out.push(at(
                ONBOARDING,
                format!("the activation-email table has no `{required}` column (T-0026 step 8)"),
            ));
        }
    }
    if rows.len() != EMAILS.len() {
        out.push(at(
            ONBOARDING,
            format!(
                "the activation-email table has {} rows but T-0026 step 8 names {} emails",
                rows.len(),
                EMAILS.len()
            ),
        ));
    }
    let b13_keys: BTreeSet<&str> = b13.iter().map(|(key, _)| key.as_str()).collect();
    let mut seen_keys = BTreeSet::new();
    for email in EMAILS {
        let Some((_, row)) = rows.iter().find(|(_, row)| {
            column(&header, "Email")
                .and_then(|index| row.get(index))
                .is_some_and(|cell| cell.trim().eq_ignore_ascii_case(email))
        }) else {
            out.push(at(
                ONBOARDING,
                format!("the activation email `{email}` is missing (T-0026 step 8)"),
            ));
            continue;
        };
        let subject = column(&header, "Subject")
            .and_then(|index| row.get(index))
            .map_or("", String::as_str);
        if subject.trim().is_empty() {
            out.push(at(
                ONBOARDING,
                format!("the activation email `{email}` has no subject (T-0026 step 8)"),
            ));
        }
        let structure = column(&header, "Structure")
            .and_then(|index| row.get(index))
            .map_or("", String::as_str);
        if structure.trim().is_empty() {
            out.push(at(
                ONBOARDING,
                format!("the activation email `{email}` has no content structure (T-0026 step 8)"),
            ));
        }
        let key_cell = column(&header, "i18n key stems")
            .and_then(|index| row.get(index))
            .map_or("", String::as_str);
        let keys = backticked(key_cell);
        if keys.len() < 2 {
            out.push(at(
                ONBOARDING,
                format!("the activation email `{email}` needs at least two i18n key stems (T-0026 step 8)"),
            ));
        }
        if !keys.iter().any(|key| key.ends_with("-subject")) {
            out.push(at(
                ONBOARDING,
                format!("the activation email `{email}` needs a subject key stem (T-0026 step 8)"),
            ));
        }
        for key in keys {
            if !well_formed_key(&key) {
                out.push(at(
                    ONBOARDING,
                    format!("the activation email key `{key}` is not a well-formed semantic key (T-0019)"),
                ));
            }
            if b13_keys.contains(key.as_str()) {
                out.push(at(
                    ONBOARDING,
                    format!("the activation email key `{key}` collides with a B13 key stem (T-0026 step 8)"),
                ));
            }
            if !seen_keys.insert(key.clone()) {
                out.push(at(
                    ONBOARDING,
                    format!(
                        "the activation email key `{key}` is used more than once (T-0026 step 8)"
                    ),
                ));
            }
        }
    }
    out
}

/// The claims policy of section 4 on the two documents: no forbidden claims phrase.
pub fn claim_findings(text: &str) -> Vec<Finding> {
    let lower = text.to_lowercase();
    let mut out = Vec::new();
    for phrase in FORBIDDEN_CLAIMS {
        if lower.contains(phrase) {
            out.push(at(
                "docs/UX",
                "the document contains a forbidden claims phrase of the claims policy (section 4); rewrite the sentence (claims-lint is authoritative)",
            ));
        }
    }
    out
}

/// A1 and A2: the six categories with whole-number weights sum to 100, and the catalog rows of each
/// category sum to that category weight.
pub fn category_findings(text: &str) -> Vec<Finding> {
    let mut out = Vec::new();
    let Some((header, rows)) = section_table(text, "Categories") else {
        return vec![at(
            READINESS_MODEL,
            "no `## Categories` table (T-0026 step 2, B12.2)",
        )];
    };
    for required in ["Category", "Weight", "What the checks cover"] {
        if column(&header, required).is_none() {
            out.push(at(
                READINESS_MODEL,
                format!("the category table has no `{required}` column (T-0026 step 2)"),
            ));
        }
    }
    let mut declared: BTreeMap<String, u32> = BTreeMap::new();
    for (line, row) in &rows {
        let category = column(&header, "Category")
            .and_then(|index| row.get(index))
            .map_or("", String::as_str)
            .trim()
            .to_owned();
        let weight = row_weight(&header, row);
        let Some(weight) = weight else {
            out.push(at(
                format!("{READINESS_MODEL}:{line}"),
                format!("the category `{category}` has no whole-number weight (T-0026 step 2, A2)"),
            ));
            continue;
        };
        if !CATEGORIES
            .iter()
            .any(|(expected, _)| expected.eq_ignore_ascii_case(&category))
        {
            out.push(at(
                format!("{READINESS_MODEL}:{line}"),
                format!("`{category}` is not one of the six B12.2 categories (T-0026 step 2)"),
            ));
        }
        if declared.insert(category.to_lowercase(), weight).is_some() {
            out.push(at(
                format!("{READINESS_MODEL}:{line}"),
                "a category appears more than once (T-0026 step 2)",
            ));
        }
        let cover = column(&header, "What the checks cover")
            .and_then(|index| row.get(index))
            .map_or("", String::as_str);
        if cover.trim().is_empty() {
            out.push(at(
                format!("{READINESS_MODEL}:{line}"),
                "the category has no coverage description (T-0026 step 2)",
            ));
        }
    }
    if rows.len() != CATEGORIES.len() {
        out.push(at(
            READINESS_MODEL,
            format!(
                "the category table has {} rows but B12.2 names {} categories",
                rows.len(),
                CATEGORIES.len()
            ),
        ));
    }
    for (category, expected) in CATEGORIES {
        match declared.get(&category.to_lowercase()) {
            None => out.push(at(
                READINESS_MODEL,
                format!("the B12.2 category `{category}` is missing (T-0026 step 2)"),
            )),
            Some(weight) if *weight != u32::from(expected) => out.push(at(
                READINESS_MODEL,
                format!(
                    "the category `{category}` has weight {weight} but B12.2 gives {expected} (T-0026 step 2, A2)"
                ),
            )),
            Some(_) => {}
        }
    }
    let declared_total: u32 = declared.values().sum();
    if !declared.is_empty() && declared_total != 100 {
        out.push(at(
            READINESS_MODEL,
            format!("the category weights sum to {declared_total}, not 100 (T-0026 step 2, A2)"),
        ));
    }
    let mut catalog_sums: BTreeMap<String, u32> = BTreeMap::new();
    if let Some((catalog_header, catalog_rows)) = section_table(text, "Check catalog") {
        for row in catalog_rows.iter().map(|(_, row)| row) {
            let category = column(&catalog_header, "Category")
                .and_then(|index| row.get(index))
                .map_or("", String::as_str)
                .to_lowercase();
            let weight = row_weight(&catalog_header, row).unwrap_or(0);
            *catalog_sums.entry(category).or_default() += weight;
        }
    }
    for (category, expected) in CATEGORIES {
        let catalog_total = catalog_sums
            .get(&category.to_lowercase())
            .copied()
            .unwrap_or(0);
        if catalog_total != u32::from(expected) {
            out.push(at(
                READINESS_MODEL,
                format!(
                    "the `{category}` checks sum to {catalog_total} in the catalog but the category weight is {expected} (T-0026 step 2, A2)"
                ),
            ));
        }
    }
    out
}

/// A1 and T-0026 step 2: every check of the catalog has an integer weight, a real data source, a
/// refresh interval and a real B12.1 screen as the remediation link.
pub fn catalog_findings(text: &str, screens: &BTreeSet<String>) -> Vec<Finding> {
    let mut out = Vec::new();
    let Some((header, rows)) = section_table(text, "Check catalog") else {
        return vec![at(
            READINESS_MODEL,
            "no `## Check catalog` table (T-0026 step 2, A1)",
        )];
    };
    for required in [
        "Check",
        "Category",
        "Weight",
        "Data source",
        "Refresh interval",
        "Remediation link",
    ] {
        if column(&header, required).is_none() {
            out.push(at(
                READINESS_MODEL,
                format!("the readiness catalog has no `{required}` column (T-0026 step 2, A1)"),
            ));
        }
    }
    if rows.len() != CHECKS.len() {
        out.push(at(
            READINESS_MODEL,
            format!(
                "the readiness catalog has {} rows but T-0026 step 2 names {} checks (A1)",
                rows.len(),
                CHECKS.len()
            ),
        ));
    }
    for check in &CHECKS {
        let matching: Vec<&(usize, Vec<String>)> = rows
            .iter()
            .filter(|(_, row)| row.first().is_some_and(|cell| has_token(cell, check.id)))
            .collect();
        if matching.len() != 1 {
            out.push(at(
                READINESS_MODEL,
                format!(
                    "the catalog must list the check `{}` exactly once, not {} times (T-0026 step 2, A1)",
                    check.id,
                    matching.len()
                ),
            ));
            continue;
        }
        let Some((line, row)) = matching.first() else {
            continue;
        };
        let line = *line;
        let check_cell = row.first().map_or("", String::as_str);
        if !check_cell
            .to_lowercase()
            .contains(&check.name.to_lowercase())
        {
            out.push(at(
                format!("{READINESS_MODEL}:{line}"),
                format!(
                    "the check `{}` must carry the name `{}` (T-0026 step 2)",
                    check.id, check.name
                ),
            ));
        }
        let category = column(&header, "Category")
            .and_then(|index| row.get(index))
            .map_or("", String::as_str);
        if !category.eq_ignore_ascii_case(check.category) {
            out.push(at(
                format!("{READINESS_MODEL}:{line}"),
                format!(
                    "the check `{}` is in the category `{category}` but belongs to `{}` (T-0026 step 2)",
                    check.id, check.category
                ),
            ));
        }
        let weight = row_weight(&header, row);
        if weight != Some(u32::from(check.weight)) {
            out.push(at(
                format!("{READINESS_MODEL}:{line}"),
                format!(
                    "the check `{}` has weight {:?} but the model gives {} (T-0026 step 2, A1)",
                    check.id, weight, check.weight
                ),
            ));
        }
        let source = column(&header, "Data source")
            .and_then(|index| row.get(index))
            .map_or("", String::as_str);
        let source_lower = source.to_lowercase();
        let real_source = TABLES.iter().any(|table| has_token(source, table));
        if !real_source || source_lower.contains("made up") || source_lower.contains("placeholder")
        {
            out.push(at(
                format!("{READINESS_MODEL}:{line}"),
                format!(
                    "the check `{}` has no real data source from the B5 data model (T-0026 step 2, A1)",
                    check.id
                ),
            ));
        }
        let refresh = column(&header, "Refresh interval")
            .and_then(|index| row.get(index))
            .map_or("", String::as_str);
        if refresh.trim().is_empty() || !duration_like(refresh) {
            out.push(at(
                format!("{READINESS_MODEL}:{line}"),
                format!(
                    "the check `{}` has no numeric or event-driven refresh interval (T-0026 step 2, A1)",
                    check.id
                ),
            ));
        }
        let remediation = column(&header, "Remediation link")
            .and_then(|index| row.get(index))
            .map_or("", String::as_str);
        let tokens = screen_tokens(remediation);
        if tokens.is_empty() {
            out.push(at(
                format!("{READINESS_MODEL}:{line}"),
                format!(
                    "the check `{}` has no B12.1 remediation link (T-0026 step 2, A1)",
                    check.id
                ),
            ));
        }
        for token in &tokens {
            if !screens.contains(token) {
                out.push(at(
                    format!("{READINESS_MODEL}:{line}"),
                    format!(
                        "the check `{}` has the remediation link `{token}`, which is not a B12.1 screen (T-0026 step 2, A1)",
                        check.id
                    ),
                ));
            }
        }
    }
    for (line, row) in &rows {
        let check_cell = row.first().map_or("", String::as_str);
        if check_id_in(check_cell).is_none() {
            out.push(at(
                format!("{READINESS_MODEL}:{line}"),
                format!(
                    "the catalog row `{check_cell}` names no known readiness check (T-0026 step 2)"
                ),
            ));
        }
    }
    out
}

/// A2: the 23 catalog weights sum to 100.
pub fn weight_findings(text: &str) -> Vec<Finding> {
    let mut out = Vec::new();
    let Some((header, rows)) = section_table(text, "Check catalog") else {
        return vec![at(
            READINESS_MODEL,
            "no `## Check catalog` table, so the weights cannot be summed (T-0026 A2)",
        )];
    };
    let mut total = 0_u32;
    let mut counted = 0_usize;
    for (line, row) in &rows {
        match row_weight(&header, row) {
            Some(weight) => {
                total += weight;
                counted += 1;
            }
            None => out.push(at(
                format!("{READINESS_MODEL}:{line}"),
                "a catalog row has no whole-number weight (T-0026 A2)",
            )),
        }
    }
    if counted != CHECKS.len() {
        out.push(at(
            READINESS_MODEL,
            format!(
                "only {counted} of {} catalog rows have a weight (T-0026 A2)",
                CHECKS.len()
            ),
        ));
    }
    if total != 100 {
        out.push(at(
            READINESS_MODEL,
            format!("the catalog weights sum to {total}, not 100 (T-0026 A2)"),
        ));
    }
    out
}

/// A2: the unknown rule says unknown never counts as a pass, renders `Unknown ({reason})` from B13
/// and shows the unknown count honestly.
pub fn unknown_findings(text: &str, b13: &[(String, String)]) -> Vec<Finding> {
    let mut out = Vec::new();
    let Some(body) = section_body(text, "Unknown handling") else {
        return vec![at(
            READINESS_MODEL,
            "no `## Unknown handling` section (T-0026 step 2, A2)",
        )];
    };
    let joined = body
        .iter()
        .map(|(_, line)| line.as_str())
        .collect::<Vec<_>>()
        .join("\n");
    let lower = joined.to_lowercase();
    if !lower.contains("unknown") || !lower.contains("never counts as a pass") {
        out.push(at(
            READINESS_MODEL,
            "the unknown rule must say that an Unknown check never counts as a pass (T-0026 A2)",
        ));
    }
    let unknown_text = b13_value(b13, "unknown-value").unwrap_or("Unknown ({reason})");
    if !joined.contains(unknown_text) {
        out.push(at(
            READINESS_MODEL,
            format!(
                "the unknown rule must render the B13 `unknown-value` text `{unknown_text}` (T-0026 step 2)"
            ),
        ));
    }
    if !lower.contains("count of unknown checks") {
        out.push(at(
            READINESS_MODEL,
            "the unknown rule must say that the score ring shows the count of Unknown checks honestly (T-0026 step 2)",
        ));
    }
    out
}

/// A5: the footnote equals the B13 `readiness-footnote` text as a whole string, case-sensitive, and
/// the document says where it is placed.
pub fn footnote_findings(
    text: &str,
    b13: &[(String, String)],
    screens: &BTreeSet<String>,
) -> Vec<Finding> {
    let mut out = Vec::new();
    let Some(footnote) = b13_value(b13, "readiness-footnote") else {
        return vec![at(
            "docs/SPEC.md",
            "B13 has no `readiness-footnote` row, so the footnote cannot be compared (T-0026 A5)",
        )];
    };
    let Some(body) = section_body(text, "Honesty footnote") else {
        return vec![at(
            READINESS_MODEL,
            "no `## Honesty footnote` section (T-0026 step 2, A5)",
        )];
    };
    let quotes: Vec<&str> = body
        .iter()
        .filter_map(|(_, line)| line.trim().strip_prefix('>'))
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .collect();
    match quotes.as_slice() {
        [] => out.push(at(
            READINESS_MODEL,
            "the honesty footnote section has no blockquote with the exact text (T-0026 A5)",
        )),
        [quoted] if *quoted != footnote => out.push(at(
            READINESS_MODEL,
            format!(
                "the footnote must equal the B13 `readiness-footnote` text `{footnote}` as a whole string, but it says `{quoted}` (T-0026 A5)"
            ),
        )),
        [_] => {}
        _ => out.push(at(
            READINESS_MODEL,
            "the honesty footnote blockquote must contain exactly the one B13 string, not several lines (T-0026 A5)",
        )),
    }
    let joined = body
        .iter()
        .map(|(_, line)| line.as_str())
        .collect::<Vec<_>>()
        .join("\n");
    let tokens = screen_tokens(&joined);
    if !tokens.iter().any(|token| token == "S-044") || !screens.contains("S-044") {
        out.push(at(
            READINESS_MODEL,
            "the footnote section must place the text on the B12.1 screen S-044 (T-0026 step 2)",
        ));
    }
    if !has_token(&joined, "ReadinessRing") {
        out.push(at(
            READINESS_MODEL,
            "the footnote section must name the ReadinessRing component that carries the footnote slot (T-0026 step 2)",
        ));
    }
    if !joined.to_lowercase().contains("below") {
        out.push(at(
            READINESS_MODEL,
            "the footnote section must say that the text is shown below the readiness ring (T-0026 step 2)",
        ));
    }
    out
}

/// T-0026 "Tests": the worked scoring example of the readiness model evaluates to its stated scores
/// with the pure scoring function.
pub fn scoring_findings(text: &str) -> Vec<Finding> {
    let mut out = Vec::new();
    let weights = catalog_weights(text);
    if weights.is_empty() {
        return vec![at(
            READINESS_MODEL,
            "no readable check catalog, so the scoring example cannot be evaluated (T-0026 Tests)",
        )];
    }
    let rules = section_text(text, "Scoring rules").to_lowercase();
    for required in [
        "partial",
        "ratio",
        "rounded down",
        "pass",
        "fail",
        "unknown",
    ] {
        if !rules.contains(required) {
            out.push(at(
                READINESS_MODEL,
                format!("the scoring rules do not state the `{required}` rule (T-0026 step 2)"),
            ));
        }
    }
    let Some((header, rows)) = section_table(text, "Worked scoring example") else {
        return vec![at(
            READINESS_MODEL,
            "no `## Worked scoring example` table (T-0026 Tests)",
        )];
    };
    for required in [
        "Case",
        "Status overrides (all other checks Pass)",
        "Expected score",
        "Unknown count",
    ] {
        if column(&header, required).is_none() {
            out.push(at(
                READINESS_MODEL,
                format!("the scoring example has no `{required}` column (T-0026 Tests)"),
            ));
        }
    }
    if rows.len() < 3 {
        out.push(at(
            READINESS_MODEL,
            "the scoring example has fewer than three cases (T-0026 Tests)",
        ));
    }
    for (line, row) in &rows {
        let overrides = column(&header, "Status overrides (all other checks Pass)")
            .and_then(|index| row.get(index))
            .map_or("", String::as_str);
        let expected_score = column(&header, "Expected score")
            .and_then(|index| row.get(index))
            .and_then(|value| value.trim().parse::<u32>().ok());
        let expected_unknown = column(&header, "Unknown count")
            .and_then(|index| row.get(index))
            .and_then(|value| value.trim().parse::<usize>().ok());
        let (Some(expected_score), Some(expected_unknown)) = (expected_score, expected_unknown)
        else {
            out.push(at(
                format!("{READINESS_MODEL}:{line}"),
                "a scoring example row has no numeric expected score or unknown count (T-0026 Tests)",
            ));
            continue;
        };
        let mut partial = BTreeMap::new();
        let state = example_state(overrides, &mut partial);
        let (score, unknown) = score(&weights, &state, &partial);
        if score != expected_score {
            out.push(at(
                format!("{READINESS_MODEL}:{line}"),
                format!(
                    "the scoring example `{overrides}` expects the score {expected_score} but the scoring function gives {score} (T-0026 Tests)"
                ),
            ));
        }
        if unknown != expected_unknown {
            out.push(at(
                format!("{READINESS_MODEL}:{line}"),
                format!(
                    "the scoring example `{overrides}` expects {expected_unknown} Unknown checks but the scoring function counts {unknown} (T-0026 Tests)"
                ),
            ));
        }
    }
    out
}

#[cfg(test)]
pub(crate) mod fixtures {
    //! Fixture tree for the T-0026 checks: the two documents and the fixture-spec rows.
    //!
    //! The fixture documents are structurally complete and use only screens of the fixture B12.1
    //! table. They are generated here so the Lead can add them to the shared fixture tree without
    //! editing the tests: `for (path, text) in fixtures::documents() { repo.put(&path, &text); }`.
    //!
    //! The shared fixture B13 table has only `tagline`, `signup-title` and `success-saved`, so the
    //! Lead must add the `readiness-footnote` row (`| readiness-footnote | Measures configuration
    //! completeness, not security. |`) before the fixture tree can pass [`super::footnote_findings`].

    use super::{CATEGORIES, CHECKS, ONBOARDING, ONBOARDING_FTL, READINESS_MODEL, STAGES};

    /// The B12.2 S-044 check phrases, the bullet category each one sits in, and the exactly one model
    /// check it maps to. The phrases are copied from the six bullet lists of the master specification
    /// (`#### S-044 Protection readiness`); the fixture documents and the fixture master are generated
    /// from this list so the module tests exercise the same shape as the shipped text.
    const B122_MAPPING: [(&str, &str, &str); 23] = [
        (
            "traffic flows through HDD (last proxied request within 24 h)",
            "Traffic",
            "RD-TRAFFIC",
        ),
        ("delegation or CNAME verified", "Traffic", "RD-DELEGATION"),
        (
            "no grey web records that expose the same hostnames",
            "Traffic",
            "RD-GREY",
        ),
        (
            "valid certificate with more than one quarter lifetime remaining",
            "Encryption",
            "RD-CERT",
        ),
        ("HTTPS redirect on", "Encryption", "RD-HTTPS"),
        (
            "origin verification mode strict",
            "Encryption",
            "RD-ORIGIN-VERIFY",
        ),
        (
            "HSTS enabled (partial credit by max-age)",
            "Encryption",
            "RD-HSTS",
        ),
        ("lockdown applied", "Origin", "RD-LOCKDOWN"),
        ("secret header verified", "Origin", "RD-SECRET"),
        (
            "origin IP not found in own DNS/headers/mail",
            "Origin",
            "RD-ORIGIN-EXPOSURE",
        ),
        ("origin health check passing", "Origin", "RD-ORIGIN-HEALTH"),
        (
            "WAF in block mode (monitor gives partial)",
            "Detection",
            "RD-WAF-MODE",
        ),
        ("SQLi shield enabled", "Detection", "RD-SHIELD"),
        ("all hard categories on", "Detection", "RD-HARD-CATEGORIES"),
        ("auth endpoints declared", "Detection", "RD-AUTH-ENDPOINTS"),
        ("outbound filter on", "Detection", "RD-OUTBOUND"),
        (
            "rate limits on auth endpoints",
            "Abuse controls",
            "RD-RATE-LIMITS",
        ),
        ("challenge configured", "Abuse controls", "RD-CHALLENGE"),
        ("scanner policy on", "Abuse controls", "RD-SCANNER"),
        ("alert channel tested", "Operations", "RD-ALERT-TESTED"),
        ("MFA required for org", "Operations", "RD-MFA"),
        ("DNS backup exported", "Operations", "RD-DNS-BACKUP"),
        ("appeals enabled", "Operations", "RD-APPEALS"),
    ];

    /// The screen the fixture uses for a check. The shared fixture B12.1 table lacks S-053 and S-097,
    /// so the fixture uses S-052 (origin settings, which has a test) and S-054 (security overview).
    fn fixture_screen(id: &str) -> &'static str {
        match id {
            "RD-ORIGIN-HEALTH" => "S-052",
            "RD-OUTBOUND" => "S-054",
            _ => CHECKS
                .iter()
                .find(|check| check.id == id)
                .map_or("S-044", |check| check.remediation),
        }
    }

    /// The fixture onboarding copy file (F-28). It defines every empty-state key the fixture
    /// onboarding document names, so the fixture tree exercises the definition rule and the style
    /// rules with a passing fixture. The fixture specification does not carry the B13
    /// `empty-events`/`empty-domains` rows, so the fixture puts every empty-state key in this file.
    pub(crate) fn onboarding_ftl() -> String {
        String::from(
            "# Onboarding copy fixture (F-28). Keys are lowercase semantic words joined by hyphens.\n\
             empty-onboarding-profile = The fixture profile is empty. Fill it in to continue.\n\
             empty-domains = The fixture has no website yet. Add one to start.\n\
             empty-events = The fixture has no events. Traffic appears here after the first request.\n\
             empty-readiness = The fixture has no check data. Add a website so the checks can run.\n\
             empty-alerts = The fixture has no alert rule. Create one to receive a notice.\n\
             empty-team = The fixture has no invitation. Invite a teammate or skip this step.\n\
             empty-reports = The fixture has no report. Create the first one when you need a summary.\n\
             empty-privacy = The fixture has no open request. Request an export to receive your data.\n",
        )
    }

    /// The fixture documents and the fixture copy file, as `(repository-relative path, text)`.
    pub(crate) fn documents() -> Vec<(String, String)> {
        vec![
            (ONBOARDING.to_owned(), onboarding()),
            (READINESS_MODEL.to_owned(), readiness()),
            (ONBOARDING_FTL.to_owned(), onboarding_ftl()),
        ]
    }

    /// Extra fixture-spec rows this module needs beyond the shared fixture tree.
    ///
    /// The shared fixture specification has no B9 metrics table, so this returns a complete B9
    /// section for the Lead to append to the fixture master (the module reads the metric ids of the
    /// onboarding measures from it). The shared B12.1 table already names every screen the fixture
    /// documents use. The Lead must also add the `readiness-footnote` row to the fixture B13 table.
    pub(crate) fn spec_section() -> String {
        let mut s = String::from(
            "\n## B9. Metrics catalog (fixture)\n\n\
             | Metric | Type | Labels | Meaning |\n| --- | --- | --- | --- |\n\
             | MET-hdd_mail_sent_total / failed_total / bounced_total | counter | template | Mail sent |\n\
             \n### B12.2 Detailed specifications of critical screens (fixture)\n\n\
             #### S-044 Protection readiness\n\n\
             Score 0 to 100 with ring and the footnote.\n",
        );
        let mut index = 0_usize;
        for (category, weight) in CATEGORIES {
            let mut phrases: Vec<&str> = Vec::new();
            while let Some((phrase, bullet_category, _)) = B122_MAPPING.get(index) {
                if *bullet_category != category {
                    break;
                }
                phrases.push(*phrase);
                index += 1;
            }
            s.push_str(&format!(
                "- **{category}** ({weight}): {}.\n",
                phrases.join(", ")
            ));
        }
        s
    }

    /// The fixture onboarding document.
    pub(crate) fn onboarding() -> String {
        let mut s = String::from(
            "# Onboarding and activation (fixture)\n\n\
             Status: fixture for the T-0026 checks.\n\n\
             ## Stage map\n\n\
             | Stage | Screen | User goal | Why we ask | Exit criterion | Drop-off risk |\n\
             | --- | --- | --- | --- | --- | --- |\n",
        );
        for (stage, screen) in STAGES {
            s.push_str(&format!(
                "| {stage} | {screen} | The fixture states the goal. | The fixture states the reason. | The fixture states the exit. | The fixture states the risk. |\n"
            ));
        }
        s.push_str(
            "\n## Checklist structure\n\n\
             | Property | Rule |\n| --- | --- |\n\
             | Derived state | An item is complete only when the underlying data says so. |\n\
             | Persistence | The checklist stays on S-040 until every item is done or the owner dismisses it. |\n\
             | Resume | Reopening S-035 returns to the first unfinished item. |\n\
             | Ordering | Items follow the stage order; a blocked item moves to the end. |\n\
             | Optional items | The team invitation is optional and never blocks activation. |\n\
             | Dismissal and return | A dismissal hides the checklist for 14 days; critical items stay in the attention list. |\n\
             | No dead ends | Every item has a fix link to S-040 and a reason when it cannot proceed. |\n\
             \nThe checklist never blocks product use.\n",
        );
        s.push_str(
            "\n## Next best action\n\n\
             The list is ordered and the first match wins. Priorities are unique and increase by one. The card appears on S-040 and S-043. \
             The rule with the condition `any check is not Pass` is the generic rule; the unconditional last rule is only reached when every check passes. \
             For a non-owner role the card names who can perform the step: an owner or an admin enrols MFA for the organisation.\n\n\
             1. rule 1: if RD-DELEGATION is Fail then Finish the DNS connection at S-047.\n\
             2. rule 2: if RD-DELEGATION is Unknown then Check DNS delegation at S-099.\n\
             3. rule 3: if RD-TRAFFIC is Fail then Send traffic through HDD at S-043.\n\
             4. rule 4: if RD-ORIGIN-HEALTH is Fail then Fix the origin health at S-052.\n\
             5. rule 5: if RD-ORIGIN-HEALTH is Unknown then Run an origin test at S-052.\n\
             6. rule 6: if RD-LOCKDOWN is Fail then Apply the origin lockdown at S-098.\n\
             7. rule 7: if RD-CERT is Fail then Fix the certificate at S-051.\n\
             8. rule 8: if RD-WAF-MODE is Partial then Review monitor results at S-054.\n\
             9. rule 9: if RD-WAF-MODE is Fail then Choose a protection mode at S-055.\n\
             10. rule 10: if RD-ALERT-TESTED is Fail then Test the alert channel at S-076.\n\
             11. rule 11: if RD-MFA is Fail then Ask an owner or an admin to enrol MFA at S-030.\n\
             12. rule 12: if any check is not Pass then Open the remediation link for the first non-Pass check in catalog order.\n\
             13. rule 13: if always then Nothing to do now.\n\
             \n### Example evaluations\n\n\
             | Inputs | Expected rule | Expected action |\n| --- | --- | --- |\n\
             | RD-DELEGATION=Fail; others=Pass | 1 | Finish the DNS connection at S-047. |\n\
             | RD-DELEGATION=Unknown; others=Pass | 2 | Check DNS delegation at S-099. |\n\
             | RD-TRAFFIC=Fail; others=Pass | 3 | Send traffic through HDD at S-043. |\n\
             | RD-ORIGIN-HEALTH=Fail; others=Pass | 4 | Fix the origin health at S-052. |\n\
             | RD-ORIGIN-HEALTH=Unknown; others=Pass | 5 | Run an origin test at S-052. |\n\
             | RD-LOCKDOWN=Fail; others=Pass | 6 | Apply the origin lockdown at S-098. |\n\
             | RD-CERT=Fail; others=Pass | 7 | Fix the certificate at S-051. |\n\
             | RD-WAF-MODE=Partial; others=Pass | 8 | Review monitor results at S-054. |\n\
             | RD-WAF-MODE=Fail; others=Pass | 9 | Choose a protection mode at S-055. |\n\
             | RD-ALERT-TESTED=Fail; others=Pass | 10 | Test the alert channel at S-076. |\n\
             | RD-MFA=Fail; others=Pass | 11 | Ask an owner or an admin to enrol MFA at S-030. |\n\
             | RD-DELEGATION=Fail; RD-MFA=Fail; others=Pass | 1 | Finish the DNS connection at S-047. |\n\
             | RD-ORIGIN-HEALTH=Unknown; RD-LOCKDOWN=Fail; others=Pass | 5 | Run an origin test at S-052. |\n\
             | RD-WAF-MODE=Partial; RD-CERT=Fail; others=Pass | 7 | Fix the certificate at S-051. |\n\
             | RD-HTTPS=Fail; RD-HSTS=Fail; others=Pass | 12 | Open the remediation link for RD-HTTPS at S-050. |\n\
             | RD-TRAFFIC=Fail; RD-ORIGIN-HEALTH=Unknown; others=Pass | 3 | Send traffic through HDD at S-043. |\n\
             | RD-SHIELD=Unknown; others=Pass | 12 | Open the remediation link for RD-SHIELD at S-057. |\n\
             | RD-GREY=Fail; RD-DNS-BACKUP=Fail; others=Pass | 12 | Open the remediation link for RD-GREY at S-045. |\n\
             | RD-ORIGIN-EXPOSURE=Fail; RD-SCANNER=Partial; others=Pass | 12 | Open the remediation link for RD-ORIGIN-EXPOSURE at S-138. |\n\
             | every check unknown | 2 | Check DNS delegation at S-099. |\n\
             | others=Pass | 13 | Nothing to do now. |\n",
        );
        s.push_str(
            "\n## Nudges and reminders\n\n\
             Quiet hours are 22:00 to 07:00 local time; no email is sent inside them. The opt-out lives in notification preferences on S-086.\n\n\
             | Nudge | Channel | Frequency cap | Opt-out |\n| --- | --- | --- | --- |\n\
             | Unfinished critical stage | in-app card | at most 1 per 72 hours and at most 3 per week | Dismiss the card; turn off onboarding tips on S-086. |\n\
             | Unfinished critical stage | email | at most 1 per 7 days and at most 4 in total | Turn off onboarding reminders on S-086; opt out in notification preferences. |\n\
             | Monitor review reminder | in-app card | at most 1 per 24 hours and at most 2 per week | Dismiss the card for 14 days; opt out on S-086. |\n\
             | Weekly summary | email | 1 per week | Unsubscribe in the footer; opt out on S-086. |\n\
             | Completion thanks | in-app card | 1 per organisation in total | Dismiss the card; no further copy is sent. |\n",
        );
        s.push_str(
            "\n## Empty states\n\n\
             All empty-state keys of this fixture are defined in `i18n/en/onboarding.ftl`; in the shipped deck `empty-events` and `empty-domains` are B13 keys. The new `empty-*` keys are registered with the T-0144 registry and must not be added to the copy deck.\n\n\
             | Screen | Empty state | Copy key | Next action |\n| --- | --- | --- | --- |\n\
             | S-035 | The profile fields are empty; no sample name is shown. | `empty-onboarding-profile` | Fill the profile. |\n\
             | S-040 | No domains and no events; the checklist is the only content. | `empty-domains` | Add a website. |\n\
             | S-041 | The list has no rows and one add action. | `empty-domains` | Add a website. |\n\
             | S-044 | No check data; the ring is replaced by an explanation. | `empty-readiness` | Add a website. |\n\
             | S-054 | No traffic yet; the page says so and links troubleshooting. | `empty-events` | Check DNS propagation. |\n\
             | S-065 | The table has no events and shows the live status. | `empty-events` | Wait for traffic. |\n\
             | S-076 | No alert rule; the page offers a blank template. | `empty-alerts` | Create an alert rule. |\n\
             | S-082 | No invitations; the team step is optional. | `empty-team` | Invite a teammate or skip. |\n\
             | S-073 | No reports; the page offers the first report. | `empty-reports` | Create a report. |\n\
             | S-090 | No export or deletion request; the forms are shown. | `empty-privacy` | Request an export. |\n",
        );
        s.push_str(
            "\n## Monitor-to-block decision\n\n\
             | Item | What the screen shows | Rule |\n| --- | --- | --- |\n\
             | Would-have-blocked count | S-054 shows the count for the window. | The count comes from real events. |\n\
             | Sample events | S-065 and S-066 show examples with redacted payloads. | The examples are real events. |\n\
             | False-positive review | S-064 and S-069 show how a wrong block is undone. | The owner reviews each candidate. |\n\
             | 48-hour readiness hint | S-055 states the 48-hour hint before the switch. | The hint is not a countdown. |\n\
             | Typed confirmation | S-055 asks the owner to type the domain name. | The safe option is the default. |\n\
             \nThe owner needs at least 48 hours of monitor traffic for a useful review. The switch keeps the typed confirmation.\n",
        );
        s.push_str(
            "\n## Measures\n\n\
             Every number below is a local counter or an existing audit event. There is no third-party analytics script and no tracking cookie. Counts below five are hidden.\n\n\
             | Measure | Counter or event | Source | Privacy |\n| --- | --- | --- | --- |\n\
             | Stage completion time | `onboarding.stage_completed` | audit_log and the stage counter | org id and stage only |\n\
             | Stage drop-off | `onboarding.stage_abandoned` | the stage counter | org id and stage only |\n\
             | Time to first protected domain | `AUD-domain.created` and `AUD-domain.activated` | audit_log | timestamps and org id only |\n\
             | Next best action completed | `onboarding.next_action_completed` | the action counter | action id and org id only |\n\
             | Nudge sent and opted out | `onboarding.nudge_sent` and `onboarding.nudge_opt_out` | the nudge counter | kind and org id only |\n\
             | Email delivery | `MET-hdd_mail_sent_total` | B9 metrics | template label only |\n",
        );
        s.push_str(
            "\n## Activation emails\n\n\
             | Email | Subject | Structure | i18n key stems |\n| --- | --- | --- | --- |\n\
             | welcome | Welcome to Hack Dev Defence | Opening, one next step, checklist note, footer. | `email-welcome-subject`, `email-welcome-intro`, `email-welcome-footer` |\n\
             | verify | Confirm your email address | Greeting, confirm button, expiry, resend link. | `email-verify-subject`, `email-verify-button`, `email-verify-resend` |\n\
             | first domain | Add your first website | Why a domain, the next step, one link. | `email-first-domain-subject`, `email-first-domain-action` |\n\
             | weekly summary | Your week in protection | Counts, open items, one action, unsubscribe. | `email-weekly-summary-subject`, `email-weekly-summary-counts`, `email-weekly-summary-footer` |\n",
        );
        s
    }

    /// The fixture readiness model.
    pub(crate) fn readiness() -> String {
        let mut s = String::from(
            "# Protection readiness model (fixture)\n\n\
             Status: fixture for the T-0026 checks.\n\n\
             ## Categories\n\n\
             | Category | Weight | What the checks cover |\n| --- | --- | --- |\n",
        );
        for (category, weight) in CATEGORIES {
            s.push_str(&format!(
                "| {category} | {weight} | The fixture states the coverage. |\n"
            ));
        }
        s.push_str(
            "\n## Check catalog\n\n\
             | Check | Category | Weight | Data source | Refresh interval | Remediation link |\n\
             | --- | --- | --- | --- | --- | --- |\n",
        );
        for check in CHECKS {
            s.push_str(&format!(
                "| {} · {} | {} | {} | {} | {} | {} |\n",
                check.id,
                check.name,
                check.category,
                check.weight,
                check.source,
                check.refresh,
                fixture_screen(check.id)
            ));
        }
        s.push_str(
            "\n## B12.2 mapping\n\n\
             Each phrase of the six B12.2 bullet lists maps to exactly one model check.\n\n\
             | B12.2 check phrase | B12.2 category | Model check |\n| --- | --- | --- |\n",
        );
        for (phrase, category, id) in B122_MAPPING {
            s.push_str(&format!("| {phrase} | {category} | {id} |\n"));
        }
        s.push_str(
            "\n## Scoring rules\n\n\
             A Pass scores 1, a Partial scores its ratio between 0 and 1 (RD-WAF-MODE scores 0.5 when `waf_mode` is `monitor`, a design value confirmed in T-0172), \
             a Fail scores 0 and an Unknown scores 0. The total is the sum of weight times credit, rounded down to a whole number from 0 to 100. Fixing a failed check never lowers the score.\n\
             \n## Unknown handling\n\n\
             An Unknown check never counts as a pass and scores 0. It renders as `Unknown ({reason})` from B13 and the reason is always shown. \
             The score ring shows the count of Unknown checks next to the score, so a low score with many unknowns is read honestly.\n\
             \n## Honesty footnote\n\n\
             The text is copied from B13 `readiness-footnote` and compared as a whole string.\n\
             > Measures configuration completeness, not security.\n\
             \nS-044 shows it directly below the readiness ring; the ReadinessRing component's footnote slot carries the same text.\n\
             \n## Worked scoring example\n\n\
             | Case | Status overrides (all other checks Pass) | Expected score | Unknown count |\n| --- | --- | --- | --- |\n\
             | A | none | 100 | 0 |\n\
             | B | RD-WAF-MODE Fail | 92 | 0 |\n\
             | C | RD-HSTS Partial(0.5) | 98 | 0 |\n\
             | D | RD-LOCKDOWN Unknown; RD-ALERT-TESTED Unknown | 91 | 2 |\n\
             | E | every check Unknown | 0 | 23 |\n\
             | F | RD-WAF-MODE Partial(0.5) | 96 | 0 |\n",
        );
        s
    }

    /// Replace the readiness table of a generated fixture J-25 with the rows of the fixture readiness
    /// model, so the J-25 cross-check rule has a passing fixture (T-0026 step 2). The rest of the
    /// journey document is kept, including its T-0016 sections.
    pub(crate) fn journey_j25(generated: &str) -> String {
        let mut out: Vec<String> = Vec::new();
        let mut in_section = false;
        for line in generated.lines() {
            if line.trim() == "## Readiness score" {
                in_section = true;
                out.push(line.to_owned());
                out.push(String::new());
                out.push(
                    "| Check | Weight | Status values | Why it matters | Fix link |".to_owned(),
                );
                out.push("| --- | --- | --- | --- | --- |".to_owned());
                for check in CHECKS {
                    out.push(format!(
                        "| {} | {} | Pass, Partial, Fail, Unknown | A configuration check the model scores. | {} |",
                        check.name,
                        check.weight,
                        fixture_screen(check.id)
                    ));
                }
                continue;
            }
            if in_section {
                if line.starts_with("## ") {
                    in_section = false;
                    out.push(String::new());
                    out.push(line.to_owned());
                }
                continue;
            }
            out.push(line.to_owned());
        }
        out.join("\n")
    }

    /// The fixture master specification: the B12.1 screens the fixture documents use, the B11.8
    /// component, the B13 rows including `readiness-footnote`, the B9 metrics and the B8 audit events.
    pub(crate) fn spec() -> String {
        let mut s = String::from(
            "### B12.1 Screen table\n\n\
             | ID | Name | Purpose and key content |\n| --- | --- | --- |\n",
        );
        for (id, name) in [
            ("S-020", "Sign up"),
            ("S-030", "MFA enrolment"),
            ("S-035", "Onboarding wizard"),
            ("S-040", "Org overview"),
            ("S-041", "Domains"),
            ("S-042", "Add-domain wizard"),
            ("S-043", "Domain overview"),
            ("S-044", "Protection readiness"),
            ("S-045", "DNS records"),
            ("S-047", "DNS import and parity"),
            ("S-048", "DNS history and export"),
            ("S-050", "TLS overview"),
            ("S-051", "Certificates"),
            ("S-052", "Origin settings"),
            ("S-054", "Security overview"),
            ("S-055", "WAF settings"),
            ("S-056", "Attack categories"),
            ("S-057", "Vulnerable-Origin Shield"),
            ("S-061", "Rate limiting"),
            ("S-062", "Bots and challenge"),
            ("S-064", "Exceptions"),
            ("S-065", "Live threat monitor"),
            ("S-066", "Event detail"),
            ("S-069", "Appeals inbox"),
            ("S-073", "Reports"),
            ("S-076", "Alert rules"),
            ("S-082", "Invitations"),
            ("S-086", "Org settings"),
            ("S-090", "Data and privacy"),
            ("S-098", "Origin lockdown wizard"),
            ("S-099", "DNS propagation checker"),
            ("S-138", "Bypass Guard"),
        ] {
            s.push_str(&format!("| {id} | {name} | The fixture purpose. |\n"));
        }
        s.push_str(
            "\n### B11.8 Component inventory\n\n\
             | Component | Purpose |\n| --- | --- |\n\
             | ReadinessRing | A ring with a textual score and the footnote slot. |\n\
             \n## B8. Audit events (fixture)\n\n\
             | Event | Scope | Fields |\n| --- | --- | --- |\n\
             | AUD-domain.created / updated / activated | Domain | hostname |\n\
             | AUD-dns.exported | DNS | version |\n\
             | AUD-auth.mfa_enrolled / removed | Auth | factor |\n\
             \n## B13. Copy deck (canonical strings that tests and docs reference)\n\n\
             | Key stem | Text |\n| --- | --- |\n\
             | `tagline` | Put a firewall in front of your website. |\n\
             | `signup-title` | Create your account |\n\
             | `success-saved` | Saved. |\n\
             | `readiness-footnote` | Measures configuration completeness, not security. |\n\
             | `unknown-value` | Unknown ({reason}) |\n",
        );
        s.push_str(&spec_section());
        s
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used, clippy::unwrap_used, reason = "tests")]

    use std::collections::BTreeSet;
    use std::path::PathBuf;

    use super::*;

    /// The fixture documents plus the registry data read from the fixture master.
    fn context() -> (String, String, BTreeSet<String>, Vec<(String, String)>) {
        let spec = fixtures::spec();
        let screens = super::super::screen_ids(&spec);
        let b13 = super::super::content::b13_rows(&spec);
        let documents = fixtures::documents();
        let onboarding = documents
            .iter()
            .find(|(path, _)| path == ONBOARDING)
            .map(|(_, text)| text.clone())
            .unwrap_or_default();
        let readiness = documents
            .iter()
            .find(|(path, _)| path == READINESS_MODEL)
            .map(|(_, text)| text.clone())
            .unwrap_or_default();
        (onboarding, readiness, screens, b13)
    }

    /// A temporary repository root with `docs/UX` already created.
    fn temp_root(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("hdd-t0026-{}-{name}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(dir.join("docs").join("UX")).expect("temp tree");
        dir
    }

    #[test]
    fn t26_structure_requires_the_named_sections() {
        let (onboarding, readiness, screens, _b13) = context();
        let _ = screens;
        assert!(structure_findings(ONBOARDING, &onboarding, &ONBOARDING_SECTIONS).is_empty());
        assert!(structure_findings(READINESS_MODEL, &readiness, &READINESS_SECTIONS).is_empty());
        let mutated = onboarding.replace("## Stage map", "## Stage list");
        assert_ne!(mutated, onboarding);
        let findings = structure_findings(ONBOARDING, &mutated, &ONBOARDING_SECTIONS);
        assert!(
            findings
                .iter()
                .any(|f| f.message.to_lowercase().contains("section")),
            "a missing section must be a finding: {findings:?}"
        );
    }

    #[test]
    fn t26_stage_map_uses_the_expected_real_screen_for_each_stage() {
        let (onboarding, _readiness, screens, _b13) = context();
        assert!(stage_findings(&onboarding, &screens).is_empty());
        let mutated = onboarding.replace("| verify | S-042 |", "| verify | S-076 |");
        assert_ne!(mutated, onboarding);
        let findings = stage_findings(&mutated, &screens);
        assert!(
            findings
                .iter()
                .any(|f| f.message.to_lowercase().contains("stage")),
            "a valid screen in the wrong stage row must be a finding: {findings:?}"
        );
    }

    #[test]
    fn t26_checklist_requires_persistence_and_resume() {
        let (onboarding, _readiness, screens, _b13) = context();
        assert!(checklist_findings(&onboarding, &screens).is_empty());
        let mutated = onboarding.replace(
            "The checklist stays on S-040 until every item is done",
            "The checklist stays on S-041 until every item is done",
        );
        assert_ne!(mutated, onboarding);
        let findings = checklist_findings(&mutated, &screens);
        assert!(
            findings
                .iter()
                .any(|f| f.message.to_lowercase().contains("checklist")),
            "a checklist without S-040 persistence must be a finding: {findings:?}"
        );
    }

    #[test]
    fn t26_next_best_action_is_evaluated_against_its_examples() {
        let (onboarding, _readiness, screens, _b13) = context();
        assert!(next_action_findings(&onboarding, &screens).is_empty());
        let mutated = onboarding.replace(
            "| RD-DELEGATION=Fail; others=Pass | 1 | Finish the DNS connection at S-047. |",
            "| RD-DELEGATION=Fail; others=Pass | 3 | Finish the DNS connection at S-047. |",
        );
        assert_ne!(mutated, onboarding);
        let findings = next_action_findings(&mutated, &screens);
        assert!(
            findings
                .iter()
                .any(|f| f.message.to_lowercase().contains("example")
                    || f.message.to_lowercase().contains("rule")),
            "an example row that does not match the decision list must be a finding: {findings:?}"
        );
    }

    #[test]
    fn t26_nudges_have_a_numeric_cap_and_an_opt_out() {
        let (onboarding, _readiness, screens, _b13) = context();
        assert!(nudge_findings(&onboarding, &screens).is_empty());
        let mutated = onboarding.replace("at most 1 per 72 hours", "sometimes");
        assert_ne!(mutated, onboarding);
        let findings = nudge_findings(&mutated, &screens);
        assert!(
            findings
                .iter()
                .any(|f| f.message.to_lowercase().contains("cap")),
            "a non-numeric frequency cap must be a finding: {findings:?}"
        );
    }

    #[test]
    fn t26_empty_states_name_real_screens_and_honest_keys() {
        let (onboarding, _readiness, screens, b13) = context();
        assert!(empty_state_findings(&onboarding, &screens, &b13).is_empty());
        let mutated = onboarding.replace("`empty-readiness`", "`readiness-footnote`");
        assert_ne!(mutated, onboarding);
        let findings = empty_state_findings(&mutated, &screens, &b13);
        assert!(
            findings
                .iter()
                .any(|f| f.message.to_lowercase().contains("empty-state")
                    || f.message.to_lowercase().contains("copy key")),
            "a valid B13 key in the wrong place must be a finding: {findings:?}"
        );
    }

    #[test]
    fn t26_monitor_summary_keeps_the_block_decision_evidence() {
        let (onboarding, _readiness, screens, _b13) = context();
        assert!(monitor_findings(&onboarding, &screens).is_empty());
        let mutated = onboarding.replace("48-hour readiness hint", "readiness hint");
        assert_ne!(mutated, onboarding);
        let findings = monitor_findings(&mutated, &screens);
        assert!(
            findings
                .iter()
                .any(|f| f.message.to_lowercase().contains("monitor")),
            "a monitor summary without the 48-hour hint must be a finding: {findings:?}"
        );
    }

    #[test]
    fn t26_measures_use_local_counters_only() {
        let (onboarding, _readiness, _screens, _b13) = context();
        let spec = fixtures::spec();
        assert!(measure_findings(&onboarding, &spec).is_empty());
        let mutated = format!("{onboarding}\nWe also use Google Analytics.\n");
        let findings = measure_findings(&mutated, &spec);
        assert!(
            findings
                .iter()
                .any(|f| f.message.to_lowercase().contains("third-party")),
            "a third-party analytics name must be a finding: {findings:?}"
        );
    }

    #[test]
    fn t26_activation_emails_have_a_subject_structure_and_safe_keys() {
        let (onboarding, _readiness, _screens, b13) = context();
        assert!(email_findings(&onboarding, &b13).is_empty());
        let mutated = onboarding.replace("`email-verify-subject`", "`signup-title`");
        assert_ne!(mutated, onboarding);
        let findings = email_findings(&mutated, &b13);
        assert!(
            findings
                .iter()
                .any(|f| f.message.to_lowercase().contains("key")
                    || f.message.to_lowercase().contains("subject")),
            "a B13 key used as an email stem must be a finding: {findings:?}"
        );
    }

    #[test]
    fn t26_no_forbidden_claims_phrase() {
        let (onboarding, _readiness, _screens, _b13) = context();
        assert!(claim_findings(&onboarding).is_empty());
        let mutated = format!("{onboarding}\nThe product is unhackable.\n");
        let findings = claim_findings(&mutated);
        assert!(
            findings
                .iter()
                .any(|f| f.message.to_lowercase().contains("claims")),
            "a forbidden claims phrase must be a finding: {findings:?}"
        );
    }

    #[test]
    fn t26_category_weights_sum_to_one_hundred() {
        let (_onboarding, readiness, _screens, _b13) = context();
        assert!(category_findings(&readiness).is_empty());
        let mutated = readiness.replace("| Traffic | 20 |", "| Traffic | 19 |");
        assert_ne!(mutated, readiness);
        let findings = category_findings(&mutated);
        assert!(
            findings
                .iter()
                .any(|f| f.message.to_lowercase().contains("category")),
            "a category weight that breaks the sum must be a finding: {findings:?}"
        );
    }

    #[test]
    fn t26_catalog_rows_have_weight_source_interval_and_real_screen() {
        let (_onboarding, readiness, screens, _b13) = context();
        assert!(catalog_findings(&readiness, &screens).is_empty());
        let invalid_screen = readiness.replace(
            "| RD-CERT · Certificate valid beyond a quarter of its lifetime | Encryption | 5 | `certificates` (`not_after`, `status`) | hourly | S-051 |",
            "| RD-CERT · Certificate valid beyond a quarter of its lifetime | Encryption | 5 | `certificates` (`not_after`, `status`) | hourly | S-999 |",
        );
        assert_ne!(invalid_screen, readiness);
        let findings = catalog_findings(&invalid_screen, &screens);
        assert!(
            findings
                .iter()
                .any(|f| f.message.to_lowercase().contains("remediation")
                    || f.message.to_lowercase().contains("catalog")),
            "an unknown remediation screen must be a finding: {findings:?}"
        );
        let empty_source = readiness.replace("`certificates` (`not_after`, `status`)", "");
        assert_ne!(empty_source, readiness);
        let findings = catalog_findings(&empty_source, &screens);
        assert!(
            findings
                .iter()
                .any(|f| f.message.to_lowercase().contains("data source")),
            "an empty data source must be a finding: {findings:?}"
        );
    }

    #[test]
    fn t26_catalog_weights_sum_to_one_hundred() {
        let (_onboarding, readiness, _screens, _b13) = context();
        assert!(weight_findings(&readiness).is_empty());
        let mutated = readiness.replace("| Encryption | 5 |", "| Encryption | 4 |");
        assert_ne!(mutated, readiness);
        let findings = weight_findings(&mutated);
        assert!(
            findings
                .iter()
                .any(|f| f.message.to_lowercase().contains("sum")),
            "a catalog weight sum of 99 must be a finding: {findings:?}"
        );
    }

    #[test]
    fn t26_unknown_never_counts_as_a_pass() {
        let (_onboarding, readiness, _screens, b13) = context();
        assert!(unknown_findings(&readiness, &b13).is_empty());
        let mutated = readiness.replace("never counts as a pass", "never counts as a failure");
        assert_ne!(mutated, readiness);
        let findings = unknown_findings(&mutated, &b13);
        assert!(
            findings
                .iter()
                .any(|f| f.message.to_lowercase().contains("unknown")),
            "an unknown rule that allows a pass must be a finding: {findings:?}"
        );
    }

    #[test]
    fn t26_footnote_equals_the_b13_text() {
        let (_onboarding, readiness, screens, b13) = context();
        assert!(footnote_findings(&readiness, &b13, &screens).is_empty());
        let mutated = readiness.replace(
            "> Measures configuration completeness, not security.",
            "> Measures configuration completeness, not safety.",
        );
        assert_ne!(mutated, readiness);
        let findings = footnote_findings(&mutated, &b13, &screens);
        assert!(
            findings
                .iter()
                .any(|f| f.message.to_lowercase().contains("footnote")),
            "a footnote one word off must be a finding: {findings:?}"
        );
    }

    #[test]
    fn t26_scoring_example_is_evaluated() {
        let (_onboarding, readiness, _screens, _b13) = context();
        assert!(scoring_findings(&readiness).is_empty());
        let mutated = readiness.replace(
            "| B | RD-WAF-MODE Fail | 92 | 0 |",
            "| B | RD-WAF-MODE Fail | 93 | 0 |",
        );
        assert_ne!(mutated, readiness);
        let findings = scoring_findings(&mutated);
        assert!(
            findings
                .iter()
                .any(|f| f.message.to_lowercase().contains("score")),
            "an arithmetic example that does not match the scoring function must be a finding: {findings:?}"
        );
    }

    #[test]
    fn t26_j25_readiness_table_agrees_with_the_model() {
        let (_onboarding, readiness, _screens, _b13) = context();
        let journey = fixtures::journey_j25("## Readiness score\n\n");
        assert!(
            journey_readiness_findings(&readiness, &journey).is_empty(),
            "{:?}",
            journey_readiness_findings(&readiness, &journey)
        );
        let weight = journey.replace(
            "| Traffic flows through HDD | 8 |",
            "| Traffic flows through HDD | 7 |",
        );
        assert_ne!(weight, journey);
        assert!(
            journey_readiness_findings(&readiness, &weight)
                .iter()
                .any(|finding| finding.message.contains("weight 7")),
            "a weight that differs from the model must be a finding"
        );
        let fix = journey.replace("| S-043 |", "| S-044 |");
        assert_ne!(fix, journey);
        assert!(
            journey_readiness_findings(&readiness, &fix)
                .iter()
                .any(|finding| finding.message.contains("fix link")),
            "a fix link that differs from the model must be a finding"
        );
        let missing = journey
            .lines()
            .filter(|line| !line.starts_with("| Traffic flows through HDD |"))
            .collect::<Vec<_>>()
            .join("\n");
        assert!(
            journey_readiness_findings(&readiness, &missing)
                .iter()
                .any(|finding| finding.message.contains("not in the J-25")),
            "a model check missing from J-25 must be a finding"
        );
    }

    #[test]
    fn t26_check_on_a_fixture_tree_is_green() {
        let root = temp_root("green");
        let spec = fixtures::spec();
        for (path, text) in fixtures::documents() {
            let target = root.join(&path);
            if let Some(parent) = target.parent() {
                std::fs::create_dir_all(parent).expect("fixture directory");
            }
            std::fs::write(target, text).expect("write fixture document");
        }
        // F-28: the copy deck is the second source the empty-state keys are looked up in.
        std::fs::create_dir_all(root.join("i18n").join("en")).expect("i18n directory");
        std::fs::write(
            root.join(COPY_DECK),
            super::super::content::fixtures::copy_deck(),
        )
        .expect("write fixture copy deck");
        std::fs::create_dir_all(root.join("docs").join("UX").join("journeys"))
            .expect("journeys directory");
        std::fs::write(
            root.join(JOURNEY_READINESS),
            fixtures::journey_j25("## Readiness score\n\n"),
        )
        .expect("write fixture J-25");
        let findings = check_with_spec(&root, &spec);
        assert!(
            findings.is_empty(),
            "the fixture tree must pass: {findings:?}"
        );
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn t26_missing_documents_are_findings_not_panics() {
        let root = temp_root("missing");
        let findings = check_with_spec(&root, &fixtures::spec());
        assert!(!findings.is_empty(), "a missing document must be a finding");
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn t26_malformed_specification_is_findings_not_panics() {
        let root = temp_root("malformed");
        let findings = check_with_spec(&root, "");
        assert!(
            !findings.is_empty(),
            "a missing B13 table and missing documents must be findings"
        );
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn t26_b122_mapping_has_one_row_per_phrase() {
        let (_onboarding, readiness, _screens, _b13) = context();
        let spec = fixtures::spec();
        assert!(
            b122_mapping_findings(&readiness, &spec).is_empty(),
            "{:?}",
            b122_mapping_findings(&readiness, &spec)
        );
        let paraphrased = readiness.replace(
            "| no grey web records that expose the same hostnames | Traffic | RD-GREY |",
            "| no grey web records that expose a hostname | Traffic | RD-GREY |",
        );
        assert_ne!(paraphrased, readiness);
        let findings = b122_mapping_findings(&paraphrased, &spec);
        assert!(
            findings
                .iter()
                .any(|f| f.message.to_lowercase().contains("b12.2")),
            "a paraphrase of a B12.2 phrase must be a finding: {findings:?}"
        );
        let wrong_check = readiness.replace(
            "| WAF in block mode (monitor gives partial) | Detection | RD-WAF-MODE |",
            "| WAF in block mode (monitor gives partial) | Detection | RD-SHIELD |",
        );
        assert_ne!(wrong_check, readiness);
        let findings = b122_mapping_findings(&wrong_check, &spec);
        assert!(
            findings
                .iter()
                .any(|f| f.message.to_lowercase().contains("b12.2")),
            "a phrase mapped to the wrong model check must be a finding: {findings:?}"
        );
    }

    #[test]
    fn t26_waf_monitor_partial_is_a_design_value() {
        let (_onboarding, readiness, _screens, _b13) = context();
        assert!(
            waf_partial_findings(&readiness).is_empty(),
            "{:?}",
            waf_partial_findings(&readiness)
        );
        let no_confirmation = readiness.replace(
            "a design value confirmed in T-0172",
            "a design value agreed later",
        );
        assert_ne!(no_confirmation, readiness);
        let findings = waf_partial_findings(&no_confirmation);
        assert!(
            findings
                .iter()
                .any(|f| f.message.to_lowercase().contains("partial")),
            "a monitor-mode ratio without the T-0172 confirmation must be a finding: {findings:?}"
        );
        let wrong_ratio = readiness.replace(
            "| F | RD-WAF-MODE Partial(0.5) | 96 | 0 |",
            "| F | RD-WAF-MODE Partial(0.25) | 96 | 0 |",
        );
        assert_ne!(wrong_ratio, readiness);
        let findings = waf_partial_findings(&wrong_ratio);
        assert!(
            findings
                .iter()
                .any(|f| f.message.to_lowercase().contains("partial")
                    || f.message.to_lowercase().contains("monitor")),
            "a scoring example that disagrees with the monitor-mode ratio must be a finding: {findings:?}"
        );
    }

    #[test]
    fn t26_origin_exposure_covers_mail_records_and_headers() {
        let (_onboarding, readiness, _screens, _b13) = context();
        assert!(
            origin_mail_findings(&readiness).is_empty(),
            "{:?}",
            origin_mail_findings(&readiness)
        );
        let no_dkim = readiness.replace("(MX, SPF and DKIM)", "(MX and SPF)");
        assert_ne!(no_dkim, readiness);
        let findings = origin_mail_findings(&no_dkim);
        assert!(
            findings
                .iter()
                .any(|f| f.message.to_lowercase().contains("mail")
                    || f.message.to_lowercase().contains("dkim")),
            "an origin-exposure row without the mail records must be a finding: {findings:?}"
        );
    }

    #[test]
    fn t26_every_catalog_check_is_reachable_by_a_rule() {
        let (onboarding, _readiness, screens, _b13) = context();
        assert!(
            next_action_findings(&onboarding, &screens).is_empty(),
            "{:?}",
            next_action_findings(&onboarding, &screens)
        );
        let without_generic = onboarding.replace(
            "12. rule 12: if any check is not Pass then Open the remediation link for the first non-Pass check in catalog order.\n",
            "",
        );
        assert_ne!(without_generic, onboarding);
        let findings = next_action_findings(&without_generic, &screens);
        assert!(
            findings.iter().any(|f| {
                let message = f.message.to_lowercase();
                message.contains("reachable") || message.contains("all-pass")
            }),
            "a catalog check that no rule reaches must be a finding: {findings:?}"
        );
    }

    #[test]
    fn t26_all_pass_state_returns_the_distinct_outcome() {
        let (onboarding, _readiness, screens, _b13) = context();
        let mutated = onboarding.replace(
            "13. rule 13: if always then Nothing to do now.",
            "13. rule 13: if always then Review the checklist at S-044.",
        );
        assert_ne!(mutated, onboarding);
        let findings = next_action_findings(&mutated, &screens);
        assert!(
            findings.iter().any(|f| {
                let message = f.message.to_lowercase();
                message.contains("all-pass") || message.contains("nothing to do now")
            }),
            "an all-Pass state that returns a task must be a finding: {findings:?}"
        );
    }

    #[test]
    fn t26_mfa_rule_names_who_can_enrol() {
        let (onboarding, _readiness, screens, _b13) = context();
        let anonymous_actor = onboarding.replace(
            "Ask an owner or an admin to enrol MFA at S-030.",
            "Ask the owner to enrol MFA at S-030.",
        );
        assert_ne!(anonymous_actor, onboarding);
        let findings = next_action_findings(&anonymous_actor, &screens);
        assert!(
            findings.iter().any(|f| {
                let message = f.message.to_lowercase();
                message.contains("mfa") || message.contains("actor")
            }),
            "an MFA rule that does not name who can enrol must be a finding: {findings:?}"
        );
        let no_role_note = onboarding.replace("For a non-owner role", "For a role");
        assert_ne!(no_role_note, onboarding);
        let findings = next_action_findings(&no_role_note, &screens);
        assert!(
            findings
                .iter()
                .any(|f| f.message.to_lowercase().contains("non-owner")),
            "the section must name the non-owner role case: {findings:?}"
        );
    }

    #[test]
    fn t26_six_multi_condition_examples_are_evaluated() {
        let (onboarding, _readiness, screens, _b13) = context();
        assert!(
            next_action_findings(&onboarding, &screens).is_empty(),
            "{:?}",
            next_action_findings(&onboarding, &screens)
        );
        let single_condition_only = onboarding
            .lines()
            .filter(|line| !(line.trim_start().starts_with('|') && line.contains(';')))
            .collect::<Vec<_>>()
            .join("\n");
        assert_ne!(single_condition_only, onboarding);
        let findings = next_action_findings(&single_condition_only, &screens);
        assert!(
            findings
                .iter()
                .any(|f| f.message.to_lowercase().contains("multi-condition")),
            "fewer than six multi-condition examples must be a finding: {findings:?}"
        );
    }

    /// Replace one `key = value` line of a Fluent fixture, leaving the other keys intact.
    fn with_line(text: &str, key: &str, replacement: &str) -> String {
        let prefix = format!("{key} = ");
        text.lines()
            .map(|line| {
                if line.starts_with(&prefix) {
                    replacement
                } else {
                    line
                }
            })
            .collect::<Vec<_>>()
            .join("\n")
            + "\n"
    }

    /// Findings as one string, for a readable assertion message.
    fn joined(findings: &[Finding]) -> String {
        findings
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>()
            .join("\n")
    }

    #[test]
    fn t26_copy_keys_are_defined_exactly_once_in_the_three_sources() {
        let (onboarding, _readiness, _screens, b13) = context();
        let deck = super::super::content::fixtures::copy_deck();
        let ftl = fixtures::onboarding_ftl();
        let findings = copy_key_definition_findings(&onboarding, deck, &ftl, &b13);
        assert!(findings.is_empty(), "{}", joined(&findings));

        // A referenced key that no source defines is a finding.
        let undefined = with_line(&ftl, "empty-alerts", "");
        assert_ne!(undefined, ftl);
        let text = joined(&copy_key_definition_findings(
            &onboarding,
            deck,
            &undefined,
            &b13,
        ));
        assert!(
            text.contains("empty-alerts"),
            "a copy key defined nowhere must be a finding: {text}"
        );

        // A key defined twice in the new file is a finding.
        let duplicated = format!("{ftl}empty-team = A second definition for the same key.\n");
        let text = joined(&copy_key_definition_findings(
            &onboarding,
            deck,
            &duplicated,
            &b13,
        ));
        assert!(
            text.contains("empty-team") && (text.contains("2 times") || text.contains("twice")),
            "a key defined twice must be a finding: {text}"
        );

        // A key defined in the B13 copy deck and in the new file is a finding.
        let cross_source = format!(
            "{ftl}readiness-footnote = Measures configuration completeness, not security.\n"
        );
        let text = joined(&copy_key_definition_findings(
            &onboarding,
            deck,
            &cross_source,
            &b13,
        ));
        assert!(
            text.contains("readiness-footnote"),
            "a key defined in two sources must be a finding: {text}"
        );
    }

    #[test]
    fn t26_copy_keys_are_read_from_every_copy_key_column() {
        let (onboarding, _readiness, _screens, b13) = context();
        let deck = super::super::content::fixtures::copy_deck();
        let ftl = fixtures::onboarding_ftl();
        let refs = copy_key_references(&onboarding);
        assert!(
            refs.iter()
                .any(|(_, key)| key == "empty-onboarding-profile"),
            "the Empty states Copy key column must be read: {refs:?}"
        );
        let extra = format!(
            "{onboarding}\n## Later table\n\n\
             | Screen | Empty state | Copy key | Next action |\n| --- | --- | --- | --- |\n\
             | S-090 | A state the fixture adds. | `empty-later-table` | Request an export. |\n"
        );
        assert!(
            copy_key_references(&extra)
                .iter()
                .any(|(_, key)| key == "empty-later-table"),
            "a second Copy key column must be read as well"
        );
        let text = joined(&copy_key_definition_findings(&extra, deck, &ftl, &b13));
        assert!(
            text.contains("empty-later-table"),
            "a key that no source defines must be a finding: {text}"
        );
    }

    #[test]
    fn t26_onboarding_ftl_values_pass_the_style_rules() {
        let ftl = fixtures::onboarding_ftl();
        let findings = ftl_value_findings(ONBOARDING_FTL, &ftl, None);
        assert!(findings.is_empty(), "{}", joined(&findings));

        let bad_key = ftl.replace("empty-alerts = ", "Empty-Alerts = ");
        assert_ne!(bad_key, ftl);
        let text = joined(&ftl_value_findings(ONBOARDING_FTL, &bad_key, None));
        assert!(
            text.contains("Empty-Alerts"),
            "a key that is not a semantic hyphenated stem must be a finding: {text}"
        );

        let emoji = with_line(
            &ftl,
            "empty-alerts",
            "empty-alerts = A new notice \u{1F680}",
        );
        let text = joined(&ftl_value_findings(ONBOARDING_FTL, &emoji, None));
        assert!(
            text.to_lowercase().contains("emoji"),
            "an emoji must be a finding: {text}"
        );

        let markup = with_line(
            &ftl,
            "empty-alerts",
            "empty-alerts = A <b>bold</b> notice for the team.",
        );
        let text = joined(&ftl_value_findings(ONBOARDING_FTL, &markup, None));
        assert!(
            text.contains('<') || text.contains("markup"),
            "`<` markup must be a finding: {text}"
        );

        let exclamation = with_line(&ftl, "empty-alerts", "empty-alerts = A new notice!");
        let text = joined(&ftl_value_findings(ONBOARDING_FTL, &exclamation, None));
        assert!(
            text.to_lowercase().contains("exclamation"),
            "an exclamation mark outside a success key must be a finding: {text}"
        );

        let duplicate_value = with_line(
            &ftl,
            "empty-team",
            "empty-team = A new notice for the team.",
        );
        let duplicate_value = with_line(
            &duplicate_value,
            "empty-alerts",
            "empty-alerts = A new notice for the team.",
        );
        let text = joined(&ftl_value_findings(ONBOARDING_FTL, &duplicate_value, None));
        assert!(
            text.contains("same value") || text.to_lowercase().contains("duplicate"),
            "two keys with one value must be a finding: {text}"
        );

        let empty = with_line(&ftl, "empty-alerts", "empty-alerts =");
        let text = joined(&ftl_value_findings(ONBOARDING_FTL, &empty, None));
        assert!(
            text.to_lowercase().contains("empty"),
            "an empty value without the comment must be a finding: {text}"
        );
    }

    #[test]
    fn t26_onboarding_ftl_passes_the_claims_scanner() {
        let cfg: crate::claims::Config =
            toml::from_str(include_str!("../../../../docs/claims-lint.toml"))
                .expect("shipped config");
        let ftl = fixtures::onboarding_ftl();
        let findings = ftl_value_findings(ONBOARDING_FTL, &ftl, Some(&cfg));
        assert!(findings.is_empty(), "{}", joined(&findings));

        let claim = with_line(
            &ftl,
            "empty-alerts",
            "empty-alerts = We give absolute protection to every website.",
        );
        let text = joined(&ftl_value_findings(ONBOARDING_FTL, &claim, Some(&cfg)));
        assert!(
            text.contains("absolute protection"),
            "a forbidden claims phrase must be a finding: {text}"
        );
    }
}
