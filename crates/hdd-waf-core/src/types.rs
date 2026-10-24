//! Shared inspection types for the HK1 demo track: the request vectors, the field kinds, the site settings and the
//! verdict the proxy acts on.
//!
//! This module is the frozen interface between `hdd-waf-core` and `hdd-proxy` (COLLAB.md, hackathon demo track HK1).
//! `inspect` itself is pure: no I/O, no clock, no allocation beyond the normaliser's bounded workspaces, and it never
//! panics (R-09). The detector may only return the fields declared here; the proxy decides the site mode.

use serde::{Deserialize, Serialize};

/// Where in the request a value was found. The order is the order the extractor reports findings in.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Vector {
    /// A path segment, percent-decoded.
    Path,
    /// A query-string name or value.
    Query,
    /// An `application/x-www-form-urlencoded` body name or value.
    FormBody,
    /// A JSON string value (object keys are not inspected as values).
    JsonBody,
    /// A multipart form field (`name` and content).
    MultipartField,
    /// A multipart file name.
    MultipartFilename,
    /// One of the selected request headers (`User-Agent`, `Referer`, `X-Forwarded-For`).
    Header,
    /// A cookie name or value.
    Cookie,
}

/// The likely meaning of a field, inferred from its name and vector (C4.6). It changes the policy: a password field
/// tolerates quote characters, a numeric id tolerates digits only, and prose-shaped fields get the false-positive
/// controls of C4.9.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FieldKind {
    /// A password or passphrase field: the password exception of C4.6 applies to the H2 family.
    Password,
    /// A user name, login name or email address.
    Username,
    /// An integer identifier (`id`, `page`, `user_id`, ...).
    NumericId,
    /// A search box or filter term.
    Search,
    /// Free prose (comment, message, address, ...).
    FreeText,
    /// A file name.
    Filename,
    /// A request header value.
    Header,
    /// A cookie value.
    Cookie,
    /// No inference possible.
    Unknown,
}

/// How aggressively the detector treats ambiguous shapes (`Balanced` is the default, `Paranoid` adds low-confidence
/// families and stricter thresholds).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Strictness {
    /// The default policy of C4.6: hard families plus the documented exceptions.
    #[default]
    Balanced,
    /// Adds the cheaper heuristic families and lowers the thresholds; documented per rule.
    Paranoid,
}

/// One request under inspection.
///
/// The proxy fills this from the wire. `body` is at most [`INSPECT_BODY_CAP`] bytes: a larger body is inspected up to
/// the cap and [`Verdict::truncated`] is set, never silently passed.
#[derive(Debug, Clone, Copy)]
pub struct InspectInput<'a> {
    /// The request method, upper-case by convention.
    pub method: &'a str,
    /// The request path, without the query string.
    pub path: &'a str,
    /// The raw query string, without the leading `?`.
    pub query: Option<&'a str>,
    /// The request headers as received (order preserved, names as sent).
    pub headers: &'a [(String, String)],
    /// The `Content-Type` value, if any.
    pub content_type: Option<&'a str>,
    /// The request body, at most [`INSPECT_BODY_CAP`] bytes.
    pub body: &'a [u8],
}

/// The per-site settings the proxy passes to [`crate::inspect`].
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct SiteSettings {
    /// The strictness profile.
    pub strictness: Strictness,
    /// Operator-provided field hints: the first matching name wins over the name heuristic of C4.6.
    #[serde(default)]
    pub field_hints: Vec<(String, FieldKind)>,
    /// Operator-provided rules, applied before the built-in families.
    #[serde(default)]
    pub extra_rules: Vec<CustomRule>,
}

/// The decision the detector recommends. The proxy turns `Block` into a 403 in `block` mode and into a recorded
/// `would_block` event in `monitor` mode; `Allow` is forwarded in both modes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Action {
    /// The request may be forwarded.
    #[default]
    Allow,
    /// The request must be refused (`block` mode) or recorded as `would_block` (`monitor` mode).
    Block,
}

/// A verdict for one request.
///
/// `category` is `Some("sqli")` for the built-in injection rules of this demo track and `Some("custom")` for an
/// operator custom rule (the proxy bans alike); the request-level refusals are `Some("policy")` with the subtypes:
/// `"truncated"` (the extraction value cap, the request-body cap or the detector work budget was hit, so the request is
/// refused rather than passed unread, R-26; rules `LIMIT-001`), `"unsupported_content_encoding"` (a non-identity
/// `Content-Encoding` cannot be inspected and is refused, rule `CE-001`), `"boundary_mismatch"` (a multipart body whose
/// boundary does not match the `Content-Type` cannot be parsed safely, rule `MP-001`) and `"inspection_timeout"`
/// (the detector exceeded its wall-clock budget on the blocking pool and the request is refused, rule `LIMIT-002`).
/// `evidence` is redacted and at most [`MAX_EVIDENCE_BYTES`] bytes, cut on a UTF-8 boundary.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Verdict {
    /// The recommended action.
    pub action: Action,
    /// The attack category (`"sqli"`, `"custom"` or `"policy"`), `None` when allowed.
    pub category: Option<&'static str>,
    /// The family subtype (`"tautology"`, `"union"`, ...), `None` when allowed.
    pub subtype: Option<&'static str>,
    /// The built-in rule or custom rule id that fired.
    pub rule_id: Option<&'static str>,
    /// Where the offending value was found.
    pub vector: Option<Vector>,
    /// The field name (header name, cookie name, JSON path, form key, ...).
    pub field: Option<String>,
    /// The inferred field kind.
    pub field_kind: Option<FieldKind>,
    /// Redacted, at most [`MAX_EVIDENCE_BYTES`] bytes, valid UTF-8.
    pub evidence: String,
    /// A relative confidence in `0..=100`; higher is more certain.
    pub score: u32,
    /// The body was longer than [`INSPECT_BODY_CAP`] and only the first cap bytes were inspected.
    pub truncated: bool,
}

impl Default for Verdict {
    fn default() -> Self {
        Self::allow()
    }
}

impl Verdict {
    /// An `Allow` verdict with no details.
    #[must_use]
    pub fn allow() -> Self {
        Self {
            action: Action::Allow,
            category: None,
            subtype: None,
            rule_id: None,
            vector: None,
            field: None,
            field_kind: None,
            evidence: String::new(),
            score: 0,
            truncated: false,
        }
    }

    /// A `Block` verdict. The caller supplies the evidence already redacted and cut to [`MAX_EVIDENCE_BYTES`]; the
    /// detector does that through its helper, and the proxy never re-cuts it.
    // The parameters are exactly the fields of [`Verdict`] that a block sets; grouping them into another struct would
    // only move the same data one level down and break the frozen public interface. Justified allow, no behaviour.
    #[allow(clippy::too_many_arguments)]
    #[must_use]
    pub fn block(
        category: &'static str,
        subtype: &'static str,
        rule_id: &'static str,
        vector: Vector,
        field: impl Into<String>,
        field_kind: FieldKind,
        evidence: impl Into<String>,
        score: u32,
    ) -> Self {
        let mut evidence = evidence.into();
        if evidence.len() > MAX_EVIDENCE_BYTES {
            let mut cut = MAX_EVIDENCE_BYTES;
            while cut > 0 && !evidence.is_char_boundary(cut) {
                cut -= 1;
            }
            evidence.truncate(cut);
        }
        Self {
            action: Action::Block,
            category: Some(category),
            subtype: Some(subtype),
            rule_id: Some(rule_id),
            vector: Some(vector),
            field: Some(field.into()),
            field_kind: Some(field_kind),
            evidence,
            score,
            truncated: false,
        }
    }
}

/// A per-site custom rule: either a linear-time regular expression or a literal `contains` match over the normalised
/// value. The proxy validates the rule when the configuration loads, so `inspect` never fails on a malformed pattern
/// (a rule that does not compile simply never fires; the config layer is where that is reported).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CustomRule {
    /// The rule id reported in the verdict and the audit log.
    pub id: String,
    /// Only apply the rule to this vector; `None` applies it to every vector.
    #[serde(default)]
    pub vector: Option<Vector>,
    /// Literal match over the normalised value (mutually exclusive with `regex`).
    #[serde(default)]
    pub contains: Option<String>,
    /// Linear-time regex match over the normalised value (mutually exclusive with `contains`).
    #[serde(default)]
    pub regex: Option<String>,
    /// What to do when the rule matches.
    pub action: Action,
    /// A human description shown in the dashboard and the event log.
    pub description: String,
}

/// The maximum number of request-body bytes inspected. A larger body is inspected up to this cap and the verdict is
/// marked `truncated` (never silently passed).
pub const INSPECT_BODY_CAP: usize = 256 * 1024;

/// The maximum length of [`Verdict::evidence`] in bytes.
pub const MAX_EVIDENCE_BYTES: usize = 128;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn allow_verdict_has_no_category() {
        let verdict = Verdict::allow();
        assert_eq!(verdict.action, Action::Allow);
        assert!(verdict.category.is_none());
        assert!(verdict.evidence.is_empty());
    }

    #[test]
    fn block_verdict_cuts_evidence_on_a_utf8_boundary() {
        let mut evidence = "é".repeat(MAX_EVIDENCE_BYTES);
        evidence.push('x');
        let verdict = Verdict::block(
            "sqli",
            "tautology",
            "H1-001",
            Vector::Query,
            "q",
            FieldKind::Search,
            evidence,
            90,
        );
        assert_eq!(verdict.action, Action::Block);
        assert!(verdict.evidence.len() <= MAX_EVIDENCE_BYTES);
        assert!(verdict.evidence.chars().all(|c| c == 'é'));
    }

    #[test]
    fn custom_rule_round_trips_through_json() {
        let rule = CustomRule {
            id: "C-001".to_owned(),
            vector: Some(Vector::Query),
            contains: Some("union select".to_owned()),
            regex: None,
            action: Action::Block,
            description: "operator rule for the demo day".to_owned(),
        };
        let json = serde_json::to_string(&rule).unwrap_or_default();
        assert!(json.contains("C-001"));
        let parsed: Result<CustomRule, _> = serde_json::from_str(&json);
        assert_eq!(parsed.ok(), Some(rule));
    }
}
