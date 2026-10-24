//! Live Target Profile v5 (`hdd.live.yaml`, section 8): types, strict parsing, validation, redaction and rendering.
//!
//! Parsing is two-stage and bounded. Stage one reads the YAML into a generic value with `serde-saphyr` under a tight budget
//! (no anchors, aliases or merge keys, shallow nesting, a few thousand events, duplicate keys rejected, size capped). Stage
//! two deserializes that value into [`Profile`] with `serde_path_to_error`, so an unknown or mistyped key is reported with its
//! full key path. The YAML parser decision is ADR-0002.

use std::fmt;

use serde_json::Value;

pub mod capability;
pub mod env;
pub mod secrets;
pub mod types;
pub mod validate;

pub use secrets::{EnvVarName, SecretPath};
pub use types::Profile;
pub use validate::{Context, Finding, Reason, Report, Status, validate};

/// Largest accepted profile file (the real file is a few kilobytes).
pub const MAX_PROFILE_BYTES: usize = 256 * 1024;

/// Why a profile could not be read.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParseError {
    /// Dotted key path the error is about (empty for whole-document problems).
    pub key_path: String,
    /// What is wrong, with the remedy where one exists.
    pub message: String,
}

impl fmt::Display for ParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.key_path.is_empty() {
            f.write_str(&self.message)
        } else {
            write!(f, "{}: {}", self.key_path, self.message)
        }
    }
}

impl std::error::Error for ParseError {}

fn perr(path: impl Into<String>, message: impl Into<String>) -> ParseError {
    ParseError {
        key_path: path.into(),
        message: message.into(),
    }
}

fn yaml_options() -> serde_saphyr::Options {
    use serde_saphyr::{DuplicateKeyPolicy, MergeKeyPolicy};
    let mut budget = serde_saphyr::Budget::default();
    budget.max_aliases = 0;
    budget.max_anchors = 0;
    budget.max_depth = 16;
    budget.flow_nesting_limit = 16;
    budget.max_events = 20_000;
    budget.max_nodes = 10_000;
    budget.max_documents = 1;
    budget.max_merge_keys = 0;
    budget.max_total_scalar_bytes = MAX_PROFILE_BYTES;
    let mut options = serde_saphyr::Options::default();
    options.budget = Some(budget);
    options.duplicate_keys = DuplicateKeyPolicy::Error;
    options.merge_keys = MergeKeyPolicy::Error;
    options.strict_booleans = true;
    options
}

/// Turn serde's "unknown field" message into the full key path of the offending key.
fn locate(path: &serde_path_to_error::Path, message: &str) -> ParseError {
    let parent = path.to_string();
    let parent = if parent == "." { String::new() } else { parent };
    if let Some(rest) = message.strip_prefix("unknown field `")
        && let Some(end) = rest.find('`')
    {
        let key = rest.get(..end).unwrap_or("");
        // serde_path_to_error may already include the offending key as the last path segment
        let already = parent == key || parent.ends_with(&format!(".{key}"));
        let full = if parent.is_empty() || already {
            if parent.is_empty() {
                key.to_owned()
            } else {
                parent
            }
        } else {
            format!("{parent}.{key}")
        };
        return perr(
            full,
            format!("unknown key (the profile rejects keys it does not define): {message}"),
        );
    }
    perr(parent, scrub_message(message))
}

/// Remove the offending value from a serde message: the profile is the place where people paste secrets into the wrong
/// field, so `invalid type: string "..."` and `unknown variant `...`` must not repeat what was pasted. The list of expected
/// variants (which helps the operator) is kept.
pub fn scrub_message(message: &str) -> String {
    let mut out = message.to_owned();
    // quoted values: string "...", unit variant "..." etc.
    let mut cleaned = String::with_capacity(out.len());
    let mut in_quote = false;
    for c in out.chars() {
        if c == '"' {
            if in_quote {
                cleaned.push_str("<value>\"");
            } else {
                cleaned.push('"');
            }
            in_quote = !in_quote;
        } else if !in_quote {
            cleaned.push(c);
        }
    }
    out = cleaned;
    if let Some(rest) = out.strip_prefix("unknown variant `")
        && let Some(end) = rest.find('`')
    {
        out = format!(
            "unknown variant `<value>`{}",
            rest.get(end + 1..).unwrap_or("")
        );
    }
    out
}

/// Remove credentials, query and fragment from a URL-looking string (`None` when it is not one).
fn scrub_url_string(s: &str) -> Option<String> {
    let (scheme, rest) = s.split_once("://")?;
    let end = rest.find(['/', '?', '#']).unwrap_or(rest.len());
    let (authority, tail) = rest.split_at(end);
    let authority = authority
        .rsplit_once('@')
        .map_or(authority, |(_, host)| host);
    let tail = tail.split(['?', '#']).next().unwrap_or("");
    Some(format!("{scheme}://{authority}{tail}"))
}

/// Strip credentials and query strings from every URL-looking string of a JSON value (for printing).
fn scrub_urls(v: &mut Value) {
    match v {
        Value::String(s) => {
            if let Some(clean) = scrub_url_string(s) {
                *s = clean;
            }
        }
        Value::Array(a) => a.iter_mut().for_each(scrub_urls),
        Value::Object(m) => m.values_mut().for_each(scrub_urls),
        _ => {}
    }
}

/// Read profile YAML into a generic value under the same budget as [`parse_yaml`] (used by tooling that inspects raw keys).
pub fn parse_value(text: &str) -> Result<Value, ParseError> {
    if text.len() > MAX_PROFILE_BYTES {
        return Err(perr(
            "",
            format!("profile file is larger than {MAX_PROFILE_BYTES} bytes"),
        ));
    }
    serde_saphyr::from_str_with_options(text, yaml_options())
        .map_err(|e| perr("", format!("YAML error: {e}")))
}

/// Parse a profile from YAML text. Unknown keys, wrong types, secret-looking values in name fields, duplicate keys,
/// anchors/aliases and oversized or deeply nested documents are all rejected.
pub fn parse_yaml(text: &str) -> Result<Profile, ParseError> {
    if text.len() > MAX_PROFILE_BYTES {
        return Err(perr(
            "",
            format!("profile file is larger than {MAX_PROFILE_BYTES} bytes"),
        ));
    }
    let value = parse_value(text)?;
    let Some(map) = value.as_object() else {
        return Err(perr(
            "",
            "the profile must be a YAML mapping at the top level",
        ));
    };
    if !map.contains_key("schema_version") {
        return Err(perr(
            "schema_version",
            "required key `schema_version` is missing; set `schema_version: 5`",
        ));
    }
    serde_path_to_error::deserialize::<_, Profile>(&value)
        .map_err(|e| locate(e.path(), &e.inner().to_string()))
}

/// The profile as pretty JSON with secrets reduced to names: `*_env` fields show variable names only, key paths show file
/// names only (`SecretPath` serializes redacted). Safe to print or log.
pub fn redacted_json(p: &Profile) -> String {
    let mut v = serde_json::to_value(p).unwrap_or(Value::Null);
    scrub_urls(&mut v);
    serde_json::to_string_pretty(&v).unwrap_or_else(|_| "{}".to_owned())
}

/// JSON Schema of the profile, pretty-printed with a trailing newline (the committed `docs/profile.schema.json`).
pub fn schema_json() -> String {
    let schema = schemars::schema_for!(Profile);
    let mut s = serde_json::to_string_pretty(&schema).unwrap_or_else(|_| "{}".to_owned());
    s.push('\n');
    s
}

/// Render a report as a table: `RULE | STATUS | FIELD | MESSAGE`, each non-PASS finding followed by its remediation.
pub fn render_table(report: &Report) -> String {
    let w_rule = report
        .findings
        .iter()
        .map(|f| f.rule.len())
        .max()
        .unwrap_or(4)
        .max(4);
    let w_status = report
        .findings
        .iter()
        .map(|f| f.status.to_string().len())
        .max()
        .unwrap_or(6)
        .max(6);
    let mut out = format!(
        "{:<w_rule$}  {:<w_status$}  FIELD / MESSAGE\n",
        "RULE", "STATUS"
    );
    out.push_str(&format!("{}\n", "-".repeat(w_rule + w_status + 20)));
    for f in &report.findings {
        let field = if f.field.is_empty() {
            String::new()
        } else {
            format!("{}: ", f.field)
        };
        out.push_str(&format!(
            "{:<w_rule$}  {:<w_status$}  {field}{}\n",
            f.rule,
            f.status.to_string(),
            f.message
        ));
        if !f.remediation.is_empty() {
            out.push_str(&format!(
                "{:<w_rule$}  {:<w_status$}  -> {}\n",
                "", "", f.remediation
            ));
        }
    }
    let count = |s: fn(&Status) -> bool| report.findings.iter().filter(|f| s(&f.status)).count();
    out.push_str(&format!(
        "\n{} PASS, {} FAIL, {} WARN, {} UNVERIFIED, {} N/A\n",
        count(|s| *s == Status::Pass),
        count(|s| *s == Status::Fail),
        count(|s| *s == Status::Warn),
        count(|s| matches!(s, Status::Unverified(_))),
        count(|s| *s == Status::NotApplicable)
    ));
    out
}

/// The "missing required fields" list of the first response (section 9, item 2) for a profile that does not exist or is
/// being checked: every required field with how to provide it. `local` selects the local-profile subset.
pub fn render_required_fields(local: bool) -> String {
    let mut out = String::new();
    out.push_str(if local {
        "Required for runtime.profile: local (section 8.2):\n"
    } else {
        "Required for runtime.profile: hosted (section 8):\n"
    });
    for r in validate::REQUIRED_FIELDS {
        if (local && r.local) || (!local && r.hosted) {
            out.push_str(&format!("  - {}: {}\n", r.path, r.how));
        }
    }
    out.push_str("Copy hdd.live.example.yaml to hdd.live.yaml (git-ignored), fill these fields, and run `hddctl preflight --profile-only`.\n");
    out
}

/// The missing-required-fields renderer applied to a parsed profile: lists only the fields still empty.
pub fn render_missing(p: &Profile) -> String {
    let local = p.runtime.profile == types::RuntimeProfile::Local;
    let report = validate(p, &Context::default());
    let missing: Vec<&Finding> = report
        .of_rule("PROF-REQUIRED")
        .into_iter()
        .filter(|f| f.status == Status::Fail)
        .collect();
    if missing.is_empty() {
        return "No required field is missing.\n".to_owned();
    }
    let mut out = format!(
        "{} required field(s) missing for runtime.profile: {}:\n",
        missing.len(),
        if local { "local" } else { "hosted" }
    );
    for f in missing {
        out.push_str(&format!("  - {}\n      {}\n", f.field, f.remediation));
    }
    out
}

#[cfg(test)]
mod tests;
