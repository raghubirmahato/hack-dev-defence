//! Deterministic finding explanation and remediation text (COLLAB Addendum 6 item 1).
//!
//! This module is pure content generation: given the facts HDD already recorded about a blocked request (category,
//! family/subtype, rule id, vector, field kind, method, path, redacted evidence and the site's stack hint) it
//! produces the same explanation every time. There is no I/O, no clock, no randomness and no network: the optional
//! AI explanation is a separate layer owned by the proxy, and a deterministic explanation is always available
//! without it (R-33: no model decides a verdict).
//!
//! The text is honest by construction: `inferred_weakness` is worded as an inference from the payload shape (never
//! as proof of a vulnerability), `attacker_impact` separates what the family enables from what the matched path
//! suggests, and the virtual-patch note states that a block is not a fix (R-11).

use serde::{Deserialize, Serialize};

use crate::evidence::redact;
use crate::types::{FieldKind, Vector};

/// The site's technology stack hint. It only selects the remediation code example; detection never depends on it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Stack {
    /// A Node.js backend (sql.js/sqlite3/mysql2/pg style drivers).
    Node,
    /// A PHP backend (PDO or mysqli).
    Php,
    /// A Python backend (sqlite3/psycopg style drivers).
    Python,
    /// A Java backend (JDBC `PreparedStatement`).
    Java,
    /// Any other stack, or no hint: generic parameterised-query guidance.
    #[default]
    Other,
}

/// The facts needed to explain one blocked request deterministically.
#[derive(Debug, Clone, Copy)]
pub struct ExplainRequest<'a> {
    /// The detection category recorded in the verdict (`"sqli"`, `"custom"` or `"policy"`).
    pub category: &'a str,
    /// The family/subtype recorded in the verdict (`"tautology"`, `"comment_breakout"`, `"truncated"`, ...).
    pub family: &'a str,
    /// The rule id recorded in the verdict (`"H2-001"`, `"LIMIT-001"`, `"CE-001"`, ...).
    pub rule_id: &'a str,
    /// Where in the request the value was found.
    pub vector: Vector,
    /// The literal parameter/header/cookie name the value was found in; empty when the extractor had no name (a path
    /// segment, the raw body), in which case the sentence falls back to the vector label.
    pub field_name: &'a str,
    /// The inferred meaning of the field (password, username, numeric id, ...).
    pub field_kind: FieldKind,
    /// The request method, e.g. `POST`.
    pub method: &'a str,
    /// The request path, e.g. `/admin/login`.
    pub path: &'a str,
    /// The evidence already recorded by the detector; it is redacted again and capped at 128 bytes.
    pub evidence: &'a str,
    /// The site's stack hint; selects the remediation code example.
    pub stack: Stack,
}

/// A copy-paste remediation example for one stack.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CodeExample {
    /// The example's language tag (`javascript`, `php`, `python`, `java`, `sql`).
    pub language: String,
    /// One short line saying what the example shows.
    pub caption: String,
    /// The example code itself, plain text.
    pub code: String,
}

/// The deterministic explanation of one blocked request (Addendum 6 item 1).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Explanation {
    /// One exact sentence naming the family, vector, literal field name, method and path, followed by the redacted
    /// evidence.
    pub detected: String,
    /// The probable weakness, explicitly stated as an inference from the payload shape and never as proof.
    pub inferred_weakness: String,
    /// What an attacker could do, per family and per endpoint kind (with what the matched path suggests).
    pub attacker_impact: String,
    /// The ordered remediation steps, including the honest virtual-patch-is-not-a-fix line (R-11).
    pub remediation_steps: Vec<String>,
    /// The stack-specific parameterised-query example.
    pub code_example: CodeExample,
    /// The honest line that a virtual patch is not a fix.
    pub virtual_patch_note: String,
}

/// Build the deterministic explanation for one blocked request. Pure and total: any input produces text.
#[must_use]
pub fn explain(request: &ExplainRequest<'_>) -> Explanation {
    let family = classify(request);
    let detected = detected_sentence(request, family);
    let inferred_weakness = inferred_weakness(family);
    let attacker_impact = format!(
        "{} {}",
        family_impact(family),
        endpoint_impact(request.path)
    );
    let mut remediation_steps = vec![family_remediation(family).to_owned()];
    remediation_steps.push(
        "Use parameterised queries for every database call on this endpoint (see the stack example); bind values \
         as parameters and never build SQL by concatenating request data. Validate ORDER BY and LIMIT numbers \
         against an allowlist instead of interpolating them."
            .to_owned(),
    );
    remediation_steps.push(
        "Run the application with a least-privilege database account: no DDL, no FILE or shell privileges, and \
         access only to the schemas the application needs."
            .to_owned(),
    );
    remediation_steps.push(
        "Store password hashes (Argon2id or bcrypt) and compare them in application code; never put a password in \
         the SQL text."
            .to_owned(),
    );
    remediation_steps.push(
        "Return generic error messages to clients and keep database details in server-side logs only."
            .to_owned(),
    );
    remediation_steps.push(
        "Rate-limit and lock out repeated login attempts per account and per client address."
            .to_owned(),
    );
    remediation_steps.push(
        "Validate and length-limit input as defence in depth; validation reduces noise but does not replace \
         parameterisation."
            .to_owned(),
    );
    remediation_steps.push(virtual_patch_note().to_owned());
    let code_example = code_example(request.stack, is_auth_path(request.path));
    Explanation {
        detected,
        inferred_weakness,
        attacker_impact,
        remediation_steps,
        code_example,
        virtual_patch_note: virtual_patch_note().to_owned(),
    }
}

/// The known detection families plus the policy/custom/unknown categories.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Family {
    Tautology,
    CommentBreakout,
    Union,
    Stacked,
    Blind,
    Metadata,
    AuthBypass,
    Evasion,
    GenericSqli,
    PolicyTruncated,
    PolicyContentEncoding,
    PolicyBoundary,
    PolicyOther,
    Custom,
    Unknown,
}

fn classify(request: &ExplainRequest<'_>) -> Family {
    let category = request.category.trim().to_ascii_lowercase();
    let family = request.family.trim().to_ascii_lowercase();
    let rule = request.rule_id.trim().to_ascii_uppercase();
    match category.as_str() {
        "policy" => {
            if family.contains("truncat") || rule.starts_with("LIMIT") {
                Family::PolicyTruncated
            } else if family.contains("encoding") || rule.starts_with("CE") {
                Family::PolicyContentEncoding
            } else if family.contains("boundary") || rule.starts_with("MP") {
                Family::PolicyBoundary
            } else {
                Family::PolicyOther
            }
        }
        "custom" => Family::Custom,
        "sqli" | "" => sqli_family(&family, &rule),
        _ => Family::Unknown,
    }
}

fn sqli_family(family: &str, rule: &str) -> Family {
    if rule.starts_with("H1") {
        return Family::Tautology;
    }
    if rule.starts_with("H2") {
        return Family::CommentBreakout;
    }
    if rule.starts_with("H3") {
        return Family::Union;
    }
    if rule.starts_with("H4") {
        return Family::Stacked;
    }
    if rule.starts_with("H5") {
        return Family::Blind;
    }
    if rule.starts_with("H6") {
        return Family::Metadata;
    }
    if rule.starts_with("H7") {
        return Family::AuthBypass;
    }
    if rule.starts_with("H8") {
        return Family::Evasion;
    }
    if family.contains("tautolog") || family.contains("arithmetic") {
        Family::Tautology
    } else if family.contains("comment") || family.contains("terminator") {
        Family::CommentBreakout
    } else if family.contains("union") || family.contains("order_by") {
        Family::Union
    } else if family.contains("stacked")
        || family.contains("statement")
        || family.contains("file_write")
    {
        Family::Stacked
    } else if family.contains("time")
        || family.contains("blind")
        || family.contains("boolean")
        || family.contains("subselect")
        || family.contains("waitfor")
        || family.contains("function")
    {
        Family::Blind
    } else if family.contains("metadata") || family.contains("schema") {
        Family::Metadata
    } else if family.contains("auth") || family.contains("having") {
        Family::AuthBypass
    } else if family.contains("evasion")
        || family.contains("hex")
        || family.contains("char_")
        || family.contains("concat")
        || family.contains("glued")
        || family.contains("split")
        || family.contains("versioned")
    {
        Family::Evasion
    } else {
        Family::GenericSqli
    }
}

fn family_label(family: Family) -> &'static str {
    match family {
        Family::Tautology => "SQL injection by tautology (an always-true condition)",
        Family::CommentBreakout => "SQL injection by quote break-out with a comment",
        Family::Union => "SQL injection by UNION-based query",
        Family::Stacked => "SQL injection by stacked statements",
        Family::Blind => "SQL injection by a blind or time-based function",
        Family::Metadata => "SQL injection by schema or metadata discovery",
        Family::AuthBypass => "SQL injection by an authentication-bypass idiom",
        Family::Evasion => "SQL injection by an encoding-evasion construct",
        Family::GenericSqli => "SQL injection",
        Family::PolicyTruncated => {
            "Request refused by the inspection policy: the inspection value/body cap was exceeded (truncated)"
        }
        Family::PolicyContentEncoding => {
            "Request refused by the inspection policy: unsupported Content-Encoding"
        }
        Family::PolicyBoundary => {
            "Request refused by the inspection policy: multipart boundary mismatch"
        }
        Family::PolicyOther => "Request refused by the inspection policy",
        Family::Custom => "Request matched the site's custom operator rule",
        Family::Unknown => "Request matched HDD's inspection rules",
    }
}

fn inferred_weakness(family: Family) -> String {
    let inference = "Inference from the payload shape, not proof:";
    let body = match family {
        Family::Tautology => {
            "the backend probably concatenates this field into a WHERE or HAVING condition, so an always-true value \
             defeats the filter it was meant to apply."
        }
        Family::CommentBreakout => {
            "the backend probably wraps this field in SQL quotes and concatenates it, so the quote closes the string \
             literal and the comment discards the rest of the statement."
        }
        Family::Union => {
            "the backend probably concatenates this field into a SELECT whose rows reach the response, so appending a \
             UNION lets the attacker choose which columns are extracted."
        }
        Family::Stacked => {
            "the backend probably concatenates this field and the database driver accepts several statements per \
             call, so a second statement can run with the application's privileges."
        }
        Family::Blind => {
            "the backend probably concatenates this field and reveals timing or error differences that encode \
             boolean answers, so data can be reconstructed without seeing query output."
        }
        Family::Metadata => {
            "the backend probably concatenates this field into SQL and returns schema, version or account metadata \
             to the client."
        }
        Family::AuthBypass => {
            "the backend probably builds its authentication condition from this field, so the condition can be made \
             true without a valid password."
        }
        Family::Evasion => {
            "the backend probably concatenates this field and the database still interprets the character or encoding \
             trick as SQL syntax."
        }
        Family::GenericSqli => {
            "the backend probably concatenates this field into SQL text instead of binding it as a parameter."
        }
        Family::PolicyTruncated
        | Family::PolicyContentEncoding
        | Family::PolicyBoundary
        | Family::PolicyOther => {
            return format!(
                "{inference} the request was refused by HDD's inspection policy before the application saw it, so \
                 no application vulnerability is implied by this evidence alone."
            );
        }
        Family::Custom => {
            "the request matched a site-specific operator rule; confirm what the rule protects before calling the \
             matched shape a vulnerability."
        }
        Family::Unknown => {
            "HDD matched something in this request; review the rule id and the endpoint before drawing a conclusion."
        }
    };
    format!("{inference} {body}")
}

fn family_impact(family: Family) -> &'static str {
    match family {
        Family::Tautology => {
            "An always-true condition defeats the intended filter or authentication check; on a login form the \
             attacker can authenticate without a password."
        }
        Family::CommentBreakout => {
            "The quote closes the string literal and the comment discards the rest of the statement, so the attacker \
             controls the meaning of the query from this field."
        }
        Family::Union => {
            "Data extraction through UNION: the attacker appends SELECTs and reads rows from other tables \
             (credentials, sessions, personal data) through the application's own output."
        }
        Family::Stacked => {
            "Data change through stacked statements: the attacker can run INSERT, UPDATE or DELETE statements, or \
             administrative statements, with the application's database privileges."
        }
        Family::Blind => {
            "Blind exfiltration: the attacker reconstructs data one bit at a time from timing or error differences, \
             without seeing query output."
        }
        Family::Metadata => {
            "Schema disclosure: table, column, version and account metadata can be read, which makes the next \
             extraction step easier."
        }
        Family::AuthBypass => {
            "Authentication bypass: the attacker logs in without a valid password, usually as the first user the \
             query returns (often the administrator)."
        }
        Family::Evasion => {
            "The encoding trick only matters because injection is possible; the database still receives \
             attacker-controlled SQL text."
        }
        Family::GenericSqli => {
            "SQL injection: the attacker can change the meaning of the database query within the application's \
             privileges."
        }
        Family::PolicyTruncated
        | Family::PolicyContentEncoding
        | Family::PolicyBoundary
        | Family::PolicyOther => {
            "No application impact by itself: this is an inspection or encoding policy refusal, not a confirmed \
             vulnerability; the evidence stays an attempt observation."
        }
        Family::Custom => {
            "Impact depends on the target of the operator rule; treat this as an attempt observation and validate \
             the matching endpoint."
        }
        Family::Unknown => {
            "No application impact is proven by this match; treat it as an attempt observation."
        }
    }
}

fn endpoint_impact(path: &str) -> String {
    let lower = path.to_ascii_lowercase();
    let shown = display_path(path);
    if is_auth_path(&lower) {
        format!(
            "The matched path `{shown}` looks like a login or administrator endpoint, so a successful bypass can \
             reach an administrator session."
        )
    } else {
        format!(
            "The matched path `{shown}` is not an authentication endpoint; unless it exposes privileged data, the \
             practical impact is below a login bypass."
        )
    }
}

fn is_auth_path(lower_path: &str) -> bool {
    [
        "/admin",
        "/login",
        "/log-in",
        "/signin",
        "/sign-in",
        "/auth",
        "/administrator",
        "/session",
        "/wp-login",
    ]
    .iter()
    .any(|needle| lower_path.contains(needle))
}

fn family_remediation(family: Family) -> &'static str {
    match family {
        Family::Tautology => {
            "Rebuild the authentication or filter condition with bound parameters; an always-true condition must \
             not be able to complete the query."
        }
        Family::CommentBreakout => {
            "Bind this field as a parameter so quotes and comment markers are data; add a regression test that a \
             quote in this field changes no query structure."
        }
        Family::Union => {
            "Return only the columns the endpoint needs and use a least-privilege account; a UNION payload must fail \
             because the query is fixed."
        }
        Family::Stacked => {
            "Disable multiple statements in the database driver (mysql2 multipleStatements:false, PDO prepared \
             statements, JDBC single-statement execution) and remove DDL and DML grants the endpoint does not need."
        }
        Family::Blind => {
            "Do not return database error text or query timing to clients; add statement timeouts and alert on \
             repeated slow or failing requests."
        }
        Family::Metadata => {
            "Do not expose schema or version metadata; tighten the database account and turn verbose error pages \
             off."
        }
        Family::AuthBypass => {
            "Fix the login query with a prepared statement and compare password hashes in application code; add \
             rate limiting and lockout."
        }
        Family::Evasion => {
            "Decode and normalise input once at the edge and bind it as a parameter; encoding tricks only matter \
             while the value reaches SQL text."
        }
        Family::GenericSqli => {
            "Replace the concatenated query with a parameterised statement and add a regression test for this field."
        }
        Family::PolicyTruncated => {
            "Reduce or paginate the request so it fits the inspection cap; a request that exceeds the cap is refused \
             rather than passed."
        }
        Family::PolicyContentEncoding => {
            "Reject unsupported Content-Encoding values at the edge and decode supported ones before inspection."
        }
        Family::PolicyBoundary => {
            "Reject multipart requests whose body does not match the declared boundary; do not parse them as another \
             form type."
        }
        Family::PolicyOther => {
            "Keep the inspection policy strict and investigate why the client sent a policy-refused request."
        }
        Family::Custom => {
            "Review the operator rule's pattern and confirm the endpoint it protects; fix the underlying issue the \
             rule targets."
        }
        Family::Unknown => {
            "Review the rule id and the endpoint; keep the inspection policy enabled while investigating."
        }
    }
}

fn detected_sentence(request: &ExplainRequest<'_>, family: Family) -> String {
    let method = display_method(request.method);
    let path = display_path(request.path);
    let field = display_field(request);
    let evidence = display_evidence(request.evidence);
    format!(
        "{} in {field} of {method} {path}; matched evidence (redacted): `{evidence}`.",
        family_label(family)
    )
}

/// The field part of the sentence: the literal name when the extractor recorded one, otherwise the vector label
/// (a path segment or a raw body value has no parameter name).
fn display_field(request: &ExplainRequest<'_>) -> String {
    let name = request.field_name.trim();
    if name.is_empty() {
        return vector_label(request.vector).to_owned();
    }
    let cleaned: String = name
        .chars()
        .map(|c| {
            if c == '`' {
                '\''
            } else if c.is_control() {
                ' '
            } else {
                c
            }
        })
        .collect();
    format!(
        "{} `{}`",
        vector_label(request.vector),
        capped(&cleaned, 64)
    )
}

fn vector_label(vector: Vector) -> &'static str {
    match vector {
        Vector::Path => "path segment",
        Vector::Query => "query parameter",
        Vector::FormBody => "form field",
        Vector::JsonBody => "JSON string",
        Vector::MultipartField => "multipart field",
        Vector::MultipartFilename => "multipart file name",
        Vector::Header => "request header",
        Vector::Cookie => "cookie value",
    }
}

/// Redact and cap the evidence again (defence in depth: the detector already redacted it), and strip backticks so
/// the plain-text sentence stays unambiguous when it is rendered.
fn display_evidence(evidence: &str) -> String {
    let redacted = redact(evidence);
    let cleaned: String = redacted
        .chars()
        .map(|c| if c == '`' { '\'' } else { c })
        .collect();
    capped(&cleaned, crate::types::MAX_EVIDENCE_BYTES)
}

fn display_method(method: &str) -> String {
    let trimmed = method.trim();
    if trimmed.is_empty() {
        "REQUEST".to_owned()
    } else {
        capped(trimmed, 16).to_ascii_uppercase()
    }
}

fn display_path(path: &str) -> String {
    let trimmed = path.trim();
    if trimmed.is_empty() {
        "/".to_owned()
    } else {
        capped(trimmed, 256)
    }
}

fn capped(text: &str, max: usize) -> String {
    if text.len() <= max {
        return text.to_owned();
    }
    let mut end = max;
    while end > 0 && !text.is_char_boundary(end) {
        end = end.saturating_sub(1);
    }
    text.get(..end).unwrap_or("").to_owned()
}

fn virtual_patch_note() -> &'static str {
    "A virtual patch is not a fix: the vulnerability stays open until the application code and the database \
     account are patched (R-11)."
}

fn code_example(stack: Stack, auth: bool) -> CodeExample {
    let (language, code, caption) = match (stack, auth) {
        (Stack::Node, true) => (
            "javascript",
            "// Parameterised login query; never concatenate request values.\n\
             const sql = 'SELECT id, password_hash FROM users WHERE username = ? AND active = 1';\n\
             const row = await db.get(sql, [username]);\n\
             const ok = row !== undefined && await verifyPassword(password, row.password_hash);",
            "Node.js (sqlite3/mysql2/pg) parameterised query for a login endpoint (use $1 placeholders for pg).",
        ),
        (Stack::Node, false) => (
            "javascript",
            "// Parameterised lookup; never concatenate request values.\n\
             const sql = 'SELECT id, name FROM items WHERE id = ?';\n\
             const row = await db.get(sql, [id]);",
            "Node.js (sqlite3/mysql2/pg) parameterised query for a data endpoint (use $1 placeholders for pg).",
        ),
        (Stack::Php, true) => (
            "php",
            "<?php\n\
             // Parameterised login query; never concatenate request values.\n\
             $stmt = $pdo->prepare('SELECT id, password_hash FROM users WHERE username = :username AND active = 1');\n\
             $stmt->execute([':username' => $username]);\n\
             $row = $stmt->fetch(PDO::FETCH_ASSOC);",
            "PHP PDO parameterised query for a login endpoint.",
        ),
        (Stack::Php, false) => (
            "php",
            "<?php\n\
             // Parameterised lookup; never concatenate request values.\n\
             $stmt = $pdo->prepare('SELECT id, name FROM items WHERE id = :id');\n\
             $stmt->execute([':id' => $id]);\n\
             $row = $stmt->fetch(PDO::FETCH_ASSOC);",
            "PHP PDO parameterised query for a data endpoint.",
        ),
        (Stack::Python, true) => (
            "python",
            "# Parameterised login query; never concatenate request values.\n\
             # sqlite3 uses ? placeholders; psycopg uses %s placeholders.\n\
             cur.execute(\n\
             \x20   \"SELECT id, password_hash FROM users WHERE username = ? AND active = 1\",\n\
             \x20   (username,),\n\
             )\n\
             row = cur.fetchone()",
            "Python (sqlite3/psycopg) parameterised query for a login endpoint.",
        ),
        (Stack::Python, false) => (
            "python",
            "# Parameterised lookup; never concatenate request values.\n\
             # sqlite3 uses ? placeholders; psycopg uses %s placeholders.\n\
             cur.execute(\"SELECT id, name FROM items WHERE id = ?\", (item_id,))\n\
             row = cur.fetchone()",
            "Python (sqlite3/psycopg) parameterised query for a data endpoint.",
        ),
        (Stack::Java, true) => (
            "java",
            "// Parameterised login query; never concatenate request values.\n\
             PreparedStatement statement = connection.prepareStatement(\n\
             \x20   \"SELECT id, password_hash FROM users WHERE username = ? AND active = 1\");\n\
             statement.setString(1, username);\n\
             ResultSet rows = statement.executeQuery();",
            "Java JDBC PreparedStatement parameterised query for a login endpoint.",
        ),
        (Stack::Java, false) => (
            "java",
            "// Parameterised lookup; never concatenate request values.\n\
             PreparedStatement statement = connection.prepareStatement(\n\
             \x20   \"SELECT id, name FROM items WHERE id = ?\");\n\
             statement.setString(1, itemId);\n\
             ResultSet rows = statement.executeQuery();",
            "Java JDBC PreparedStatement parameterised query for a data endpoint.",
        ),
        (Stack::Other, true) => (
            "sql",
            "-- Bind the value as a parameter; never concatenate it into the SQL text.\n\
             -- login: SELECT id, password_hash FROM users WHERE username = :username AND active = 1;",
            "Generic parameterised-query guidance for a login endpoint (any language).",
        ),
        (Stack::Other, false) => (
            "sql",
            "-- Bind the value as a parameter; never concatenate it into the SQL text.\n\
             -- lookup: SELECT id, name FROM items WHERE id = :id;",
            "Generic parameterised-query guidance for a data endpoint (any language).",
        ),
    };
    CodeExample {
        language: language.to_owned(),
        caption: caption.to_owned(),
        code: code.to_owned(),
    }
}
