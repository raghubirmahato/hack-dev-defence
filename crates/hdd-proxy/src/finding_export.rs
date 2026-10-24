//! Export of one finding as Markdown or JSON (Addendum 6 item 4).
//!
//! The export is built only from the finding record that the deterministic engine already holds (plus the cached AI
//! explanation when the caller attached one): no request body, cookie, token, header value or API key ever reaches it.
//! Markdown sections: What was detected / What an attacker could do / How to fix / Confirm evidence. JSON is the
//! frozen [`crate::api::FindingView`] serialised as-is.

use crate::api::FindingView;
use crate::util;

/// The requested export format of `GET /api/findings/{id}/export`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExportFormat {
    /// A human-readable Markdown document.
    Markdown,
    /// The frozen `FindingView` JSON.
    Json,
}

impl ExportFormat {
    /// Parse the documented `?format=` value (`markdown` default, `json`); `None` for an unsupported value.
    #[must_use]
    pub fn parse(value: Option<&str>) -> Option<Self> {
        match value.map(str::trim) {
            None | Some("") | Some("markdown") | Some("md") => Some(Self::Markdown),
            Some("json") => Some(Self::Json),
            Some(_) => None,
        }
    }

    /// The `Content-Type` of the exported document.
    #[must_use]
    pub fn content_type(self) -> &'static str {
        match self {
            Self::Markdown => "text/markdown; charset=utf-8",
            Self::Json => "application/json; charset=utf-8",
        }
    }

    /// The attachment filename for a finding id.
    #[must_use]
    pub fn filename(self, finding_id: &str) -> String {
        match self {
            Self::Markdown => format!("finding-{finding_id}.md"),
            Self::Json => format!("finding-{finding_id}.json"),
        }
    }
}

/// Render one finding as the requested format. The body is plain text/JSON, never HTML.
#[must_use]
pub fn render(finding: &FindingView, format: ExportFormat) -> String {
    match format {
        ExportFormat::Markdown => render_markdown(finding),
        ExportFormat::Json => render_json(finding),
    }
}

/// The Markdown export with the four documented sections; every value is plain text and safely copy-pasteable.
fn render_markdown(finding: &FindingView) -> String {
    let mut out = String::with_capacity(4_096);
    out.push_str(&format!("# Finding `{}`\n\n", finding.id));
    out.push_str(&format!(
        "- Site: `{}`\n- Request: `{} {}`\n- Vector: `{}`\n- Field: `{}` (kind `{}`)\n- Rule: `{}` (family `{}`, category `{}`)\n- Confidence: `{}`\n- Seen: {} to {}, {} blocked attempt(s)\n- Redacted evidence: `{}`\n\n",
        finding.site,
        finding.method,
        finding.path,
        finding.vector,
        finding.field,
        finding.field_kind,
        finding.rule_id,
        finding.family,
        finding.category,
        finding.confidence,
        finding.first_seen,
        finding.last_seen,
        finding.count,
        escape_markdown_span(&finding.evidence),
    ));
    out.push_str("## What was detected\n\n");
    out.push_str(&format!("{}\n\n", finding.detected.trim()));
    out.push_str("## What an attacker could do\n\n");
    out.push_str(&format!("{}\n\n", finding.attacker_impact.trim()));
    out.push_str("## How to fix\n\n");
    for (index, step) in finding.remediation.steps.iter().enumerate() {
        out.push_str(&format!("{}. {}\n", index.saturating_add(1), step.trim()));
    }
    out.push('\n');
    out.push_str(&format!(
        "Code example ({}): {}\n\n```{}\n{}\n```\n\n",
        finding.remediation.code_example.language,
        finding.remediation.code_example.caption,
        finding.remediation.code_example.language,
        finding.remediation.code_example.code.trim_end(),
    ));
    out.push_str(&format!(
        "> {}\n\n",
        finding.remediation.virtual_patch_note.trim()
    ));
    out.push_str("## Confirm evidence\n\n");
    if finding.confidence == "confirmed" {
        out.push_str(
            "The owner ran the confirm-vulnerability probe and it reported `confirmed_injectable` (inert, read-only \
             requests through the proxy; never a block or ban decision).\n\n",
        );
    } else {
        out.push_str(
            "Only blocked attempts were observed (`attempt_observed`); the confirm-vulnerability probe has not (yet) \
             reported the finding as confirmed.\n\n",
        );
    }
    if let Some(ai) = finding.ai.as_ref() {
        out.push_str("---\n\n");
        out.push_str(&format!(
            "## AI explanation ({}; {}; {})\n\n",
            ai.label, ai.model, ai.generated_at
        ));
        out.push_str(&format!("{}\n\n", ai.summary.trim()));
        if !ai.attacker_impact.is_empty() {
            out.push_str("**Attacker impact**\n\n");
            for item in &ai.attacker_impact {
                out.push_str(&format!("- {}\n", item.trim()));
            }
            out.push('\n');
        }
        if !ai.remediation_steps.is_empty() {
            out.push_str("**Remediation steps**\n\n");
            for (index, item) in ai.remediation_steps.iter().enumerate() {
                out.push_str(&format!("{}. {}\n", index.saturating_add(1), item.trim()));
            }
            out.push('\n');
        }
        if let Some(example) = ai.code_example.as_ref() {
            out.push_str(&format!(
                "```{}\n{}\n```\n\n",
                example.language,
                example.code.trim_end()
            ));
        }
    }
    out.push_str("---\n\nGenerated by Hack Dev Defence from the finding record; no request body, credential or API key is included.\n");
    out
}

/// The JSON export: the frozen `FindingView` serialised as-is (never contains a secret).
fn render_json(finding: &FindingView) -> String {
    match serde_json::to_string_pretty(finding) {
        Ok(json) => json,
        Err(_) => "{}".to_owned(),
    }
}

/// Format one inline Markdown span safely: collapse newlines and escape backtick characters.
fn escape_markdown_span(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    let mut previous_space = false;
    for character in value.chars() {
        let character = if character.is_control() {
            ' '
        } else {
            character
        };
        if character == ' ' {
            if previous_space {
                continue;
            }
            previous_space = true;
        } else {
            previous_space = false;
        }
        match character {
            '`' => out.push_str("\\`"),
            '\\' => out.push_str("\\\\"),
            other => out.push(other),
        }
    }
    util::truncate_utf8(&out, hdd_waf_core::MAX_EVIDENCE_BYTES).to_owned()
}
#[cfg(test)]
mod tests {
    use super::*;
    use crate::api::{AiExplanationView, CodeExampleView, RemediationView};

    fn sample_finding() -> FindingView {
        FindingView {
            id: "0123456789abcdef".to_owned(),
            site: "demo.test".to_owned(),
            method: "POST".to_owned(),
            path: "/admin/login".to_owned(),
            vector: "form_body".to_owned(),
            field: "username".to_owned(),
            field_kind: "username".to_owned(),
            rule_id: "H2-001".to_owned(),
            family: "comment_breakout".to_owned(),
            category: "sqli".to_owned(),
            first_seen: "2026-10-24T00:00:00.000Z".to_owned(),
            last_seen: "2026-10-24T00:00:05.000Z".to_owned(),
            count: 2,
            evidence: "admin' --".to_owned(),
            detected:
                "SQL injection by comment break-out in form field `username` of POST /admin/login"
                    .to_owned(),
            inferred_weakness: "the backend probably concatenates this field into the WHERE clause"
                .to_owned(),
            attacker_impact:
                "An attacker could bypass the login and reach an administrator session.".to_owned(),
            confidence: "attempt_observed".to_owned(),
            remediation: RemediationView {
                steps: vec![
                    "Use parameterised queries.".to_owned(),
                    "Use a least-privilege database account.".to_owned(),
                ],
                code_example: CodeExampleView {
                    language: "javascript".to_owned(),
                    caption: "parameterised statement".to_owned(),
                    code: "db.prepare('SELECT * FROM users WHERE username = ?').get(username);"
                        .to_owned(),
                },
                virtual_patch_note:
                    "A virtual patch is not a fix: the vulnerable code is still there.".to_owned(),
            },
            stack: "node".to_owned(),
            ai: None,
        }
    }

    #[test]
    fn markdown_export_has_the_documented_sections_and_no_markup_breakage() {
        let finding = sample_finding();
        let markdown = render(&finding, ExportFormat::Markdown);
        for heading in [
            "# Finding",
            "## What was detected",
            "## What an attacker could do",
            "## How to fix",
            "## Confirm evidence",
        ] {
            assert!(markdown.contains(heading), "missing {heading}");
        }
        assert!(markdown.contains("```javascript"));
        assert!(markdown.contains("attempt_observed"));
        assert!(!markdown.contains("<script>"));
        assert!(!markdown.contains("api_key"));
    }

    #[test]
    fn markdown_escapes_backticks_and_control_characters() {
        let mut finding = sample_finding();
        finding.evidence = "admin`\n' --".to_owned();
        let markdown = render(&finding, ExportFormat::Markdown);
        // The backtick is escaped and the control character collapsed to a space, so the evidence stays on one line
        // inside its inline code span.
        assert!(markdown.contains("admin\\`"), "markdown: {markdown}");
        let evidence_line = markdown
            .lines()
            .find(|line| line.contains("Redacted evidence"))
            .expect("the redacted evidence line");
        assert!(
            evidence_line.contains("admin\\` ' --"),
            "evidence line: {evidence_line}"
        );
        assert_eq!(
            markdown
                .lines()
                .filter(|line| line.contains("Redacted evidence"))
                .count(),
            1,
            "the evidence must not introduce extra lines"
        );
    }

    #[test]
    fn json_export_is_the_frozen_view() {
        let finding = sample_finding();
        let json = render(&finding, ExportFormat::Json);
        let parsed: serde_json::Value = serde_json::from_str(&json).expect("valid JSON");
        assert_eq!(
            parsed.get("id").and_then(serde_json::Value::as_str),
            Some("0123456789abcdef")
        );
        assert_eq!(
            parsed
                .get("remediation")
                .and_then(|value| value.get("code_example"))
                .and_then(|value| value.get("language"))
                .and_then(serde_json::Value::as_str),
            Some("javascript")
        );
        assert!(parsed.get("ai").is_some());
    }

    #[test]
    fn ai_text_is_included_with_its_label_and_never_as_markup() {
        let mut finding = sample_finding();
        finding.ai = Some(AiExplanationView {
            summary: "Model summary: <script>alert(1)</script>".to_owned(),
            attacker_impact: vec!["impact".to_owned()],
            remediation_steps: vec!["step".to_owned()],
            code_example: None,
            generated_at: "2026-10-24T00:00:00.000Z".to_owned(),
            model: "deepseek-flash".to_owned(),
            label: "AI-generated, verify before use".to_owned(),
        });
        let markdown = render(&finding, ExportFormat::Markdown);
        assert!(markdown.contains("AI-generated, verify before use"));
        assert!(
            markdown.contains("<script>alert(1)</script>"),
            "kept as escaped plain text"
        );
        let json = render(&finding, ExportFormat::Json);
        let parsed: serde_json::Value = serde_json::from_str(&json).expect("valid JSON");
        assert_eq!(
            parsed
                .get("ai")
                .and_then(|value| value.get("label"))
                .and_then(serde_json::Value::as_str),
            Some("AI-generated, verify before use")
        );
    }

    #[test]
    fn format_parsing_and_filenames() {
        assert_eq!(ExportFormat::parse(None), Some(ExportFormat::Markdown));
        assert_eq!(ExportFormat::parse(Some("json")), Some(ExportFormat::Json));
        assert_eq!(
            ExportFormat::parse(Some("md")),
            Some(ExportFormat::Markdown)
        );
        assert_eq!(ExportFormat::parse(Some("xml")), None);
        assert_eq!(ExportFormat::Markdown.filename("abc"), "finding-abc.md");
        assert_eq!(ExportFormat::Json.filename("abc"), "finding-abc.json");
    }
}
