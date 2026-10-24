//! `claims-lint` (T-0005 step 3, section 4): scans documentation, templates and catalogs for forbidden claim phrases.
//!
//! The configuration lives in `docs/claims-lint.toml`. Quotations of forbidden phrases (the claims dictionary, the
//! specification itself) are allowed only inside a block delimited by `claims-lint:allow-start` and
//! `claims-lint:allow-end` (written as an HTML comment in Markdown), or in a path listed under `exclude`.

use std::collections::BTreeSet;
use std::path::Path;

use serde::Deserialize;

use crate::util::{Finding, Result, glob_match, read_text, rel, walk_files};

/// A forbidden phrase, optionally excused by qualifying words on the same line.
#[derive(Debug, Deserialize, Clone)]
pub struct Phrase {
    /// The phrase (matched case-insensitively as a substring).
    pub text: String,
    /// When set, the phrase is allowed on a line that also contains one of these words (an *unqualified* claim is what is forbidden).
    #[serde(default)]
    pub unless_line_contains: Vec<String>,
}

/// A claim word that must be accompanied by a scope signal, but only on the public-copy paths it lists.
#[derive(Debug, Deserialize, Clone)]
pub struct ContextRule {
    /// Claim words, matched as whole tokens case-insensitively (for example `protect`, `protects`, `protection`).
    pub words: Vec<String>,
    /// Scope terms; any one of them qualifies a claim. A multi-word term is matched as consecutive words.
    pub scope: Vec<String>,
    /// Maximum number of words between the claim word and the first word of the scope term.
    #[serde(default = "default_within")]
    pub within: usize,
    /// Path globs (repository-relative, `*` and `**`) where the rule applies.
    pub paths: Vec<String>,
}

/// Default word window of a context rule (T-0019 step 4: 12 words).
fn default_within() -> usize {
    12
}

/// Parsed `docs/claims-lint.toml`.
#[derive(Debug, Deserialize, Clone)]
pub struct Config {
    /// Forbidden phrases.
    pub phrases: Vec<Phrase>,
    /// Claim words that need a scope signal, on public-copy paths only (T-0019 step 4).
    #[serde(default)]
    pub context: Vec<ContextRule>,
    /// Path globs (repository-relative, `*` and `**`) that are scanned.
    pub include: Vec<String>,
    /// Path globs never scanned (verbatim specification, the lint's own configuration).
    #[serde(default)]
    pub exclude: Vec<String>,
    /// File extensions scanned (without dot).
    pub extensions: Vec<String>,
}

/// Marker that opens an allowlisted quotation block.
pub const ALLOW_START: &str = "claims-lint:allow-start";
/// Marker that closes an allowlisted quotation block.
pub const ALLOW_END: &str = "claims-lint:allow-end";

/// True when `line` is a marker line: a comment (`<!-- ... -->`, `# ...`, `// ...`, `{# ... #}`) that contains the marker.
/// A sentence that merely mentions the marker (in a table, in prose) is not a marker.
pub fn is_marker(line: &str, marker: &str) -> bool {
    let t = line.trim_start();
    line.contains(marker)
        && (t.starts_with("<!--")
            || t.starts_with('#')
            || t.starts_with("//")
            || t.starts_with("{#"))
}

/// Load the configuration.
pub fn load_config(root: &Path) -> Result<Config> {
    let text = read_text(&root.join("docs").join("claims-lint.toml"))?;
    Ok(toml::from_str(&text)?)
}

/// Scan one text. `name` is used for locations.
pub fn scan_text(cfg: &Config, name: &str, text: &str) -> Vec<Finding> {
    let mut findings = Vec::new();
    let mut allowed_since: Option<usize> = None;
    for (n, line) in text.lines().enumerate() {
        let lineno = n + 1;
        if is_marker(line, ALLOW_START) {
            if allowed_since.is_some() {
                findings.push(Finding::new(
                    "claims",
                    format!("{name}:{lineno}"),
                    "nested allow-start",
                ));
            }
            allowed_since = Some(lineno);
            continue;
        }
        if is_marker(line, ALLOW_END) {
            if allowed_since.is_none() {
                findings.push(Finding::new(
                    "claims",
                    format!("{name}:{lineno}"),
                    "allow-end without allow-start",
                ));
            }
            allowed_since = None;
            continue;
        }
        if allowed_since.is_some() {
            continue;
        }
        let lower = line.to_lowercase();
        for p in &cfg.phrases {
            let needle = p.text.to_lowercase();
            if !lower.contains(&needle) {
                continue;
            }
            if p.unless_line_contains
                .iter()
                .any(|w| lower.contains(&w.to_lowercase()))
            {
                continue;
            }
            findings.push(Finding::new(
                "claims",
                format!("{name}:{lineno}"),
                format!("forbidden phrase \"{}\" (section 4.2)", p.text),
            ));
        }
        for rule in &cfg.context {
            if rule.paths.iter().any(|g| glob_match(g, name)) {
                findings.extend(context_rule_findings(rule, name, lineno, line));
            }
        }
    }
    if let Some(start) = allowed_since {
        findings.push(Finding::new(
            "claims",
            format!("{name}:{start}"),
            "allow-start without allow-end",
        ));
    }
    findings
}

/// Lower-cased word tokens of a line: letters, digits and hyphen; punctuation separates words.
fn line_tokens(line: &str) -> Vec<String> {
    line.split(|c: char| !(c.is_alphanumeric() || c == '-'))
        .filter(|t| !t.is_empty())
        .map(str::to_lowercase)
        .collect()
}

/// Whether `phrase` occurs in `words` starting at `start`.
fn phrase_matches(words: &[String], start: usize, phrase: &[String]) -> bool {
    words
        .get(start..start.saturating_add(phrase.len()))
        .is_some_and(|window| window == phrase)
}

/// Findings of one context rule on one line: an occurrence of a claim word with no scope term within the word window.
fn context_rule_findings(
    rule: &ContextRule,
    name: &str,
    lineno: usize,
    line: &str,
) -> Vec<Finding> {
    let words = line_tokens(line);
    if words.is_empty() {
        return Vec::new();
    }
    let scopes: Vec<Vec<String>> = rule
        .scope
        .iter()
        .map(|term| line_tokens(term))
        .filter(|term| !term.is_empty())
        .collect();
    let claims: Vec<Vec<String>> = rule
        .words
        .iter()
        .map(|word| line_tokens(word))
        .filter(|word| word.len() == 1)
        .collect();
    let mut unscoped: BTreeSet<String> = BTreeSet::new();
    for claim in &claims {
        let Some(claim_word) = claim.first() else {
            continue;
        };
        for (claim_at, token) in words.iter().enumerate() {
            if token != claim_word {
                continue;
            }
            let qualified = scopes.iter().any(|scope| {
                (0..words.len()).any(|scope_at| {
                    phrase_matches(&words, scope_at, scope)
                        && scope_at.abs_diff(claim_at) <= rule.within
                })
            });
            if !qualified {
                unscoped.insert(claim_word.clone());
            }
        }
    }
    unscoped
        .into_iter()
        .map(|word| {
            Finding::new(
                "claims",
                format!("{name}:{lineno}"),
                format!(
                    "the claim word \"{word}\" has no scope term within {} words on this line; say what was tested, measured, scoped or is a known limitation, or remove the claim (claims context rule)",
                    rule.within
                ),
            )
        })
        .collect()
}

/// True when the file at `relpath` should be scanned under `cfg`.
pub fn is_scanned(cfg: &Config, relpath: &str) -> bool {
    let ext_ok = relpath
        .rsplit_once('.')
        .is_some_and(|(_, e)| cfg.extensions.iter().any(|x| x.eq_ignore_ascii_case(e)));
    ext_ok
        && cfg.include.iter().any(|g| glob_match(g, relpath))
        && !cfg.exclude.iter().any(|g| glob_match(g, relpath))
}

/// Scan the repository. Returns the findings and a one-line summary.
pub fn run(root: &Path) -> Result<(Vec<Finding>, String)> {
    let cfg = load_config(root)?;
    let mut findings = Vec::new();
    let mut scanned = 0usize;
    for f in walk_files(root) {
        let r = rel(root, &f);
        if !is_scanned(&cfg, &r) {
            continue;
        }
        let text = match read_text(&f) {
            Ok(t) => t,
            // fail closed: a file that cannot be read as UTF-8 text has not been checked
            Err(e) => {
                findings.push(Finding::new(
                    "claims",
                    r,
                    format!("could not be read as text, so it was not checked: {}", e.0),
                ));
                continue;
            }
        };
        scanned += 1;
        findings.extend(scan_text(&cfg, &r, &text));
    }
    let summary = format!(
        "claims-lint: scanned {scanned} files with {} phrases and {} context rules",
        cfg.phrases.len(),
        cfg.context.len()
    );
    Ok((findings, summary))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg() -> Config {
        Config {
            phrases: vec![
                Phrase {
                    text: "unhackable".into(),
                    unless_line_contains: vec![],
                },
                Phrase {
                    text: "complete protection".into(),
                    unless_line_contains: vec![],
                },
                Phrase {
                    text: "DDoS protection".into(),
                    unless_line_contains: vec!["upstream".into(), "does not".into()],
                },
            ],
            context: vec![],
            include: vec![
                "docs/**".into(),
                "README.md".into(),
                "crates/**/templates/**".into(),
            ],
            exclude: vec!["docs/spec/**".into()],
            extensions: vec!["md".into(), "html".into()],
        }
    }

    #[test]
    fn seeded_forbidden_phrase_in_a_template_fails() {
        let f = scan_text(
            &cfg(),
            "crates/hdd-web/templates/landing.html",
            "<p>Your site is Unhackable now.</p>\n",
        );
        assert_eq!(f.len(), 1);
        assert!(f[0].location.ends_with(":1"));
        assert!(f[0].message.contains("unhackable"));
    }

    #[test]
    fn approved_patterns_of_section_4_3_pass() {
        let ok = "Layered protection with a published coverage map (S-134): what is covered, how each item is tested, and what is not covered.\n\
                  Detects and blocks SQL-injection patterns in requests and bans the sending IP. Tested against N payloads in our lab (AC-39); novel techniques can evade signature-based detection.\n\
                  Absorbs application-layer floods within your plan's limits. Volumetric floods larger than the server uplink need an upstream scrubbing provider (see DDoS readiness).\n\
                  Strict defaults, listed in the settings page. Review them.\n\
                  Active while HDD is running. On a local install, protection stops when you stop HDD or the computer sleeps.\n";
        assert!(scan_text(&cfg(), "README.md", ok).is_empty());
    }

    #[test]
    fn qualified_ddos_protection_passes_and_unqualified_fails() {
        assert!(
            scan_text(
                &cfg(),
                "README.md",
                "DDoS protection needs an upstream provider.\n"
            )
            .is_empty()
        );
        assert_eq!(
            scan_text(&cfg(), "README.md", "We offer DDoS protection.\n").len(),
            1
        );
    }

    #[test]
    fn allow_block_excuses_quotations_and_unbalanced_blocks_fail() {
        let quoted = "<!-- claims-lint:allow-start -->\nThe word unhackable is forbidden.\n<!-- claims-lint:allow-end -->\nOutside: complete protection\n";
        let f = scan_text(&cfg(), "docs/x.md", quoted);
        assert_eq!(f.len(), 1);
        assert!(f[0].location.ends_with(":4"));
        assert_eq!(
            scan_text(&cfg(), "docs/x.md", "<!-- claims-lint:allow-start -->\nx\n").len(),
            1
        );
        assert_eq!(
            scan_text(&cfg(), "docs/x.md", "x\n<!-- claims-lint:allow-end -->\n").len(),
            1
        );
    }

    #[test]
    fn a_line_that_merely_mentions_the_marker_does_not_open_a_block() {
        let doc = "| claims-lint | quote only inside `claims-lint:allow-start` blocks |
This is unhackable.
";
        let f = scan_text(&cfg(), "docs/x.md", doc);
        assert_eq!(f.len(), 1, "{f:?}");
        assert!(f[0].location.ends_with(":2"));
        assert!(is_marker("<!-- claims-lint:allow-start -->", ALLOW_START));
        assert!(is_marker("# claims-lint:allow-end", ALLOW_END));
        assert!(is_marker("  // claims-lint:allow-start", ALLOW_START));
        assert!(!is_marker(
            "Use claims-lint:allow-start to quote.",
            ALLOW_START
        ));
    }

    #[test]
    fn the_shipped_configuration_does_not_excuse_the_phrase_by_a_mere_upstream_mention() {
        let cfg: Config = toml::from_str(include_str!("../../../docs/claims-lint.toml"))
            .expect("shipped config parses");
        let hits = |line: &str| {
            scan_text(
                &cfg,
                "docs/x.md",
                &format!(
                    "{line}
"
                ),
            )
            .len()
        };
        assert_eq!(
            hits("We offer DDoS protection, backed by an upstream provider."),
            1
        );
        assert_eq!(hits("DDoS protection is included."), 1);
        assert_eq!(
            hits(
                "HDD does not provide DDoS protection; volumetric floods need an upstream provider."
            ),
            0
        );
        assert_eq!(
            hits("Volumetric DDoS protection requires an upstream scrubbing provider."),
            0
        );
        // every phrase of section 4.2 is configured
        for phrase in [
            "unhackable",
            "cannot be bypassed",
            "100% secure",
            "military-grade",
            "AI-powered",
            "absolute protection",
            "impossible to bypass",
            "world-class",
        ] {
            assert_eq!(hits(&format!("This is {phrase}.")), 1, "{phrase}");
        }
    }

    #[test]
    fn scope_follows_include_exclude_and_extension() {
        let c = cfg();
        assert!(is_scanned(&c, "docs/ENV.md"));
        assert!(is_scanned(&c, "crates/hdd-web/templates/a.html"));
        assert!(!is_scanned(&c, "docs/spec/A1.md"));
        assert!(!is_scanned(&c, "docs/data.bin"));
        assert!(!is_scanned(&c, "crates/hdd-web/src/main.rs"));
    }

    // ------------------------------------------------------------------------------------ context rules (T-0019)

    /// One row of `docs/claims-fixtures.toml`.
    #[derive(Deserialize)]
    struct Fixture {
        /// The sentence to scan.
        sentence: String,
        /// The repository path the sentence would live at.
        path: String,
        /// `pass` or `fail`.
        expect: String,
    }

    /// `docs/claims-fixtures.toml`: the fixture table.
    #[derive(Deserialize)]
    struct FixtureFile {
        /// The rows.
        fixture: Vec<Fixture>,
    }

    /// The shipped configuration.
    fn shipped() -> Config {
        toml::from_str(include_str!("../../../docs/claims-lint.toml"))
            .expect("shipped config parses")
    }

    #[test]
    fn context_fixtures_hold_under_the_shipped_configuration() {
        let cfg = shipped();
        let file: FixtureFile = toml::from_str(include_str!("../../../docs/claims-fixtures.toml"))
            .expect("fixture table parses");
        let mut passing = 0usize;
        let mut failing = 0usize;
        for f in &file.fixture {
            let findings = scan_text(&cfg, &f.path, &format!("{}\n", f.sentence));
            match f.expect.as_str() {
                "pass" => {
                    assert!(
                        findings.is_empty(),
                        "\"{}\" at {} should pass but found {findings:?}",
                        f.sentence,
                        f.path
                    );
                    passing += 1;
                }
                "fail" => {
                    assert!(
                        !findings.is_empty(),
                        "\"{}\" at {} should fail",
                        f.sentence,
                        f.path
                    );
                    failing += 1;
                }
                other => panic!("unknown `expect = {other}` in the fixture table"),
            }
        }
        assert!(
            passing >= 8 && failing >= 8,
            "the fixture table needs at least eight passing and eight failing rows, has {passing} and {failing}"
        );
    }

    #[test]
    fn context_window_is_twelve_words_not_thirteen() {
        let cfg = shipped();
        let pass = format!("protects{} tested\n", " word".repeat(11));
        // tokens: protects 0, eleven words 1..=11, tested 12 -> distance 12
        assert!(
            scan_text(&cfg, "docs/site/window.md", &pass).is_empty(),
            "distance 12 must pass"
        );
        let fail = format!("protects{} tested\n", " word".repeat(12));
        // tokens: protects 0, twelve words 1..=12, tested 13 -> distance 13
        let findings = scan_text(&cfg, "docs/site/window.md", &fail);
        assert_eq!(findings.len(), 1, "distance 13 must fail: {findings:?}");
        assert!(findings[0].message.contains("12"), "{findings:?}");
    }

    #[test]
    fn a_context_rule_never_fires_outside_its_paths() {
        let cfg = shipped();
        let sentence = "We protect your site.\n";
        assert_eq!(scan_text(&cfg, "docs/site/index.md", sentence).len(), 1);
        assert_eq!(
            scan_text(&cfg, "crates/hdd-web/templates/a.html", sentence).len(),
            1
        );
        assert!(scan_text(&cfg, "docs/guide.md", sentence).is_empty());
        assert!(scan_text(&cfg, "docs/UX/CONTENT.md", sentence).is_empty());
        assert!(scan_text(&cfg, "crates/hdd-web/src/main.rs", sentence).is_empty());
    }

    #[test]
    fn context_rules_keep_the_phrase_rules_and_the_markers() {
        let cfg = shipped();
        let quoted = "<!-- claims-lint:allow-start -->\nWe protect your site.\n<!-- claims-lint:allow-end -->\n";
        assert!(
            scan_text(&cfg, "docs/site/index.md", quoted).is_empty(),
            "the allow markers must still excuse a line"
        );
        let outside = "<!-- claims-lint:allow-start -->\nWithin scope: tested.\n<!-- claims-lint:allow-end -->\nWe protect your site.\n";
        let findings = scan_text(&cfg, "docs/site/index.md", outside);
        assert_eq!(findings.len(), 1, "{findings:?}");
        assert!(findings[0].location.ends_with(":4"), "{findings:?}");
        // the phrase rules still fire, and a context rule does not replace them
        let phrase = scan_text(&cfg, "docs/site/index.md", "This is unhackable.\n");
        assert_eq!(phrase.len(), 1, "{phrase:?}");
        assert!(phrase[0].message.contains("unhackable"), "{phrase:?}");
    }

    #[test]
    fn the_shipped_configuration_declares_a_context_rule_with_its_paths() {
        let cfg = shipped();
        assert!(!cfg.context.is_empty(), "no [[context]] rule is configured");
        let rule = cfg.context.first().expect("a context rule");
        assert!(rule.words.iter().any(|w| w == "protects"), "{rule:?}");
        assert!(rule.scope.iter().any(|s| s == "tested"), "{rule:?}");
        assert_eq!(rule.within, 12);
        for expected in ["docs/site/**", "crates/**/templates/**", "i18n/en/**"] {
            assert!(
                rule.paths.iter().any(|p| p == expected),
                "missing context path {expected}"
            );
        }
    }

    #[test]
    fn context_scope_terms_are_whole_phrases() {
        let cfg = shipped();
        // `test` alone is not a scope term, and `proxied` qualifies the word it follows.
        assert_eq!(
            scan_text(&cfg, "docs/site/x.md", "We protect every site contest.\n").len(),
            1
        );
        assert!(
            scan_text(
                &cfg,
                "i18n/en/copy-deck.ftl",
                "HDD answers DNS for your domain and protects every proxied name.\n"
            )
            .is_empty()
        );
    }
}
