//! SQL-injection detection (C4.4 to C4.8): normalise every extracted value, tokenize it, match the hard families
//! H1 to H8, and apply the C4.6 field-kind policy plus the C4.9 prose false-positive controls.
//!
//! [`inspect`] is the only public entry point. It is pure, panic-free and linear in the size of the inspected input.

use std::cmp::Ordering;

use crate::custom::{intern_rule_id, matched_action};
use crate::evidence::{from_value, redact};
use crate::extract::{Extraction, Value, extract};
use crate::field_kind::infer;
use crate::normalize::{Normalized, normalize_counted};
use crate::tokenize::{Token, TokenKind, tokenize};
use crate::types::{
    Action, FieldKind, INSPECT_BODY_CAP, InspectInput, SiteSettings, Strictness, Vector, Verdict,
};

/// The hard rule families of C4.5 plus the "other" bucket for cheap heuristic hits.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Family {
    H1,
    H2,
    H3,
    H4,
    H5,
    H6,
    H7,
    H8,
}

/// One family match before the field-kind policy decides whether it blocks or only scores.
#[derive(Debug, Clone)]
struct Hit {
    family: Family,
    subtype: &'static str,
    rule_id: &'static str,
    score: u32,
    /// Byte index of the match in the normalised text (used for the evidence window).
    at: usize,
    /// A quote (or, for a comparison tautology, an unbalanced closing parenthesis) precedes the shape.
    breakout: bool,
    /// An identifier or number immediately precedes the quote (H2 in search-like fields).
    after_identifier: bool,
    /// The shape includes an operator comparison rather than a bare literal.
    comparison: bool,
    /// The comment is `#` followed by a digit (`l'#1`), the numbered-prose soft case of C4.5 H2.
    hash_numbered: bool,
    /// The connector is preceded by a numeric literal (numeric-context injection, review R1-5).
    numeric_context: bool,
    /// A closing comment/terminator or a statement keyword follows the shape: a bare literal is hard then (R1-5).
    strong: bool,
}

/// What the policy says about a hit.
enum Decision {
    /// Block the request.
    Hard,
    /// Do not block; remember the soft score (C4.7).
    Soft(u32),
}

/// Everything the token scan needs about one normalised value.
struct Scan<'a> {
    normalized: &'a Normalized,
    text: &'a str,
    tokens: Vec<Token>,
    /// For every quote token, the next quote token of the same kind (local operand pairing; see `operand`).
    next_quote: Vec<Option<usize>>,
    /// For every token index, whether the quote there is an unmatched break-out (precomputed, linear: review R1-2).
    quote_breakouts: Vec<bool>,
    /// Whether at least one comment or statement terminator exists at or after each token index (R1-5 `strong`).
    terminator_after: Vec<bool>,
    /// Whether the value contains a statement keyword (select/union/...; R1-5 `strong`).
    has_statement_keyword: bool,
    /// Whether the first significant token of the value is a number (numeric-context blind payloads, R1-5).
    starts_numeric: bool,
    /// Whether the value contains a comparison operator anywhere (R1-5 blind function shapes).
    has_comparison_operator: bool,
    /// Index of the first quote token, for O(1) `quote_anywhere_before`.
    first_quote: Option<usize>,
    /// Whether the value contains a connector or an SQL word, for O(1) `sql_context`.
    has_sql_or_connector: bool,
    /// Whether the value contains any SQL-ish word at all (used by the H6 metadata gate).
    has_sql_words: bool,
}

/// A literal operand of a comparison.
#[derive(Debug, Clone)]
struct Lit {
    kind: LitKind,
    text: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum LitKind {
    Num,
    Str,
    Word,
}

/// A parsed predicate after a boolean connector.
#[derive(Debug, Clone)]
struct Predicate {
    truth: Option<bool>,
    comparison: bool,
    uses_like: bool,
    identifier_operand: bool,
}

/// How a connector is preceded by a breakout context.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Breakout {
    None,
    Quote,
    Paren,
}

/// The detected result for one value.
struct Outcome {
    hard: Option<Hit>,
    soft: u32,
}

/// Inspect one request and return the verdict the proxy acts on.
///
/// The function is pure, never panics and runs in time linear in the size of the request vectors (R-09, R-29).
#[must_use]
pub fn inspect(input: &InspectInput<'_>, settings: &SiteSettings) -> Verdict {
    if let Some(verdict) = attack_tool_verdict(input) {
        return verdict;
    }
    let mut ops = 0u64;
    let mut truncated = false;
    let budget = work_budget(input);
    analyze(input, settings, &mut ops, &mut truncated, budget)
}

/// Inspect one request and return the verdict plus the number of work units spent (test instrumentation for the
/// linear-time obligation; not part of the frozen public API).
#[cfg(test)]
pub(crate) fn inspect_counted(input: &InspectInput<'_>, settings: &SiteSettings) -> (Verdict, u64) {
    let mut ops = 0u64;
    let mut truncated = false;
    let budget = work_budget(input);
    let verdict = analyze(input, settings, &mut ops, &mut truncated, budget);
    (verdict, ops)
}

/// The work budget of one request: linear in the inspected bytes with a generous constant. Exceeding it is treated
/// as a truncation block, never as a fail-open (review R1-2).
#[cfg(test)]
pub(crate) fn inspect_with_budget(
    input: &InspectInput<'_>,
    settings: &SiteSettings,
    budget: u64,
) -> Verdict {
    let mut ops = 0u64;
    let mut truncated = false;
    analyze(input, settings, &mut ops, &mut truncated, budget)
}

/// User-Agent fragments of well-known offensive scanners and exploitation tools (lower case). Ordinary clients such as
/// `curl`, `python-requests` or a browser are deliberately not listed: they are judged by what they send, not by name.
const ATTACK_TOOLS: &[&str] = &[
    "sqlmap",
    "nikto",
    "acunetix",
    "netsparker",
    "nessus",
    "openvas",
    "havij",
    "w3af",
    "wpscan",
    "dirbuster",
    "gobuster",
    "feroxbuster",
    "wfuzz",
    "ffuf",
    "hydra",
    "masscan",
    "zgrab",
    "nuclei",
    "arachni",
    "skipfish",
    "sqlninja",
    "commix",
    "jaeles",
    "burpcollaborator",
    "appscan",
    "webinspect",
    "qualys",
    "grabber",
    "whatweb",
];

/// R-24: a request that names a known attack tool in its `User-Agent` is refused as a policy block with the tool as the
/// subtype evidence. The header is client-controlled, so this only stops tools that announce themselves; the SQL
/// injection rules still judge everything else by content.
fn attack_tool_verdict(input: &InspectInput<'_>) -> Option<Verdict> {
    for (name, value) in input.headers {
        if !name.eq_ignore_ascii_case("user-agent") {
            continue;
        }
        let lower = value.to_ascii_lowercase();
        let tool = ATTACK_TOOLS.iter().find(|tool| lower.contains(**tool))?;
        let evidence: String = value.chars().take(128).collect();
        return Some(Verdict::block(
            "policy",
            "attack_tool",
            "T1-001",
            Vector::Header,
            "User-Agent",
            FieldKind::Header,
            format!("{tool}: {evidence}"),
            90,
        ));
    }
    None
}

fn inspected_bytes(input: &InspectInput<'_>) -> u64 {
    let mut total = input
        .path
        .len()
        .saturating_add(input.query.map(str::len).unwrap_or(0));
    total = total.saturating_add(input.body.len().min(INSPECT_BODY_CAP));
    for (name, value) in input.headers {
        total = total.saturating_add(name.len()).saturating_add(value.len());
    }
    total as u64
}

fn work_budget(input: &InspectInput<'_>) -> u64 {
    inspected_bytes(input)
        .saturating_mul(128)
        .saturating_add(1 << 20)
}

/// A request-level policy block (category `policy`): a limit, an unsupported encoding or a parser mismatch.
fn policy_block(
    subtype: &'static str,
    rule_id: &'static str,
    vector: Vector,
    field: &str,
    kind: FieldKind,
    evidence: impl Into<String>,
    truncated: bool,
) -> Verdict {
    let mut verdict = Verdict::block(
        "policy",
        subtype,
        rule_id,
        vector,
        field.to_owned(),
        kind,
        evidence,
        100,
    );
    verdict.truncated = truncated;
    verdict
}

fn truncated_block(truncated: bool, reason: &str) -> Verdict {
    policy_block(
        "truncated",
        "LIMIT-001",
        Vector::FormBody,
        "request",
        FieldKind::Unknown,
        redact(reason),
        truncated,
    )
}

fn content_encoding_block(value: &str) -> Verdict {
    policy_block(
        "unsupported_content_encoding",
        "CE-001",
        Vector::Header,
        "Content-Encoding",
        FieldKind::Header,
        redact(value),
        false,
    )
}

fn boundary_mismatch_block(body: &[u8], truncated: bool) -> Verdict {
    let evidence = format!(
        "multipart boundary in Content-Type not found in a {} byte body",
        body.len()
    );
    policy_block(
        "boundary_mismatch",
        "MP-001",
        Vector::FormBody,
        "request",
        FieldKind::Unknown,
        redact(&evidence),
        truncated,
    )
}

/// Classify a request `Content-Encoding`: `None` when absent/identity, the refusal verdict when unsupported.
fn unsupported_content_encoding(input: &InspectInput<'_>) -> Option<Verdict> {
    for (name, value) in input.headers {
        if name.trim().eq_ignore_ascii_case("content-encoding") {
            let normalised = value.trim().to_ascii_lowercase();
            if !normalised.is_empty() && normalised != "identity" {
                return Some(content_encoding_block(value));
            }
        }
    }
    None
}

fn analyze(
    input: &InspectInput<'_>,
    settings: &SiteSettings,
    ops: &mut u64,
    truncated: &mut bool,
    budget: u64,
) -> Verdict {
    // A Content-Encoding we do not decode must be refused, not inspected as raw bytes and forwarded (review R1-4).
    if let Some(verdict) = unsupported_content_encoding(input) {
        return verdict;
    }
    let extraction = extract(input);
    *truncated |= extraction.truncated;
    if extraction.limit_exceeded || extraction.truncated {
        return truncated_block(*truncated, "inspection value/body cap reached (truncated)");
    }
    if extraction.boundary_mismatch {
        return boundary_mismatch_block(input.body, *truncated);
    }
    inspect_values(&extraction, settings, ops, truncated, budget)
}

fn inspect_values(
    extraction: &Extraction,
    settings: &SiteSettings,
    ops: &mut u64,
    truncated: &mut bool,
    budget: u64,
) -> Verdict {
    let mut best_soft = 0u32;
    for value in &extraction.values {
        let kind = infer(&value.field, value.vector, &settings.field_hints);
        let normalized = normalize_counted(&value.text, value.plus_as_space, ops);
        *truncated |= normalized.flags.truncated;
        if *ops > budget {
            return truncated_block(*truncated, "inspection work budget exceeded (truncated)");
        }

        let mut allow_override = false;
        for rule in &settings.extra_rules {
            match matched_action(rule, value.vector, &normalized) {
                Some(Action::Block) => {
                    let rule_id = intern_rule_id(&rule.id);
                    return block_verdict(
                        "custom",
                        "custom",
                        rule_id,
                        value,
                        kind,
                        &normalized,
                        0,
                        100,
                        *truncated,
                    );
                }
                Some(Action::Allow) => {
                    allow_override = true;
                    break;
                }
                None => {}
            }
        }
        if allow_override {
            continue;
        }

        let outcome = detect_value(&normalized, kind, settings.strictness, ops);
        best_soft = best_soft.max(outcome.soft);
        if let Some(hit) = outcome.hard {
            return block_verdict(
                "sqli",
                hit.subtype,
                hit.rule_id,
                value,
                kind,
                &normalized,
                hit.at,
                hit.score,
                *truncated,
            );
        }
        if *ops > budget {
            return truncated_block(*truncated, "inspection work budget exceeded (truncated)");
        }
    }
    let mut verdict = Verdict::allow();
    verdict.score = best_soft;
    verdict.truncated = *truncated;
    verdict
}

#[allow(clippy::too_many_arguments)]
fn block_verdict(
    category: &'static str,
    subtype: &'static str,
    rule_id: &'static str,
    value: &Value,
    kind: FieldKind,
    normalized: &Normalized,
    at: usize,
    score: u32,
    truncated: bool,
) -> Verdict {
    let evidence = from_value(normalized, &value.text, normalized.char_index_of(at));
    let mut verdict = Verdict::block(
        category,
        subtype,
        rule_id,
        value.vector,
        value.field.clone(),
        kind,
        evidence,
        score,
    );
    verdict.truncated = truncated;
    verdict
}

fn detect_value(
    normalized: &Normalized,
    kind: FieldKind,
    strictness: Strictness,
    ops: &mut u64,
) -> Outcome {
    let scan = Scan::new(normalized, ops);
    *ops = ops.saturating_add((scan.tokens.len() as u64).saturating_mul(8));

    let mut hits: Vec<Hit> = Vec::new();
    if let Some(hit) = scan.h2() {
        hits.push(hit);
    }
    if let Some(hit) = scan.h1(kind) {
        hits.push(hit);
    }
    if let Some(hit) = scan.h3() {
        hits.push(hit);
    }
    if let Some(hit) = scan.h4() {
        hits.push(hit);
    }
    if let Some(hit) = scan.h5() {
        hits.push(hit);
    }
    if let Some(hit) = scan.h6() {
        hits.push(hit);
    }
    if let Some(hit) = scan.h7() {
        hits.push(hit);
    }
    if let Some(hit) = scan.h8() {
        hits.push(hit);
    }

    let mut soft = scan.soft_signals(kind);
    for hit in hits {
        match policy(&hit, kind, strictness) {
            Decision::Hard => {
                return Outcome {
                    hard: Some(hit),
                    soft,
                };
            }
            Decision::Soft(score) => soft = soft.max(score),
        }
    }
    Outcome { hard: None, soft }
}

/// The C4.6 field-kind policy: which hard family is a hard hit in which field kind.
fn policy(hit: &Hit, kind: FieldKind, strictness: Strictness) -> Decision {
    let paranoid = matches!(strictness, Strictness::Paranoid);
    match kind {
        FieldKind::Password => match hit.family {
            // C4.5/C4.6: in a password field H1 needs a break-out, H3 to H6 stay hard, H2 (and the softer families)
            // are soft 4 under Balanced and hard under Paranoid.
            Family::H1 => {
                // C4.6 password row: H1 is hard only with a break-out (Strict adds the numeric-context reading).
                if hit.breakout || paranoid {
                    Decision::Hard
                } else {
                    Decision::Soft(4)
                }
            }
            Family::H3 | Family::H4 | Family::H5 | Family::H6 => Decision::Hard,
            Family::H2 | Family::H7 | Family::H8 => {
                if paranoid {
                    Decision::Hard
                } else {
                    Decision::Soft(4)
                }
            }
        },
        // C4.6 numeric_id: any quote, comment or SQL keyword at least soft 4; any H-family is hard.
        FieldKind::NumericId => Decision::Hard,
        FieldKind::Filename => match hit.family {
            // HK1 acceptance requires M1 to M6 to block in every vector, so the file-name policy keeps H2 hard when
            // an identifier precedes the quote (all mandated payloads do).
            Family::H2 if !hit.after_identifier => Decision::Soft(4),
            _ => Decision::Hard,
        },
        FieldKind::Header | FieldKind::Cookie | FieldKind::Username => match hit.family {
            Family::H1 => {
                if hit.comparison || (hit.breakout && hit.strong) || paranoid {
                    // A bare quoted literal (`'a' or 'b'`, "I said 'no' or 'yes'") is soft under Balanced even in an
                    // all-hard field kind; Strict keeps the stricter reading (review R1-5 LOW).
                    Decision::Hard
                } else {
                    Decision::Soft(4)
                }
            }
            _ => Decision::Hard,
        },
        // Username, email, search, free text, unknown: H3 to H8 hard; H1 and H2 need their break-out context
        // (C4.6 search row and C4.9 prose controls). Paranoid lowers the threshold.
        _ => match hit.family {
            Family::H1 => {
                let hard_comparison = hit.comparison && (hit.breakout || hit.numeric_context);
                let hard_bare = !hit.comparison && hit.breakout && hit.strong;
                if hard_comparison || hard_bare || paranoid {
                    Decision::Hard
                } else {
                    Decision::Soft(4)
                }
            }
            Family::H2 => {
                if hit.hash_numbered && matches!(kind, FieldKind::Search | FieldKind::FreeText) {
                    Decision::Soft(2)
                } else if hit.after_identifier || paranoid {
                    Decision::Hard
                } else {
                    Decision::Soft(4)
                }
            }
            Family::H7 => {
                if (hit.breakout && hit.comparison) || paranoid {
                    Decision::Hard
                } else {
                    Decision::Soft(4)
                }
            }
            _ => Decision::Hard,
        },
    }
}

impl<'a> Scan<'a> {
    fn new(normalized: &'a Normalized, ops: &mut u64) -> Self {
        let text = normalized.text.as_str();
        let tokens = tokenize(text, ops);
        // One pass: per-quote-type running counters for `quote_is_breakout` (review R1-2: the old implementation
        // rescanned every earlier token per quote, which was quadratic).
        let mut quote_breakouts: Vec<bool> = vec![false; tokens.len()];
        let mut quote_counts = [0usize; 3];
        for (index, token) in tokens.iter().enumerate() {
            let TokenKind::Quote(quote) = token.kind else {
                continue;
            };
            let slot = match quote {
                '\'' => 0usize,
                '"' => 1,
                _ => 2,
            };
            if let Some(count) = quote_counts.get_mut(slot) {
                if let Some(cell) = quote_breakouts.get_mut(index) {
                    *cell = *count % 2 == 0;
                }
                *count = count.saturating_add(1);
            }
        }
        // Local quote pairing for operand parsing: the next quote of the same kind after every quote token. Global
        // pairing mis-pairs the mandated payloads (`' OR '1'='1` starts with the break-out quote), which regressed
        // the M2 tautology evaluation in review round 1.
        let mut next_quote: Vec<Option<usize>> = vec![None; tokens.len()];
        let mut next_positions: [Option<usize>; 3] = [None, None, None];
        for index in (0..tokens.len()).rev() {
            let Some(token) = tokens.get(index) else {
                break;
            };
            let TokenKind::Quote(quote) = token.kind else {
                continue;
            };
            let slot = match quote {
                '\'' => 0usize,
                '"' => 1,
                _ => 2,
            };
            if let Some(entry) = next_positions.get_mut(slot) {
                if let Some(cell) = next_quote.get_mut(index) {
                    *cell = *entry;
                }
                *entry = Some(index);
            }
        }
        // Suffix flags: is there a comment or a statement terminator at or after each token? (O(1) `strong`.)
        let mut terminator_after: Vec<bool> = vec![false; tokens.len().saturating_add(1)];
        for index in (0..tokens.len()).rev() {
            let is_terminator = tokens
                .get(index)
                .map(|token| match token.kind {
                    TokenKind::Comment => true,
                    TokenKind::Punct => token.text(text) == ";",
                    _ => false,
                })
                .unwrap_or(false);
            let next = terminator_after.get(index + 1).copied().unwrap_or(false);
            if let Some(cell) = terminator_after.get_mut(index) {
                *cell = is_terminator || next;
            }
        }
        let mut has_statement_keyword = false;
        let mut has_select = false;
        let mut has_from = false;
        let mut has_union = false;
        let mut has_comparison_operator = false;
        let mut first_quote: Option<usize> = None;
        let mut has_sql_or_connector = false;
        for (index, token) in tokens.iter().enumerate() {
            match token.kind {
                TokenKind::Word => match token.text(text) {
                    "select" => {
                        has_select = true;
                        has_statement_keyword = true;
                    }
                    "from" => {
                        has_from = true;
                        has_statement_keyword = true;
                    }
                    "union" => {
                        has_union = true;
                        has_statement_keyword = true;
                    }
                    "insert" | "update" | "delete" | "drop" | "truncate" | "where" | "order"
                    | "group" | "having" | "limit" | "exec" | "execute" | "declare" | "values"
                    | "set" => has_statement_keyword = true,
                    "or" | "and" | "xor" => has_sql_or_connector = true,
                    _ => {}
                },
                TokenKind::Op => {
                    let op = token.text(text);
                    if matches!(op, "||" | "&&") {
                        has_sql_or_connector = true;
                    }
                    if matches!(op, "=" | "==" | "<" | ">" | "<=" | ">=" | "<>" | "!=") {
                        has_comparison_operator = true;
                    }
                }
                TokenKind::Quote(_) if first_quote.is_none() => {
                    first_quote = Some(index);
                }
                _ => {}
            }
        }
        let mut starts_numeric = false;
        for token in &tokens {
            match token.kind {
                TokenKind::Punct => {
                    let punctuation = token.text(text);
                    if punctuation == "(" || punctuation == "-" || punctuation == "+" {
                        continue;
                    }
                    break;
                }
                TokenKind::Number => {
                    starts_numeric = true;
                    break;
                }
                _ => break,
            }
        }
        let has_sql_words = has_union || (has_select && has_from);
        Self {
            normalized,
            text,
            tokens,
            next_quote,
            quote_breakouts,
            terminator_after,
            has_statement_keyword,
            starts_numeric,
            has_comparison_operator,
            first_quote,
            has_sql_or_connector,
            has_sql_words,
        }
    }

    fn token(&self, index: usize) -> Option<Token> {
        self.tokens.get(index).copied()
    }

    fn text_of(&self, index: usize) -> &'a str {
        self.token(index)
            .map(|token| token.text(self.text))
            .unwrap_or("")
    }

    fn kind_of(&self, index: usize) -> Option<TokenKind> {
        self.token(index).map(|token| token.kind)
    }

    fn word_is(&self, index: usize, wanted: &str) -> bool {
        self.kind_of(index) == Some(TokenKind::Word) && self.text_of(index) == wanted
    }

    fn punct_is(&self, index: usize, wanted: &str) -> bool {
        self.kind_of(index) == Some(TokenKind::Punct) && self.text_of(index) == wanted
    }

    fn is_quote(&self, index: usize) -> bool {
        matches!(self.kind_of(index), Some(TokenKind::Quote(_)))
    }

    fn is_connector(&self, index: usize) -> bool {
        match self.kind_of(index) {
            Some(TokenKind::Word) => matches!(self.text_of(index), "or" | "and" | "xor"),
            Some(TokenKind::Op) => matches!(self.text_of(index), "||" | "&&"),
            _ => false,
        }
    }

    /// Whether the connector at `index` follows a quote or an unbalanced closing parenthesis (C4.5 H1 note).
    fn breakout_before(&self, index: usize) -> Breakout {
        let mut closes = 0usize;
        let mut cursor = index;
        while cursor > 0 {
            cursor -= 1;
            let Some(token) = self.token(cursor) else {
                break;
            };
            match token.kind {
                TokenKind::Quote(_) => return Breakout::Quote,
                TokenKind::Punct => {
                    let text = token.text(self.text);
                    if text == ")" {
                        closes += 1;
                    } else if text == "(" {
                        if closes > 0 {
                            closes -= 1;
                        } else {
                            return Breakout::None;
                        }
                    } else if text == ";" || text == "," {
                        return Breakout::None;
                    }
                }
                TokenKind::Op => return Breakout::None,
                _ => return Breakout::None,
            }
        }
        if closes > 0 {
            return Breakout::Paren;
        }
        Breakout::None
    }

    fn quote_anywhere_before(&self, index: usize) -> bool {
        self.first_quote.map(|first| first < index).unwrap_or(false)
    }

    fn identifier_before(&self, index: usize) -> bool {
        let Some(previous) = index.checked_sub(1) else {
            return false;
        };
        matches!(
            self.kind_of(previous),
            Some(TokenKind::Word | TokenKind::Number)
        )
    }

    fn number_before(&self, index: usize) -> bool {
        let mut cursor = index;
        while cursor > 0 {
            cursor -= 1;
            let Some(token) = self.token(cursor) else {
                break;
            };
            match token.kind {
                TokenKind::Punct => {
                    let text = token.text(self.text);
                    if text == "-" || text == "+" {
                        continue;
                    }
                    return false;
                }
                _ => return token.kind == TokenKind::Number,
            }
        }
        false
    }

    /// Whether an opening quote at `index` is unpaired so far (an even number of the same quote precedes it), which
    /// is what makes it a break-out rather than the closing quote of a complete literal. O(1): the answer is
    /// precomputed in [`Scan::new`] (review R1-2).
    fn quote_is_breakout(&self, index: usize) -> bool {
        self.quote_breakouts.get(index).copied().unwrap_or(false)
    }

    /// Parse a literal operand starting at `start`.
    /// Skip up to `depth` closing parentheses that wrap an operand opened with the same number of `(`.
    fn close_parens(&self, mut index: usize, depth: usize) -> usize {
        let mut left = depth;
        while left > 0 && self.punct_is(index, ")") {
            index += 1;
            left -= 1;
        }
        index
    }

    fn operand(&self, start: usize) -> Option<(Lit, usize)> {
        let (literal, next, depth) = self.operand_core(start)?;
        Some((literal, self.close_parens(next, depth)))
    }

    /// `char(49)`, `char(97,98)`: a string built from character codes is a literal (`' or char(49)=char(49)--`).
    fn char_call(&self, index: usize) -> Option<(Lit, usize)> {
        if !self.word_is(index, "char") || !self.punct_is(index + 1, "(") {
            return None;
        }
        let mut cursor = index + 2;
        let mut built = String::new();
        while built.len() < 32 {
            if self.kind_of(cursor) != Some(TokenKind::Number) {
                return None;
            }
            let code: u32 = self.text_of(cursor).parse().ok()?;
            built.push(char::from_u32(code)?);
            cursor += 1;
            if self.punct_is(cursor, ",") {
                cursor += 1;
                continue;
            }
            if self.punct_is(cursor, ")") {
                return Some((Lit::string(&built), cursor + 1));
            }
            return None;
        }
        None
    }

    fn operand_core(&self, start: usize) -> Option<(Lit, usize, usize)> {
        let mut index = start;
        let mut depth = 0usize;
        while self.punct_is(index, "(") && depth < 64 {
            depth += 1;
            index += 1;
        }
        if let Some((literal, next)) = self.char_call(index) {
            return Some((literal, next, depth));
        }
        if self.punct_is(index, "-") {
            let next = index + 1;
            if self.kind_of(next) == Some(TokenKind::Number) {
                let text = format!("-{}", self.text_of(next));
                return Some((Lit::number(&text), next + 1, depth));
            }
            return None;
        }
        let token = self.token(index)?;
        if matches!(token.kind, TokenKind::Quote(_)) {
            if let Some(close) = self.next_quote.get(index).copied().flatten() {
                let content_start = token.end;
                let content_end = self
                    .token(close)
                    .map(|open| open.start)
                    .unwrap_or(content_start);
                let raw = self.text.get(content_start..content_end).unwrap_or("");
                return Some((Lit::string(raw), close + 1, depth));
            }
            let tail = self.text.get(token.end..).unwrap_or("");
            return Some((Lit::string(literal_tail(tail)), self.tokens.len(), depth));
        }
        match token.kind {
            TokenKind::Number => Some((Lit::number(token.text(self.text)), index + 1, depth)),
            TokenKind::Word => Some((Lit::word(token.text(self.text)), index + 1, depth)),
            _ => None,
        }
    }

    /// Parse the comparison operator at `index`, returning its text and the index after it.
    fn operator(&self, index: usize) -> Option<(&'a str, usize)> {
        match self.kind_of(index)? {
            TokenKind::Op => {
                let text = self.text_of(index);
                matches!(text, "=" | "==" | "<>" | "!=" | "<" | ">" | "<=" | ">=")
                    .then_some((text, index + 1))
            }
            TokenKind::Word => (self.text_of(index) == "like").then_some(("like", index + 1)),
            _ => None,
        }
    }

    fn predicate(&self, start: usize) -> Option<Predicate> {
        // A leading `not` negates the predicate (`or NOT 0`, C4.5 H1).
        let mut cursor = start;
        let mut negations = 0usize;
        while self.word_is(cursor, "not") && negations < 8 {
            cursor += 1;
            negations += 1;
        }
        // `~0`, `~1`: bitwise NOT of an integer is never zero, so it is an always-true bare literal (`' OR ~0--`).
        if self.text_of(cursor) == "~" && self.kind_of(cursor + 1) == Some(TokenKind::Number) {
            return Some(Predicate {
                truth: Some(negations.is_multiple_of(2)),
                comparison: false,
                uses_like: false,
                identifier_operand: false,
            });
        }
        let mut predicate = self.predicate_core(cursor)?;
        if negations % 2 == 1 {
            predicate.truth = predicate.truth.map(|truth| !truth);
        }
        Some(predicate)
    }

    fn predicate_core(&self, start: usize) -> Option<Predicate> {
        let (lhs, index) = self.operand(start)?;
        if let Some((operator, after)) = self.operator(index) {
            let (rhs, _end) = self.operand(after)?;
            let truth = match operator {
                "=" | "==" => lhs.equal(&rhs),
                "<>" | "!=" => lhs.equal(&rhs).map(|equal| !equal),
                "<" => lhs.compare(&rhs, Ordering::Less),
                ">" => lhs.compare(&rhs, Ordering::Greater),
                "<=" => lhs.compare(&rhs, Ordering::Less).map_or_else(
                    || lhs.compare(&rhs, Ordering::Equal),
                    |less| Some(less || lhs.equal(&rhs) == Some(true)),
                ),
                ">=" => lhs.compare(&rhs, Ordering::Greater).map_or_else(
                    || lhs.compare(&rhs, Ordering::Equal),
                    |greater| Some(greater || lhs.equal(&rhs) == Some(true)),
                ),
                "like" => lhs.like(&rhs),
                _ => None,
            };
            return Some(Predicate {
                truth,
                comparison: true,
                uses_like: operator == "like",
                identifier_operand: lhs.is_identifier() || rhs.is_identifier(),
            });
        }
        if self.word_is(index, "in") {
            return self.predicate_in(lhs, index + 1);
        }
        if self.word_is(index, "between") {
            let (low, index) = self.operand(index + 1)?;
            if !self.word_is(index, "and") {
                return None;
            }
            let (high, _) = self.operand(index + 1)?;
            let truth = lhs.between(&low, &high);
            return Some(Predicate {
                truth,
                comparison: true,
                uses_like: false,
                identifier_operand: lhs.is_identifier(),
            });
        }
        if self.word_is(index, "is") {
            let mut cursor = index + 1;
            let negated = self.word_is(cursor, "not");
            if negated {
                cursor += 1;
            }
            if !self.word_is(cursor, "null") {
                return None;
            }
            let lhs_is_null = lhs.kind == LitKind::Word && lhs.text == "null";
            let truth = Some(lhs_is_null != negated);
            return Some(Predicate {
                truth,
                comparison: true,
                uses_like: false,
                identifier_operand: lhs.is_identifier(),
            });
        }
        Some(Predicate {
            truth: lhs.truthy(),
            comparison: false,
            uses_like: false,
            identifier_operand: lhs.is_identifier(),
        })
    }

    fn predicate_in(&self, lhs: Lit, start: usize) -> Option<Predicate> {
        if !self.punct_is(start, "(") {
            return None;
        }
        let mut cursor = start + 1;
        let mut found = 0usize;
        let mut equal_seen = false;
        while found < 64 {
            if self.punct_is(cursor, ")") {
                break;
            }
            let (candidate, next) = self.operand(cursor)?;
            if lhs.equal(&candidate) == Some(true) {
                equal_seen = true;
            }
            cursor = next;
            if self.punct_is(cursor, ",") {
                cursor += 1;
            }
            found += 1;
        }
        Some(Predicate {
            truth: Some(equal_seen),
            comparison: true,
            uses_like: false,
            identifier_operand: lhs.is_identifier(),
        })
    }

    /// Whether a metadata or evasion shape sits in a context that makes it SQL-ish rather than prose. O(1): the
    /// token facts are precomputed in [`Scan::new`] (review R1-2).
    fn sql_context(&self, index: usize) -> bool {
        self.has_sql_words
            || self.has_statement_keyword
            || self.has_sql_or_connector
            || self.quote_anywhere_before(index)
    }

    /// H1: tautology / always-true predicate after a boolean connector (C4.5 H1).
    fn h1(&self, kind: FieldKind) -> Option<Hit> {
        if let Some(hit) = self.h1_quote_arithmetic() {
            return Some(hit);
        }
        if let Some(hit) = self.h1_probe_fragment() {
            return Some(hit);
        }
        for (index, token) in self.tokens.iter().enumerate() {
            if !(self.is_connector(index) || self.word_is(index, "having")) {
                continue;
            }
            let Some(predicate) = self.predicate(index + 1) else {
                continue;
            };
            let breakout = self.breakout_before(index);
            // A literal-only comparison that is false (`1 AND 1=2`, `1' AND '1'='2`) is the other half of a blind
            // boolean probe: it is attack-shaped after a quote break-out, or when the whole field is the expression.
            let false_probe = predicate.truth == Some(false)
                && predicate.comparison
                && !predicate.identifier_operand
                && (breakout == Breakout::Quote
                    || (index > 0
                        && self.kind_of(index - 1) == Some(TokenKind::Number)
                        && self.starts_numeric
                        && self.text.len() <= 48));
            if predicate.truth != Some(true) && !false_probe {
                continue;
            }
            let numeric_context = index > 0 && self.kind_of(index - 1) == Some(TokenKind::Number);
            let strong = self
                .terminator_after
                .get(index + 1)
                .copied()
                .unwrap_or(false)
                || self.has_statement_keyword;
            if !predicate.comparison {
                // A bare truthy literal (`or 1`) is attack-shaped after a quote break-out, or in a numeric field;
                // whether it is a hard hit is the policy's decision, so a quoted-words prose case stays soft under
                // Balanced and hard under Strict (review R1-5 LOW). "1 or 2" has no break-out and is skipped.
                let meaningful = kind == FieldKind::NumericId || breakout == Breakout::Quote;
                if !meaningful {
                    continue;
                }
            }
            let hard_context = match breakout {
                Breakout::Quote => true,
                // A parenthesis-only break-out is enough for a full comparison, but not for a bare literal.
                Breakout::Paren => predicate.comparison,
                Breakout::None => false_probe,
            };
            return Some(Hit {
                family: Family::H1,
                subtype: "tautology",
                rule_id: "H1-001",
                score: 92,
                at: token.start,
                breakout: hard_context,
                after_identifier: false,
                comparison: predicate.comparison,
                hash_numbered: false,
                numeric_context,
                strong,
            });
        }
        None
    }

    /// H1-003: a field that is only an injection probe fragment (`'`, `"`, `\`, `' )`, `'; --`, `' OR`): no real input
    /// is made of nothing but quote characters, closers and a comment or connector, so it is an error-probe.
    fn h1_probe_fragment(&self) -> Option<Hit> {
        let trimmed = self.text.trim();
        if trimmed.is_empty() || trimmed.len() > 8 {
            return None;
        }
        let mut quotes = 0usize;
        for word in trimmed.split_whitespace() {
            let lower = word.to_ascii_lowercase();
            if matches!(lower.as_str(), "or" | "and") {
                continue;
            }
            for c in word.chars() {
                match c {
                    '\'' | '"' | '`' | '\\' => quotes = quotes.saturating_add(1),
                    ')' | '(' | ';' | '-' | '#' | '/' | '*' => {}
                    _ => return None,
                }
            }
        }
        if quotes == 0 {
            return None;
        }
        Some(Hit {
            family: Family::H1,
            subtype: "probe_fragment",
            rule_id: "H1-003",
            score: 80,
            at: 0,
            breakout: true,
            after_identifier: false,
            comparison: true,
            hash_numbered: false,
            numeric_context: false,
            strong: false,
        })
    }

    /// H1-002: a quoted arithmetic expression (`'-0-'`, `'-1-1-'`), an injection probe with no connector (R1-5).
    fn h1_quote_arithmetic(&self) -> Option<Hit> {
        let trimmed = self.text.trim();
        let quote = trimmed.chars().next()?;
        if quote != '\'' && quote != '"' {
            return None;
        }
        let inner = trimmed.strip_prefix(quote)?.strip_suffix(quote)?;
        if inner.len() < 2 || inner.len() > 16 {
            return None;
        }
        let mut operators = 0usize;
        let mut digits = 0usize;
        for c in inner.chars() {
            match c {
                '+' | '-' => operators = operators.saturating_add(1),
                '0'..='9' | ' ' => digits = digits.saturating_add(1),
                _ => return None,
            }
        }
        if operators < 2 || digits == 0 {
            return None;
        }
        Some(Hit {
            family: Family::H1,
            subtype: "quote_arithmetic",
            rule_id: "H1-002",
            score: 85,
            at: 0,
            breakout: true,
            after_identifier: false,
            comparison: true,
            hash_numbered: false,
            numeric_context: true,
            strong: true,
        })
    }

    /// H2: quote break-out followed by a comment starter or a statement terminator (C4.5 H2).
    fn h2(&self) -> Option<Hit> {
        // `1 --`, `10 #`: a number closed by a comment and nothing else is a numeric-context comment break-out probe.
        let trimmed = self.text.trim();
        if trimmed.len() <= 12 {
            let digits = trimmed.chars().take_while(char::is_ascii_digit).count();
            let rest = trimmed.get(digits..).unwrap_or("").trim();
            if digits > 0 && (rest == "--" || rest == "#" || rest == "/*") {
                return Some(Hit {
                    family: Family::H2,
                    subtype: "comment_breakout",
                    rule_id: "H2-003",
                    score: 85,
                    at: 0,
                    breakout: true,
                    after_identifier: false,
                    comparison: false,
                    hash_numbered: false,
                    numeric_context: true,
                    strong: false,
                });
            }
        }
        for (index, token) in self.tokens.iter().enumerate() {
            match token.kind {
                TokenKind::Comment => {
                    let mut cursor = index;
                    let mut quote_index = None;
                    while cursor > 0 {
                        cursor -= 1;
                        let Some(previous) = self.token(cursor) else {
                            break;
                        };
                        if previous.kind == TokenKind::Punct && previous.text(self.text) == ")" {
                            continue;
                        }
                        if matches!(previous.kind, TokenKind::Quote(_)) {
                            quote_index = Some(cursor);
                        }
                        break;
                    }
                    let quote_index = quote_index?;
                    if !self.quote_is_breakout(quote_index) {
                        return None;
                    }
                    let comment = token.text(self.text);
                    let hash_numbered = comment.starts_with('#')
                        && comment
                            .chars()
                            .nth(1)
                            .map(|c| c.is_ascii_digit())
                            .unwrap_or(false);
                    return Some(Hit {
                        family: Family::H2,
                        subtype: "comment_breakout",
                        rule_id: "H2-001",
                        score: 95,
                        at: token.start,
                        breakout: true,
                        after_identifier: self.identifier_before(quote_index),
                        comparison: false,
                        hash_numbered,
                        numeric_context: false,
                        strong: false,
                    });
                }
                TokenKind::Punct if token.text(self.text) == ";" => {
                    let mut cursor = index;
                    let mut quote_index = None;
                    while cursor > 0 {
                        cursor -= 1;
                        let Some(previous) = self.token(cursor) else {
                            break;
                        };
                        if previous.kind == TokenKind::Punct && previous.text(self.text) == ")" {
                            continue;
                        }
                        if matches!(previous.kind, TokenKind::Quote(_)) {
                            quote_index = Some(cursor);
                        }
                        break;
                    }
                    let quote_index = quote_index?;
                    if !self.quote_is_breakout(quote_index) {
                        return None;
                    }
                    return Some(Hit {
                        family: Family::H2,
                        subtype: "terminator_breakout",
                        rule_id: "H2-002",
                        score: 92,
                        at: token.start,
                        breakout: true,
                        after_identifier: self.identifier_before(quote_index),
                        comparison: false,
                        hash_numbered: false,
                        numeric_context: false,
                        strong: false,
                    });
                }
                _ => {}
            }
        }
        None
    }

    /// H3: UNION-based extraction and ORDER BY/GROUP BY ordinal probes (C4.5 H3).
    fn h3(&self) -> Option<Hit> {
        for index in 0..self.tokens.len() {
            if !self.word_is(index, "union") {
                let order_by_probe = self.word_is(index, "order")
                    && self.word_is(index + 1, "by")
                    && self.kind_of(index + 2) == Some(TokenKind::Number)
                    && (self.quote_anywhere_before(index) || self.number_before(index));
                if order_by_probe {
                    return Some(Hit {
                        family: Family::H3,
                        subtype: "order_by_probe",
                        rule_id: "H3-002",
                        score: 90,
                        at: self.token(index).map(|token| token.start).unwrap_or(0),
                        breakout: true,
                        after_identifier: false,
                        comparison: true,
                        hash_numbered: false,
                        numeric_context: false,
                        strong: false,
                    });
                }
                continue;
            }
            let mut cursor = index + 1;
            if self.word_is(cursor, "all") || self.word_is(cursor, "distinct") {
                cursor += 1;
            }
            if !self.word_is(cursor, "select") {
                continue;
            }
            let breakout = self.breakout_before(index) != Breakout::None;
            let number_before = self.number_before(index);
            let literal_list = self.kind_of(cursor + 1) == Some(TokenKind::Number)
                || self.word_is(cursor + 1, "null")
                || self.punct_is(cursor + 1, "*");
            let sql_after = literal_list
                || (cursor + 1..cursor.saturating_add(9)).any(|after| {
                    self.word_is(after, "from")
                        || self.word_is(after, "where")
                        || self.text_of(after).starts_with("@@")
                });
            if breakout || number_before || sql_after {
                return Some(Hit {
                    family: Family::H3,
                    subtype: "union_select",
                    rule_id: "H3-001",
                    score: 93,
                    at: self.token(index).map(|token| token.start).unwrap_or(0),
                    breakout,
                    after_identifier: false,
                    comparison: true,
                    hash_numbered: false,
                    numeric_context: false,
                    strong: false,
                });
            }
        }
        None
    }

    /// H4: stacked queries and dangerous statements (C4.5 H4).
    fn h4(&self) -> Option<Hit> {
        const STACKED: &[&str] = &[
            "drop", "alter", "create", "insert", "update", "delete", "truncate", "grant", "revoke",
            "exec", "execute", "declare", "call", "copy", "merge", "replace", "rename", "vacuum",
            "attach", "pragma", "shutdown",
        ];
        const ALWAYS_DANGEROUS: &[&str] = &[
            "shutdown", "drop", "truncate", "grant", "revoke", "declare", "exec", "execute",
        ];
        for index in 0..self.tokens.len() {
            if !self.punct_is(index, ";") {
                continue;
            }
            let Some(next) = self.token(index + 1) else {
                continue;
            };
            if next.kind != TokenKind::Word {
                continue;
            }
            let word = next.text(self.text);
            // `; select ... from`, `; select 1`, `; set @a=1` after a quote or number break-out are stacked queries too.
            let extra = match word {
                "select" => {
                    (self.breakout_before(index) == Breakout::Quote || self.number_before(index))
                        && (index + 2..index.saturating_add(9)).any(|after| {
                            self.word_is(after, "from")
                                || self.punct_is(after, "*")
                                || self.kind_of(after) == Some(TokenKind::Comment)
                                || self.kind_of(after) == Some(TokenKind::Number)
                        })
                }
                "set" => {
                    (self.breakout_before(index) == Breakout::Quote || self.number_before(index))
                        && self.text_of(index + 2).starts_with('@')
                }
                _ => false,
            };
            if extra {
                return Some(Hit {
                    family: Family::H4,
                    subtype: "stacked_query",
                    rule_id: "H4-001",
                    score: 94,
                    at: next.start,
                    breakout: true,
                    after_identifier: false,
                    comparison: true,
                    hash_numbered: false,
                    numeric_context: false,
                    strong: false,
                });
            }
            if !STACKED.contains(&word) {
                continue;
            }
            let quote_context = self.quote_anywhere_before(index);
            let number_context = self.number_before(index);
            let always = ALWAYS_DANGEROUS.contains(&word);
            let program = word == "copy"
                && (index + 2..index.saturating_add(9)).any(|after| self.word_is(after, "program"));
            if quote_context || number_context || always || program {
                return Some(Hit {
                    family: Family::H4,
                    subtype: "stacked_query",
                    rule_id: "H4-001",
                    score: 94,
                    at: self.token(index).map(|token| token.start).unwrap_or(0),
                    breakout: true,
                    after_identifier: false,
                    comparison: true,
                    hash_numbered: false,
                    numeric_context: false,
                    strong: false,
                });
            }
        }
        None
    }

    /// H5: blind, time-based, error-based and out-of-band functions (C4.5 H5).
    fn h5(&self) -> Option<Hit> {
        const TIME_FUNCTIONS: &[&str] = &[
            "sleep",
            "benchmark",
            "pg_sleep",
            "pg_sleep_for",
            "pg_sleep_until",
            "extractvalue",
            "updatexml",
            "load_file",
            "lo_import",
            "pg_read_file",
            "openrowset",
            "opendatasource",
            "randomblob",
            "xp_dirtree",
            "xp_fileexist",
            "xp_cmdshell",
            "load_extension",
        ];
        for index in 0..self.tokens.len() {
            let Some(token) = self.token(index) else {
                continue;
            };
            if token.kind != TokenKind::Word {
                continue;
            }
            let word = token.text(self.text);
            let called = self.punct_is(index + 1, "(");
            let sql_context = self.sql_function_context(index);

            if word == "waitfor"
                && (index + 1..index.saturating_add(4)).any(|after| self.word_is(after, "delay"))
            {
                return Some(self.h5_hit(token.start, "waitfor_delay", "H5-002"));
            }
            if word == "into"
                && (self.word_is(index + 1, "outfile") || self.word_is(index + 1, "dumpfile"))
            {
                return Some(self.h5_hit(token.start, "file_write", "H5-003"));
            }
            if word == "exp" && called && self.punct_is(index + 2, "~") {
                return Some(self.h5_hit(token.start, "error_based", "H5-001"));
            }
            if word == "floor" && called && self.word_is(index + 2, "rand") {
                return Some(self.h5_hit(token.start, "error_based", "H5-001"));
            }
            if word == "if"
                && called
                && (index + 2..index.saturating_add(10))
                    .any(|after| self.word_is(after, "ascii") || self.word_is(after, "substring"))
            {
                return Some(self.h5_hit(token.start, "boolean_extraction", "H5-004"));
            }
            // Review R1-5: numeric-context blind shapes without the classic function names.
            let numeric_ctx = self.starts_numeric || self.quote_anywhere_before(index);
            if word == "case"
                && self.has_comparison_operator
                && numeric_ctx
                && (index + 1..index.saturating_add(13)).any(|after| self.word_is(after, "when"))
            {
                return Some(self.h5_hit(token.start, "blind_boolean", "H5-006"));
            }
            if word == "exists"
                && called
                && numeric_ctx
                && (index + 2..index.saturating_add(10)).any(|after| self.word_is(after, "select"))
            {
                return Some(self.h5_hit(token.start, "subselect", "H5-007"));
            }
            if word == "select" && index > 0 && self.punct_is(index - 1, "(") && numeric_ctx {
                return Some(self.h5_hit(token.start, "subselect", "H5-008"));
            }
            if word == "procedure" && self.word_is(index + 1, "analyse") && numeric_ctx {
                return Some(self.h5_hit(token.start, "subselect", "H5-008"));
            }
            if matches!(
                word,
                "ascii" | "substr" | "substring" | "mid" | "ord" | "length"
            ) && called
                && self.has_comparison_operator
                && numeric_ctx
            {
                return Some(self.h5_hit(token.start, "boolean_extraction", "H5-004"));
            }
            if TIME_FUNCTIONS.contains(&word) && called {
                let mut hit_worthy = sql_context;
                if word == "randomblob" {
                    hit_worthy = true;
                }
                if word.contains('.') || word.starts_with("xp_") {
                    hit_worthy = sql_context;
                }
                if hit_worthy {
                    return Some(self.h5_hit(token.start, "time_based_function", "H5-001"));
                }
                continue;
            }
            if word.contains('.')
                && (word.contains("receive_message")
                    || word.contains("dbms_lock.sleep")
                    || word.contains("utl_inaddr")
                    || word.contains("utl_http"))
                && sql_context
            {
                return Some(self.h5_hit(token.start, "out_of_band", "H5-005"));
            }
        }
        None
    }

    fn h5_hit(&self, at: usize, subtype: &'static str, rule_id: &'static str) -> Hit {
        Hit {
            family: Family::H5,
            subtype,
            rule_id,
            score: 93,
            at,
            breakout: false,
            after_identifier: false,
            comparison: true,
            hash_numbered: false,
            numeric_context: false,
            strong: false,
        }
    }

    fn sql_function_context(&self, index: usize) -> bool {
        if index == 0 {
            return false;
        }
        let previous = index - 1;
        match self.kind_of(previous) {
            Some(TokenKind::Quote(_)) => true,
            Some(TokenKind::Op) => {
                matches!(self.text_of(previous), "=" | "==" | "||" | "&&" | "<" | ">")
            }
            Some(TokenKind::Punct) => matches!(self.text_of(previous), "(" | ";" | ","),
            Some(TokenKind::Number) => false,
            Some(TokenKind::Word) => matches!(
                self.text_of(previous),
                "and"
                    | "or"
                    | "not"
                    | "where"
                    | "select"
                    | "set"
                    | "then"
                    | "when"
                    | "case"
                    | "having"
                    | "by"
                    | "union"
                    | "from"
                    | "limit"
                    | "values"
                    | "if"
                    | "else"
                    | "like"
                    | "in"
                    | "between"
                    | "as"
                    | "update"
                    | "exec"
                    | "execute"
                    | "return"
            ),
            _ => false,
        }
    }

    /// H6: schema and metadata discovery in a SQL context (C4.5 H6).
    fn h6(&self) -> Option<Hit> {
        const SCHEMAS: &[&str] = &[
            "information_schema",
            "pg_catalog",
            "pg_tables",
            "sysobjects",
            "syscolumns",
            "mysql.user",
            "sqlite_master",
            "all_tables",
            "user_tables",
            "sys.tables",
        ];
        const FUNCTIONS: &[&str] = &[
            "version",
            "database",
            "current_user",
            "system_user",
            "session_user",
        ];
        for index in 0..self.tokens.len() {
            let Some(token) = self.token(index) else {
                continue;
            };
            if token.kind != TokenKind::Word {
                continue;
            }
            let word = token.text(self.text);
            let schema = SCHEMAS.iter().any(|schema| {
                word == *schema
                    || (word.starts_with(schema)
                        && word.as_bytes().get(schema.len()) == Some(&b'.'))
            });
            if schema && self.has_sql_words {
                return Some(self.h6_hit(token.start));
            }
            let function = FUNCTIONS.contains(&word);
            if function
                && self.punct_is(index + 1, "(")
                && (self.has_sql_words || self.quote_anywhere_before(index))
            {
                return Some(self.h6_hit(token.start));
            }
            if word.starts_with("@@") && (self.has_sql_words || self.quote_anywhere_before(index)) {
                return Some(self.h6_hit(token.start));
            }
        }
        None
    }

    fn h6_hit(&self, at: usize) -> Hit {
        Hit {
            family: Family::H6,
            subtype: "metadata_discovery",
            rule_id: "H6-001",
            score: 85,
            at,
            breakout: false,
            after_identifier: false,
            comparison: true,
            hash_numbered: false,
            numeric_context: false,
            strong: false,
        }
    }

    /// H7: authentication-bypass idioms (C4.5 H7).
    fn h7(&self) -> Option<Hit> {
        for index in 0..self.tokens.len() {
            if self.word_is(index, "having") {
                if let Some(predicate) = self.predicate(index + 1)
                    && predicate.truth == Some(true)
                    && self.quote_anywhere_before(index)
                {
                    return Some(self.h7_hit(index, "auth_bypass", "H7-002"));
                }
                continue;
            }
            if !self.is_connector(index) {
                continue;
            }
            if self.breakout_before(index) == Breakout::None {
                continue;
            }
            let Some(predicate) = self.predicate(index + 1) else {
                continue;
            };
            if predicate.comparison
                && predicate.truth != Some(true)
                && (predicate.uses_like || predicate.identifier_operand)
            {
                return Some(self.h7_hit(index, "auth_bypass", "H7-001"));
            }
        }
        // The `'='` / `' like '` shape: a quote, an operator and a quote. Only the short standalone idiom is treated as
        // an auth-bypass (C4.5 H7) so that prose such as "the '=' sign" does not block.
        let trimmed = self.text.trim();
        let standalone = trimmed.len() <= 6
            && trimmed
                .chars()
                .all(|c| matches!(c, '\'' | '"' | '`' | ' ' | '='));
        for index in 0..self.tokens.len() {
            if !self.is_quote(index) {
                continue;
            }
            let operator = self.kind_of(index + 1) == Some(TokenKind::Op);
            if operator && self.is_quote(index + 2) && standalone {
                return Some(self.h7_hit(index, "auth_bypass", "H7-003"));
            }
        }
        None
    }

    fn h7_hit(&self, at_index: usize, subtype: &'static str, rule_id: &'static str) -> Hit {
        Hit {
            family: Family::H7,
            subtype,
            rule_id,
            score: 90,
            at: self.token(at_index).map(|token| token.start).unwrap_or(0),
            breakout: true,
            after_identifier: false,
            comparison: true,
            hash_numbered: false,
            numeric_context: false,
            strong: false,
        }
    }

    /// H8: evasion constructs in a SQL context (C4.5 H8).
    fn h8(&self) -> Option<Hit> {
        // Versioned comments that survive normalisation are an evasion construct in themselves.
        if self.normalized.flags.versioned_comment && self.has_sql_words {
            return Some(self.h8_hit(0, "versioned_comment", "H8-002"));
        }
        // Keyword parts joined by string concatenation: `'un'+'ion'`, `'un' 'ion'`, `CONCAT('un','ion')`.
        if let Some(at) = find_concatenated_keyword(self.text) {
            return Some(self.h8_hit(at, "concatenated_keyword", "H8-005"));
        }
        for index in 0..self.tokens.len() {
            let Some(token) = self.token(index) else {
                continue;
            };
            let word = token.text(self.text);
            // char(39) / chr(0x27) construction of quote or delimiter characters.
            if token.kind == TokenKind::Word
                && matches!(word, "char" | "chr" | "ascii")
                && self.punct_is(index + 1, "(")
                && self.kind_of(index + 2) == Some(TokenKind::Number)
                && parse_integer_literal(self.text_of(index + 2))
                    .map(is_suspicious_codepoint)
                    .unwrap_or(false)
                && self.sql_context(index)
            {
                return Some(self.h8_hit(token.start, "char_construction", "H8-001"));
            }
            if token.kind == TokenKind::Number {
                if let Some(bytes) = parse_hex_literal(word) {
                    if bytes.iter().any(|byte| is_suspicious_byte(*byte)) && self.sql_context(index)
                    {
                        return Some(self.h8_hit(token.start, "hex_construction", "H8-003"));
                    }
                    if keyword_from_bytes(&bytes).is_some() {
                        return Some(self.h8_hit(token.start, "hex_keyword", "H8-003"));
                    }
                }
                if glued_keyword(word).is_some() && self.sql_context(index) {
                    return Some(self.h8_hit(token.start, "glued_keyword", "H8-004"));
                }
            }
            // Keyword parts split by a comment-as-space: `un ion` next to `select`.
            if token.kind == TokenKind::Word {
                let next = self.text_of(index + 1);
                if !next.is_empty() {
                    let joined: String = format!("{word}{next}");
                    if matches!(
                        joined.as_str(),
                        "union" | "select" | "information_schema" | "sleep"
                    ) && self.sql_context(index)
                    {
                        return Some(self.h8_hit(token.start, "split_keyword", "H8-004"));
                    }
                }
            }
        }
        None
    }

    fn h8_hit(&self, at: usize, subtype: &'static str, rule_id: &'static str) -> Hit {
        Hit {
            family: Family::H8,
            subtype,
            rule_id,
            score: 88,
            at,
            breakout: false,
            after_identifier: false,
            comparison: true,
            hash_numbered: false,
            numeric_context: false,
            strong: false,
        }
    }

    /// Soft signals (C4.7) for telemetry; they never block.
    fn soft_signals(&self, kind: FieldKind) -> u32 {
        let mut score = 0u32;
        let comments = self
            .tokens
            .iter()
            .filter(|token| token.kind == TokenKind::Comment)
            .count();
        if matches!(kind, FieldKind::NumericId)
            && self
                .tokens
                .iter()
                .any(|token| matches!(token.kind, TokenKind::Quote(_)))
        {
            score = score.saturating_add(3);
        }
        if comments > 0 && !matches!(kind, FieldKind::FreeText) {
            score = score.saturating_add(2);
        }
        let has_select = (0..self.tokens.len()).any(|index| self.word_is(index, "select"));
        let has_from = (0..self.tokens.len()).any(|index| self.word_is(index, "from"));
        if has_select && has_from {
            score = score.saturating_add(3);
        }
        let has_insert = (0..self.tokens.len()).any(|index| self.word_is(index, "insert"));
        let has_into = (0..self.tokens.len()).any(|index| self.word_is(index, "into"));
        if has_insert && has_into {
            score = score.saturating_add(3);
        }
        if self.tokens.iter().any(|token| {
            token.kind == TokenKind::Op && matches!(token.text(self.text), "||" | "&&")
        }) {
            score = score.saturating_add(2);
        }
        if self.normalized.flags.inline_comment || self.normalized.flags.versioned_comment {
            score = score.saturating_add(1);
        }
        score.min(10)
    }
}

impl Lit {
    fn number(text: &str) -> Self {
        Self {
            kind: LitKind::Num,
            text: text.trim().chars().take(64).collect(),
        }
    }

    fn string(content: &str) -> Self {
        Self {
            kind: LitKind::Str,
            text: content.trim().chars().take(512).collect(),
        }
    }

    fn word(text: &str) -> Self {
        Self {
            kind: LitKind::Word,
            text: text.chars().take(64).collect(),
        }
    }

    fn numeric(&self) -> Option<f64> {
        let trimmed = self.text.trim();
        if let Some(hex) = trimmed.strip_prefix("0x") {
            return u32::from_str_radix(hex, 16).ok().map(f64::from);
        }
        trimmed.parse::<f64>().ok()
    }

    fn is_identifier(&self) -> bool {
        self.kind == LitKind::Word && !matches!(self.text.as_str(), "true" | "false" | "null")
    }

    fn equal(&self, other: &Self) -> Option<bool> {
        match (self.kind, other.kind) {
            (LitKind::Num, LitKind::Num) => Some(self.numeric() == other.numeric()),
            (LitKind::Str, LitKind::Str) => Some(self.text == other.text),
            (LitKind::Num, LitKind::Str) | (LitKind::Str, LitKind::Num) => {
                match (self.numeric(), other.numeric()) {
                    (Some(left), Some(right)) => Some(left == right),
                    _ => Some(false),
                }
            }
            (LitKind::Word, LitKind::Word) => {
                if matches!(self.text.as_str(), "true" | "false" | "null")
                    && matches!(other.text.as_str(), "true" | "false" | "null")
                {
                    Some(self.text == other.text)
                } else {
                    None
                }
            }
            _ => None,
        }
    }

    fn compare(&self, other: &Self, ordering: Ordering) -> Option<bool> {
        if let (Some(left), Some(right)) = (self.numeric(), other.numeric()) {
            return Some(left.partial_cmp(&right) == Some(ordering));
        }
        // `' or 'a'<'b--` is an always-true string comparison in the common collations too (C4.5 H1 tautology).
        if self.kind == LitKind::Str && other.kind == LitKind::Str {
            return Some(self.text.cmp(&other.text) == ordering);
        }
        None
    }

    fn like(&self, pattern: &Self) -> Option<bool> {
        if pattern.kind != LitKind::Str || pattern.text.contains('%') || pattern.text.contains('_')
        {
            return None;
        }
        self.equal(pattern)
    }

    fn truthy(&self) -> Option<bool> {
        match self.kind {
            LitKind::Num => Some(self.numeric().map(|value| value != 0.0).unwrap_or(false)),
            LitKind::Str => Some(!self.text.is_empty()),
            LitKind::Word => match self.text.as_str() {
                "true" => Some(true),
                "false" | "null" => Some(false),
                _ => None,
            },
        }
    }

    fn between(&self, low: &Self, high: &Self) -> Option<bool> {
        let value = self.numeric()?;
        let low = low.numeric()?;
        let high = high.numeric()?;
        Some(value >= low && value <= high)
    }
}

/// Detect SQL keyword parts joined across quoted fragments (`'un'+'ion'`, `'un' 'ion'`, `CONCAT('un','ion')`).
fn find_concatenated_keyword(text: &str) -> Option<usize> {
    const KEYWORDS: &[&str] = &[
        "union",
        "select",
        "unionselect",
        "selectunion",
        "information_schema",
        "sleep",
        "from",
        "where",
    ];
    let chars: Vec<char> = text.chars().collect();
    let mut index = 0usize;
    while index < chars.len() {
        if chars.get(index) != Some(&'\'') {
            index += 1;
            continue;
        }
        let start = index;
        let mut fragments = 0usize;
        let mut joined = String::new();
        let mut cursor = index;
        loop {
            if fragments >= 32 || joined.len() > 128 {
                break;
            }
            if chars.get(cursor) != Some(&'\'') {
                break;
            }
            let mut close = cursor.saturating_add(1);
            while let Some(&c) = chars.get(close) {
                if c == '\'' {
                    break;
                }
                close += 1;
            }
            let content: String = chars
                .get(cursor.saturating_add(1)..close)
                .map(|slice| slice.iter().collect())
                .unwrap_or_default();
            if content.len() > 24 {
                break;
            }
            fragments += 1;
            joined.push_str(&content);
            cursor = close.saturating_add(1);
            let mut next = cursor;
            while let Some(&c) = chars.get(next) {
                if c == '+'
                    || c == ' '
                    || c == '\t'
                    || c == ','
                    || c == '|'
                    || c == '&'
                    || c == '.'
                    || c == '/'
                {
                    next = next.saturating_add(1);
                } else {
                    break;
                }
            }
            if chars.get(next) == Some(&'\'') {
                cursor = next;
            } else {
                break;
            }
        }
        if fragments >= 2 {
            let compact: String = joined.chars().filter(|c| !c.is_whitespace()).collect();
            let lowered = compact.to_ascii_lowercase();
            if KEYWORDS.contains(&lowered.as_str()) {
                return Some(start);
            }
        }
        // Advance past the scanned fragment chain: re-scanning from start + 1 made this quadratic (review R1-2).
        index = cursor.max(start.saturating_add(1));
    }
    None
}

/// The content of an unterminated quoted literal: everything up to the first comment starter or statement terminator
/// (so `' or 'a'='a--` compares the operand `a`, not `a--`, review R1-5 regression).
fn literal_tail(text: &str) -> &str {
    let mut end = text.len();
    for marker in ["--", "#", "/*", ";"] {
        if let Some(position) = text.find(marker) {
            end = end.min(position);
        }
    }
    text.get(..end).unwrap_or("").trim()
}

fn parse_integer_literal(text: &str) -> Option<u32> {
    if let Some(hex) = text.strip_prefix("0x") {
        u32::from_str_radix(hex, 16).ok()
    } else {
        text.parse::<u32>().ok()
    }
}

fn is_suspicious_codepoint(value: u32) -> bool {
    matches!(
        value,
        0x27 | 0x22
            | 0x5C
            | 0x60
            | 0x20
            | 0x2D
            | 0x2F
            | 0x2A
            | 0x3B
            | 0x23
            | 0x3D
            | 0x2C
            | 0x28
            | 0x29
    )
}

fn parse_hex_literal(text: &str) -> Option<Vec<u8>> {
    let digits = text.strip_prefix("0x")?;
    if digits.is_empty() || digits.len() > 64 || digits.len() % 2 != 0 {
        return None;
    }
    let mut bytes = Vec::with_capacity(digits.len() / 2);
    let mut index = 0usize;
    while index < digits.len() {
        let pair = digits.get(index..index.saturating_add(2))?;
        bytes.push(u8::from_str_radix(pair, 16).ok()?);
        index += 2;
    }
    Some(bytes)
}

fn is_suspicious_byte(byte: u8) -> bool {
    byte.is_ascii() && is_suspicious_codepoint(u32::from(byte))
}

fn keyword_from_bytes(bytes: &[u8]) -> Option<&'static str> {
    const KEYWORDS: &[&str] = &[
        "union",
        "select",
        "sleep",
        "from",
        "where",
        "concat",
        "information_schema",
    ];
    let lowered: Vec<u8> = bytes.iter().map(u8::to_ascii_lowercase).collect();
    KEYWORDS.iter().copied().find(|keyword| {
        let needle = keyword.as_bytes();
        needle.len() <= lowered.len()
            && lowered.windows(needle.len()).any(|window| window == needle)
    })
}

/// Detect a SQL keyword glued to a numeric prefix with scientific notation, e.g. `1e0union` or `1select`.
fn glued_keyword(text: &str) -> Option<(&'static str, usize)> {
    const GLUED: &[&str] = &["union", "select", "sleep", "from", "where"];
    for keyword in GLUED {
        let Some(position) = text.find(keyword) else {
            continue;
        };
        if position == 0 {
            continue;
        }
        let prefix = text.get(..position).unwrap_or("");
        let numeric_prefix = !prefix.is_empty()
            && prefix
                .chars()
                .all(|c| c.is_ascii_digit() || matches!(c, 'e' | 'E' | '.' | '+' | '-'));
        if numeric_prefix {
            return Some((keyword, position));
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    fn headers(pairs: &[(&str, &str)]) -> Vec<(String, String)> {
        pairs
            .iter()
            .map(|(name, value)| ((*name).to_owned(), (*value).to_owned()))
            .collect()
    }

    fn verdict_for(payload: &str, field: &str) -> Verdict {
        let owned = headers(&[(field, payload)]);
        let input = InspectInput {
            method: "GET",
            path: "/",
            query: None,
            headers: &owned,
            content_type: None,
            body: b"",
        };
        inspect(&input, &SiteSettings::default())
    }

    fn blocks(payload: &str) -> bool {
        verdict_for(payload, "User-Agent").action == Action::Block
    }

    #[test]
    fn mandated_payloads_block_in_a_header_value() {
        for payload in [
            "' OR 1=1--",
            "' OR '1'='1",
            "admin' --",
            "admin' #",
            "admin'/*",
            "' or 1=1 LIMIT 1 --",
        ] {
            let verdict = verdict_for(payload, "User-Agent");
            assert_eq!(verdict.action, Action::Block, "payload {payload:?}");
            assert_eq!(verdict.category, Some("sqli"), "payload {payload:?}");
            assert!(!verdict.evidence.is_empty());
        }
    }

    #[test]
    fn prose_and_names_do_not_block() {
        for benign in [
            "O'Brien",
            "d'arcy@example.com",
            "rock 'n' roll",
            "it's -- fine",
            "'Hello' -- he said",
            "how to select a database",
            "please order by date",
            "Apt #4",
            "The union representative will select a date",
        ] {
            assert!(!blocks(benign), "false positive for {benign:?}");
        }
    }

    #[test]
    fn m2_tautology_is_an_h1_hit_and_policy_hard() {
        let mut ops = 0u64;
        let normalized = normalize_counted("' OR '1'='1", false, &mut ops);
        let scan = Scan::new(&normalized, &mut ops);
        let kinds: Vec<String> = scan
            .tokens
            .iter()
            .map(|token| format!("{:?}:{}", token.kind, token.text(scan.text)))
            .collect();
        let hit = scan.h1(FieldKind::Header);
        assert!(
            hit.is_some(),
            "H1 must fire; text={:?} tokens={kinds:?}",
            scan.text
        );
        if let Some(hit) = hit {
            assert!(
                matches!(
                    policy(&hit, FieldKind::Header, Strictness::Balanced),
                    Decision::Hard
                ),
                "H1 hit must be hard for a header field: {hit:?}"
            );
        }
    }
}
