//! `ux-docs` checks for T-0023 (internationalization and localization strategy, `docs/UX/I18N.md`).
//!
//! The module checks the strategy document against the files that really exist, against the other UX documents and
//! against the master specification. The rules, stated here because this module is the reference implementation of
//! the pieces the document promises:
//!
//! * `## Status and limits` says honestly what is design only today: `cargo xtask i18n check` is a stub until T-0082,
//!   the pseudo-locale generator and the browser overflow harness arrive with T-0082, the formatting helpers with
//!   T-0083 and the icon inventory with T-0034.
//! * `## Message format` names Fluent and gives at least ten real key examples with their file; every cited key is
//!   defined exactly once in the named `i18n/en/*.ftl` file and every cited value equals the file's value, so an
//!   invented key or a paraphrase is a finding.
//! * `## Key naming` carries the semantic pattern (at least two lower-case hyphen-separated parts, never sentences).
//! * `## File layout` lists exactly the `.ftl` files that exist under `i18n/en/` (no missing and no extra file), gives
//!   the `i18n/<locale>/<area>.ftl` pattern, the planned area files of T-0082 and the rule for adding a new area.
//! * `## Fallback and missing keys` states the `locale → language → en` chain and the runtime behaviour of a missing
//!   key; every key defined in `i18n/en/*.ftl` is unique across the files.
//! * `## Pseudo-locale` defines the exact transform (accent map, `ceil(40%)` filler per word, the deliberate
//!   8-character cap and bracket markers) and the worked examples in the document are evaluated by
//!   [`pseudo_transform`], including the measured expansion of each example (D-7) and a select expression whose
//!   variant text is transformed while the placeable references stay unchanged (D-6); a mismatch is a finding.
//! * `## RTL readiness` lists real CSS logical properties and the physical properties they replace, the server-set
//!   `lang`/`dir` attributes, `dir="auto"`/`dir="ltr"` handling and a mirrored-icon table. The icon table is honest
//!   about the design directory: while `design/` has no icon files the document must say so, and once icons exist the
//!   table must name them; the same section compares its viewport list with `docs/UX/RESPONSIVE.md` and its print
//!   margin with the canonical value RESPONSIVE.md owns.
//! * `## Locale negotiation` gives the order account setting, cookie, `Accept-Language`, default and the
//!   `Content-Language`/`Vary` behaviour; the language section names the components that ACCESSIBILITY.md maps to
//!   WCAG 3.1.1 and 3.1.2 and the seven viewports of RESPONSIVE.md.
//! * `## Formatting` fixes date, time, number, percentage, byte, duration, relative-time and time-zone rules and must
//!   carry every example of the format table of `docs/UX/CONTENT.md`, so the two documents cannot drift apart. The
//!   message column is Fluent only (D-5): ICU `, plural,` and `{#` in a cell are findings, a `$count` message must use
//!   the Fluent selector, and the content-strategy format table is scanned for the same ICU markers.
//! * `## Not translated` lists the machine identifiers with the formats the master specification defines (Ray ID
//!   16 hex + `-HDD1`, `rule_` plus 26 base32 characters, `ray_id`, JSON logs, `ERR-`, `AUD-`, `MET-`) and names what
//!   is translated.
//! * `## Email localization` covers every activation email that `docs/UX/ONBOARDING.md` declares and the email area
//!   file of T-0110, with the whole-email fallback and the HTML and text variants.
//! * `## Translator workflow` needs no external service: the section may contain no URL, the hand-off is files in the
//!   repository, the context-note format is defined, and the missing/unused/placeholder lint is labelled as the stub
//!   it is until T-0082.
//! * `## Launch locales` is compared with the `locales` key of `hdd.live.example.yaml` in both directions and requires
//!   the criteria table for adding a locale.
//! * `## Test strategy` covers the pseudo-locale overflow test (scroll width vs client width), missing-key detection
//!   and plural tests, and points at the seven viewports.
//!
//! The rules are document linters: a missing document, an empty section, a malformed table or an absent cross-document
//! source is a finding, never a panic. The values this module knows by itself are the design decisions the task asks
//! for (the pseudo-locale algorithm, the logical-property list, the required section list and token groups); the
//! registry values (keys, file names, the profile locales, the accessibility owners, the viewports) are read from the
//! repository at run time.

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

use regex::Regex;

use crate::util::{Finding, read_text, walk_files};

use super::{MdTable, finding, section_body, tables_in};

/// The strategy document (T-0023 deliverable).
pub const I18N: &str = "docs/UX/I18N.md";
/// The profile example whose `locales` key sets the launch set.
pub const PROFILE_EXAMPLE: &str = "hdd.live.example.yaml";
/// The content strategy this document must agree with.
pub const CONTENT: &str = "docs/UX/CONTENT.md";
/// The accessibility document that owns the WCAG 3.1.1 and 3.1.2 rules.
pub const ACCESSIBILITY: &str = "docs/UX/ACCESSIBILITY.md";
/// The responsive document that owns the seven viewports and the print margin.
pub const RESPONSIVE: &str = "docs/UX/RESPONSIVE.md";
/// The onboarding document that declares the four activation emails.
pub const ONBOARDING: &str = "docs/UX/ONBOARDING.md";
/// The English locale directory, read at run time so the file table cannot drift.
pub const FTL_DIR: &str = "i18n/en";
/// The design directory: while it has no icon files the mirrored-icon table must say so.
pub const DESIGN_DIR: &str = "design";

/// The level-2 sections of `docs/UX/I18N.md`, in the order the task steps define.
pub const SECTIONS: [&str; 14] = [
    "Status and limits",
    "Message format",
    "Key naming",
    "File layout",
    "Fallback and missing keys",
    "Pseudo-locale",
    "RTL readiness",
    "Locale negotiation",
    "Formatting",
    "Not translated",
    "Email localization",
    "Translator workflow",
    "Launch locales",
    "Test strategy",
];

/// A semantic i18n key stem, the same shape the copy-deck style check uses. New keys have at least two parts and the
/// single-word B13 key `tagline` is grandfathered.
pub const KEY_SHAPE: &str = r"^[a-z0-9]+(-[a-z0-9]+)*$";

/// The minimum number of real key examples of A1.
pub const MIN_KEY_EXAMPLES: usize = 10;
/// The minimum number of logical CSS properties of A2.
pub const MIN_LOGICAL_PROPERTIES: usize = 10;
/// The minimum number of mirrored-icon roles in the RTL table.
pub const MIN_ICON_ROLES: usize = 8;
/// The minimum number of criteria for adding a locale.
pub const MIN_LOCALE_CRITERIA: usize = 5;
/// The minimum number of translator-workflow steps.
pub const MIN_WORKFLOW_STEPS: usize = 5;
/// The minimum number of test rows.
pub const MIN_TEST_ROWS: usize = 10;

/// The letters the pseudo-locale transform accents, in alphabet order.
pub const ACCENT: [(&str, &str); 26] = [
    ("a", "á"),
    ("b", "ƀ"),
    ("c", "ç"),
    ("d", "ð"),
    ("e", "é"),
    ("f", "ƒ"),
    ("g", "ğ"),
    ("h", "ĥ"),
    ("i", "í"),
    ("j", "ĵ"),
    ("k", "ķ"),
    ("l", "ĺ"),
    ("m", "ɱ"),
    ("n", "ñ"),
    ("o", "ó"),
    ("p", "þ"),
    ("q", "ɋ"),
    ("r", "ŕ"),
    ("s", "š"),
    ("t", "ţ"),
    ("u", "ú"),
    ("v", "ṽ"),
    ("w", "ŵ"),
    ("x", "ẋ"),
    ("y", "ý"),
    ("z", "ž"),
];

/// The filler character appended after an accented word.
pub const FILLER: char = '·';
/// The opening bracket marker of a pseudo-locale message.
pub const PSEUDO_OPEN: &str = "[[";
/// The closing bracket marker of a pseudo-locale message.
pub const PSEUDO_CLOSE: &str = "]]";
/// The cap of filler characters per word.
pub const MAX_PADDING: usize = 8;

/// The real CSS logical properties the document may list: `(logical property, physical property it replaces)`.
pub const LOGICAL_PROPERTIES: [(&str, &str); 20] = [
    ("margin-inline-start", "margin-left"),
    ("margin-inline-end", "margin-right"),
    ("margin-block-start", "margin-top"),
    ("margin-block-end", "margin-bottom"),
    ("padding-inline-start", "padding-left"),
    ("padding-inline-end", "padding-right"),
    ("padding-block-start", "padding-top"),
    ("padding-block-end", "padding-bottom"),
    ("border-inline-start", "border-left"),
    ("border-inline-end", "border-right"),
    ("border-start-start-radius", "border-top-left-radius"),
    ("border-start-end-radius", "border-top-right-radius"),
    ("border-end-start-radius", "border-bottom-left-radius"),
    ("border-end-end-radius", "border-bottom-right-radius"),
    ("inset-inline-start", "left"),
    ("inset-inline-end", "right"),
    ("inline-size", "width"),
    ("block-size", "height"),
    ("min-inline-size", "min-width"),
    ("max-inline-size", "max-width"),
];

/// The physical properties the strategy bans in an RTL-safe component stylesheet (the `Replaces` column).
pub const BANNED_PHYSICAL: [&str; 8] = [
    "margin-left",
    "margin-right",
    "padding-left",
    "padding-right",
    "border-left",
    "border-right",
    "text-align: left",
    "float: left",
];

/// The area files T-0082 step 7 seeds. The files that exist now (the B1 batch plus `errors.ftl`) are the first
/// delivery; a message keeps its key when it moves into its area file.
pub const AREA_FILES: [&str; 7] = [
    "common", "auth", "app", "admin", "public", "errors", "email",
];

/// The token a document uses while `design/` has no icon inventory.
pub const NO_ICONS_MARKER: &str = "no icon inventory exists yet";

/// The exact `Vary` value the HTML response must send so a shared cache cannot mix locales.
pub const VARY: &str = "Vary: Accept-Language, Cookie";

/// One message line of a Fluent file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Message {
    /// 1-based line number in the file.
    pub line: usize,
    /// The key on the left of `=`. Empty when the line is malformed.
    pub key: String,
    /// The value on the right of `=`, trimmed.
    pub value: String,
}

/// The messages of every `i18n/en/*.ftl` file, keyed by repository-relative path.
pub(crate) type Ftl = BTreeMap<String, Vec<Message>>;

/// A `ux-docs` finding at `location`.
fn at(location: impl Into<String>, message: impl Into<String>) -> Finding {
    finding(location, message)
}

/// A character that can continue a key, a CSS property, a viewport or an id.
fn is_token_char(c: char) -> bool {
    c.is_alphanumeric() || c == '_' || c == '-' || c == '.' || c == '/'
}

/// True when `text` contains `token` as a whole token (review lesson 1).
fn has_token(text: &str, token: &str) -> bool {
    if token.is_empty() {
        return false;
    }
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

/// The body lines of the level-2 section `title`, or `None` when it is missing.
fn section_lines(doc: &str, title: &str) -> Option<Vec<(usize, String)>> {
    section_body(doc, title)
}

/// The body text of the level-2 section `title`, or `None` when it is missing.
fn section_text(doc: &str, title: &str) -> Option<String> {
    section_lines(doc, title).map(|lines| {
        lines
            .into_iter()
            .map(|(_, line)| line)
            .collect::<Vec<_>>()
            .join("\n")
    })
}

/// Every Markdown table of the level-2 section `title`, in order.
fn section_tables(doc: &str, title: &str) -> Vec<MdTable> {
    section_lines(doc, title).map_or_else(Vec::new, |lines| tables_in(&lines))
}

/// The first Markdown table of the level-2 section `title`.
fn first_table(doc: &str, title: &str) -> Option<MdTable> {
    section_tables(doc, title).into_iter().next()
}

/// A header index for a required column, or a finding naming the column.
fn require_column(header: &[String], name: &str, location: &str) -> Result<usize, Finding> {
    super::column(header, name).ok_or_else(|| {
        at(
            location,
            format!("the table has no `{name}` column, so the rule cannot be checked"),
        )
    })
}

/// The `(line, cell)` of a row at `index`.
fn cell(row: &(usize, Vec<String>), index: usize) -> (usize, &str) {
    (row.0, row.1.get(index).map_or("", String::as_str).trim())
}

/// Parse the messages of one Fluent file: comment and blank lines are skipped.
pub(crate) fn parse_ftl(text: &str) -> Vec<Message> {
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

/// Build the printed deck from `(path, text)` pairs, as the rule functions expect it (test fixtures only).
#[cfg(test)]
pub(crate) fn deck(files: &[(String, String)]) -> Ftl {
    files
        .iter()
        .map(|(path, text)| (path.clone(), parse_ftl(text)))
        .collect()
}

/// The first message defining `key` in `messages`.
fn message_for<'a>(messages: &'a [Message], key: &str) -> Option<&'a Message> {
    messages.iter().find(|message| message.key == key)
}

/// Remove backticks and surrounding whitespace from a table cell.
fn bare(cell: &str) -> String {
    cell.trim().trim_matches('`').trim().to_owned()
}

/// The lower-case form of `text`, for case-insensitive comparisons of prose.
fn lower(text: &str) -> String {
    text.to_lowercase()
}

/// True when the lower-cased `text` contains `needle` (case-insensitive phrase check).
fn mentions(text: &str, needle: &str) -> bool {
    lower(text).contains(&lower(needle))
}

/// The accent character of one ASCII letter.
fn accent(c: char) -> Option<char> {
    if c.is_ascii_lowercase() {
        ACCENT
            .iter()
            .find(|(letter, _)| *letter == c.to_string())
            .and_then(|(_, pseudo)| pseudo.chars().next())
    } else if c.is_ascii_uppercase() {
        ACCENT
            .iter()
            .find(|(letter, _)| *letter == c.to_ascii_lowercase().to_string())
            .and_then(|(_, pseudo)| pseudo.chars().next())
            .and_then(|c| c.to_uppercase().next())
    } else {
        None
    }
}

/// The filler count of a word of `letters` letters: `ceil(40%)`, capped at [`MAX_PADDING`].
pub(crate) fn padding(letters: usize) -> usize {
    (2 * letters).div_ceil(5).min(MAX_PADDING)
}

/// The result of the reference pseudo-locale transform: the transformed text (without the bracket markers), the
/// number of ASCII letters that were accented, and the number of filler characters emitted (D-7).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct PseudoMetrics {
    /// The transformed text, before the bracket markers are added.
    pub text: String,
    /// The number of ASCII letters the transform accented.
    pub letters: usize,
    /// The number of filler characters the transform emitted.
    pub fillers: usize,
}

impl PseudoMetrics {
    /// The measured expansion in whole percent, rounded half up; `None` when the message has no letters.
    pub(crate) fn expansion_percent(&self) -> Option<usize> {
        if self.letters == 0 {
            return None;
        }
        Some((self.fillers * 200 + self.letters) / (2 * self.letters))
    }

    /// The cell of the measured-expansion column: `fillers/letters = percent%`, or `n/a (no letters)`.
    pub(crate) fn expansion_cell(&self) -> String {
        match self.expansion_percent() {
            Some(percent) => format!("{}/{} = {percent}%", self.fillers, self.letters),
            None => "n/a (no letters)".to_owned(),
        }
    }
}

/// True for a placeable reference: `$var`, a term `-term`, or a function call such as `NUMBER($n)` (D-6).
fn is_placeable_reference(text: &str) -> bool {
    let text = text.trim();
    let is_identifier = |value: &str| {
        !value.is_empty() && value.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
    };
    if let Some(rest) = text.strip_prefix('$') {
        return is_identifier(rest);
    }
    if let Some(rest) = text.strip_prefix('-') {
        return is_identifier(rest);
    }
    match text.split_once('(') {
        Some((name, args)) => {
            !name.is_empty()
                && name
                    .chars()
                    .all(|c| c.is_ascii_uppercase() || c.is_ascii_digit() || c == '_')
                && args.ends_with(')')
        }
        None => false,
    }
}

/// Collect the content of a `{ … }` span without the outer braces, consuming through its matching close.
fn take_brace(chars: &mut std::iter::Peekable<std::str::Chars<'_>>) -> String {
    let mut depth = 1_usize;
    let mut inner = String::new();
    for c in chars.by_ref() {
        match c {
            '{' => {
                depth += 1;
                inner.push(c);
            }
            '}' => {
                depth -= 1;
                if depth == 0 {
                    break;
                }
                inner.push(c);
            }
            _ => inner.push(c),
        }
    }
    inner
}

/// The next variant marker of a select expression: the byte offset and whether it is the `*` default.
fn next_variant(rest: &str) -> Option<(usize, bool)> {
    let mut depth = 0_usize;
    for (index, c) in rest.char_indices() {
        match c {
            '{' => depth += 1,
            '}' => depth = depth.saturating_sub(1),
            '[' if depth == 0 => return Some((index, false)),
            '*' if depth == 0
                && rest
                    .get(index + 1..)
                    .is_some_and(|after| after.starts_with('[')) =>
            {
                return Some((index, true));
            }
            _ => {}
        }
    }
    None
}

/// Transform the variants of a select expression: the variant keys are copied and the variant text is transformed
/// like the rest of the message (D-6).
fn transform_variants(mut rest: &str, metrics: &mut PseudoMetrics) {
    while let Some((start, star)) = next_variant(rest) {
        transform_text(&rest[..start], metrics);
        let mut cursor = start;
        if star {
            metrics.text.push('*');
            cursor += 1;
        }
        metrics.text.push('[');
        cursor += 1;
        rest = &rest[cursor..];
        let Some(close) = rest.find(']') else {
            transform_text(rest, metrics);
            return;
        };
        metrics.text.push_str(&rest[..close]);
        metrics.text.push(']');
        rest = &rest[close + 1..];
    }
    transform_text(rest, metrics);
}

/// Transform one brace span: a select expression keeps its selector reference and variant keys and transforms the
/// variant text; a placeable reference is copied unchanged (D-6).
fn transform_placeable(inner: &str, metrics: &mut PseudoMetrics) {
    let arrow = inner.find("->");
    let left_is_reference = inner
        .split_once("->")
        .map(|(left, _)| is_placeable_reference(left))
        .unwrap_or(false);
    if let (Some(arrow), true) = (arrow, left_is_reference) {
        let (left, right) = inner.split_at(arrow);
        metrics.text.push('{');
        metrics.text.push_str(left);
        metrics.text.push_str("->");
        transform_variants(&right[2..], metrics);
        metrics.text.push('}');
    } else {
        metrics.text.push('{');
        metrics.text.push_str(inner);
        metrics.text.push('}');
    }
}

/// Transform `text` into `metrics`: accent and expand words, copy placeable references, transform selector variants.
fn transform_text(text: &str, metrics: &mut PseudoMetrics) {
    let mut chars = text.chars().peekable();
    while let Some(c) = chars.next() {
        if c == '{' {
            let inner = take_brace(&mut chars);
            transform_placeable(&inner, metrics);
            continue;
        }
        if c.is_ascii_alphabetic() {
            let mut word = String::new();
            word.push(c);
            while let Some(next) = chars.peek() {
                if next.is_ascii_alphabetic() {
                    if let Some(taken) = chars.next() {
                        word.push(taken);
                    }
                } else {
                    break;
                }
            }
            for letter in word.chars() {
                metrics.text.push(accent(letter).unwrap_or(letter));
            }
            let count = padding(word.len());
            metrics.letters += word.len();
            metrics.fillers += count;
            for _ in 0..count {
                metrics.text.push(FILLER);
            }
            continue;
        }
        metrics.text.push(c);
    }
}

/// The reference pseudo-locale transform of T-0023 step 1:
///
/// 1. a placeable reference (`$var`, a term `-term`, or a function call such as `NUMBER($n)`) is copied unchanged and
///    does not expand;
/// 2. in a select expression (`{ $count -> [one] … *[other] … }`) the selector reference and the variant keys are
///    copied and the variant text is transformed like the rest of the message (D-6);
/// 3. a maximal run of ASCII letters is accented letter by letter (case preserved) and receives [`padding`] filler
///    characters, counted over the run's letter count, capped at [`MAX_PADDING`] (a deliberate limit, D-7);
/// 4. every other character is copied unchanged;
/// 5. the message is wrapped in the bracket markers.
pub(crate) fn pseudo_metrics(input: &str) -> PseudoMetrics {
    let mut metrics = PseudoMetrics {
        text: String::with_capacity(input.len() * 2),
        letters: 0,
        fillers: 0,
    };
    transform_text(input, &mut metrics);
    metrics
}

/// The reference pseudo-locale transform with its bracket markers (test and fixture use; the check evaluates the
/// metrics so it can verify the measured expansion as well).
#[cfg(test)]
pub(crate) fn pseudo_transform(input: &str) -> String {
    let metrics = pseudo_metrics(input);
    format!("{PSEUDO_OPEN}{}{PSEUDO_CLOSE}", metrics.text)
}

/// The locale tags of the profile example: the value of its `locales` key.
fn profile_locales(profile: &str) -> Option<Vec<String>> {
    for line in profile.lines() {
        let trimmed = line.trim_start();
        let Some(rest) = trimmed.strip_prefix("locales:") else {
            continue;
        };
        let rest = rest.split('#').next().unwrap_or("").trim();
        let inner = rest.strip_prefix('[')?.strip_suffix(']')?;
        let mut out = Vec::new();
        for item in inner.split(',') {
            let tag = item.trim().trim_matches('"').trim_matches('\'').trim();
            if !tag.is_empty() {
                out.push(tag.to_owned());
            }
        }
        return Some(out);
    }
    None
}

/// True for a plausible BCP 47 locale tag: a 2-3 letter lower-case language, optional hyphen-separated subtags.
fn valid_locale_tag(tag: &str) -> bool {
    let Some(re) = Regex::new(r"^[a-z]{2,3}(-[A-Za-z0-9]{2,8})*$").ok() else {
        return false;
    };
    re.is_match(tag)
}

/// The viewport tokens (`WxH`) of the `## Device matrix` table of the responsive document.
fn responsive_viewports(responsive: &str) -> Vec<String> {
    let mut out = Vec::new();
    let Some(table) = first_table(responsive, "Device matrix") else {
        return out;
    };
    let Ok(re) = Regex::new(r"^\d{2,4}x\d{2,4}$") else {
        return out;
    };
    for row in &table.rows {
        let (_, cell) = cell(row, 0);
        if re.is_match(cell) && !out.iter().any(|known| known == cell) {
            out.push(cell.to_owned());
        }
    }
    out
}

/// The canonical print margin (`<n> mm margins`) of the responsive document.
fn responsive_print_margin(responsive: &str) -> Option<u32> {
    let re = Regex::new(r"(\d+)\s*mm\s+margins").ok()?;
    re.captures(responsive)
        .and_then(|captures| captures.get(1))
        .and_then(|value| value.as_str().parse::<u32>().ok())
}

/// Every `<n> mm margins` value in `text` (the print-margin form the responsive document owns).
fn marked_margins(text: &str) -> Vec<u32> {
    let mut out = Vec::new();
    let Ok(re) = Regex::new(r"(\d+)\s*mm\s+margins") else {
        return out;
    };
    for captures in re.captures_iter(text) {
        if let Some(value) = captures
            .get(1)
            .and_then(|value| value.as_str().parse::<u32>().ok())
        {
            out.push(value);
        }
    }
    out
}

/// The design icon files that exist, as repository-relative paths. An icon is an `.svg`, `.png`, `.ico` or `.webp`
/// file under `design/`.
fn design_icons(root: &Path) -> Vec<String> {
    let dir = root.join(DESIGN_DIR);
    if !dir.is_dir() {
        return Vec::new();
    }
    walk_files(&dir)
        .into_iter()
        .filter(|path| {
            path.extension()
                .and_then(|extension| extension.to_str())
                .is_some_and(|extension| {
                    matches!(
                        extension.to_ascii_lowercase().as_str(),
                        "svg" | "png" | "ico" | "webp"
                    )
                })
        })
        .map(|path| {
            path.strip_prefix(root)
                .unwrap_or(&path)
                .to_string_lossy()
                .replace('\\', "/")
        })
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

/// The owner components of the WCAG 3.1.1 and 3.1.2 rows of the accessibility document, as whole tokens.
fn accessibility_language_owners(accessibility: &str) -> (Option<String>, Vec<String>) {
    let mut page_pattern = None;
    let mut components = Vec::new();
    let Ok(component_re) = Regex::new(r"[A-Z][A-Za-z0-9]+") else {
        return (page_pattern, components);
    };
    for line in accessibility.lines() {
        let Some(cells) = super::cells(line) else {
            continue;
        };
        let Some(criterion) = cells.first().map(String::as_str).map(str::trim) else {
            continue;
        };
        let owner = cells
            .iter()
            .rev()
            .find(|cell| !cell.trim().is_empty())
            .map_or("", String::as_str);
        if criterion == "3.1.1" && owner.contains("page pattern") {
            page_pattern = owner
                .split_once("page pattern:")
                .map(|(_, name)| name.trim().to_owned());
        }
        if criterion == "3.1.2" {
            for token in component_re.find_iter(owner) {
                let token = token.as_str().to_owned();
                if !components.contains(&token) {
                    components.push(token);
                }
            }
        }
    }
    (page_pattern, components)
}

/// The activation email names of the onboarding document's `## Activation emails` table.
fn activation_emails(onboarding: &str) -> Vec<String> {
    let mut out = Vec::new();
    let Some(table) = first_table(onboarding, "Activation emails") else {
        return out;
    };
    for row in &table.rows {
        let (_, name) = cell(row, 0);
        let name = name.trim();
        if !name.is_empty() && !out.iter().any(|known| known == name) {
            out.push(name.to_owned());
        }
    }
    out
}

/// The examples of a content-strategy format row: the double-quoted spans of the `Example` cell when it has them,
/// otherwise the whole cell.
fn quoted_examples(cell: &str) -> Vec<String> {
    let Ok(re) = Regex::new(r#""([^"]+)""#) else {
        return vec![cell.trim().to_owned()];
    };
    let found: Vec<String> = re
        .captures_iter(cell)
        .filter_map(|captures| captures.get(1))
        .map(|value| value.as_str().trim().to_owned())
        .filter(|value| !value.is_empty())
        .collect();
    if found.is_empty() {
        let whole = cell.trim().to_owned();
        if whole.is_empty() {
            Vec::new()
        } else {
            vec![whole]
        }
    } else {
        found
    }
}

/// The `(item, example)` pairs of the `## Number, date and unit formats` table of the content strategy.
fn content_format_examples(content: &str) -> Vec<(String, String)> {
    let mut out = Vec::new();
    let Some(table) = first_table(content, "Number, date and unit formats") else {
        return out;
    };
    let (Ok(item), Ok(example)) = (
        require_column(&table.header, "Item", CONTENT),
        require_column(&table.header, "Example", CONTENT),
    ) else {
        return out;
    };
    for row in &table.rows {
        let (_, item) = cell(row, item);
        let (_, example) = cell(row, example);
        if item.is_empty() || example.is_empty() {
            continue;
        }
        for value in quoted_examples(example) {
            out.push((item.to_owned(), value));
        }
    }
    out
}

/// Whole T-0023 check on the repository at `root`, with the master specification text passed by the caller.
pub fn check(root: &Path, spec: &str) -> Vec<Finding> {
    check_with_spec(root, spec)
}

/// Load one required document of another task, reporting a missing or byte-order-marked file as a finding.
fn load_required(root: &Path, path: &str, why: &str, out: &mut Vec<Finding>) -> String {
    match read_text(&root.join(path)) {
        Ok(text) => {
            if text.starts_with('\u{feff}') {
                out.push(at(
                    path,
                    "the file starts with a byte-order mark; UTF-8 without BOM is required (T-0023 step 1)",
                ));
            }
            text
        }
        Err(error) => {
            out.push(at(path, format!("cannot be read ({error}); {why}")));
            String::new()
        }
    }
}

/// Every `i18n/en/*.ftl` file, parsed, plus the findings of loading them.
fn load_ftl(root: &Path) -> (Ftl, Vec<Finding>) {
    let mut out = Vec::new();
    let dir = root.join(FTL_DIR);
    let Ok(entries) = std::fs::read_dir(&dir) else {
        out.push(at(
            FTL_DIR,
            "the English locale directory does not exist, so the file layout and the example keys cannot be checked (T-0023 step 1)",
        ));
        return (BTreeMap::new(), out);
    };
    let mut files: Vec<(String, String)> = Vec::new();
    for entry in entries.flatten() {
        let path = entry.path();
        if path.extension().and_then(|extension| extension.to_str()) != Some("ftl") {
            continue;
        }
        let relative = crate::util::rel(root, &path);
        match read_text(&path) {
            Ok(text) => {
                if text.starts_with('\u{feff}') {
                    out.push(at(
                        &relative,
                        "the file starts with a byte-order mark; UTF-8 without BOM is required (T-0023 step 1)",
                    ));
                }
                files.push((relative, text));
            }
            Err(error) => out.push(at(&relative, format!("cannot be read: {error}"))),
        }
    }
    files.sort_by(|left, right| left.0.cmp(&right.0));
    if files.is_empty() {
        out.push(at(
            FTL_DIR,
            "no `.ftl` file exists under `i18n/en/`, so the file layout cannot be checked (T-0023 step 1)",
        ));
    }
    let mut deck = Ftl::new();
    for (path, text) in files {
        let messages = parse_ftl(&text);
        for message in &messages {
            if message.key.is_empty() {
                out.push(at(
                    format!("{path}:{}", message.line),
                    "the line is not a `key = value` message (T-0023 step 1)",
                ));
            }
        }
        deck.insert(path, messages);
    }
    (deck, out)
}

/// Whole T-0023 check on the repository at `root`, with the master specification text.
pub(crate) fn check_with_spec(root: &Path, spec: &str) -> Vec<Finding> {
    let mut out = Vec::new();
    let (ftl, mut ftl_findings) = load_ftl(root);
    out.append(&mut ftl_findings);
    out.extend(key_uniqueness_findings(&ftl));
    let profile = load_required(
        root,
        PROFILE_EXAMPLE,
        "the profile example that carries the `locales` key does not exist (T-0023 step 7)",
        &mut out,
    );
    let content = load_required(
        root,
        CONTENT,
        "the content strategy whose translation guidance and format table are compared does not exist (T-0023 step 6)",
        &mut out,
    );
    let onboarding = load_required(
        root,
        ONBOARDING,
        "the onboarding document that declares the four activation emails does not exist (T-0023 step 5)",
        &mut out,
    );
    match read_text(&root.join(I18N)) {
        Ok(doc) => {
            if doc.starts_with('\u{feff}') {
                out.push(at(
                    I18N,
                    "the file starts with a byte-order mark; UTF-8 without BOM is required (T-0023 step 1)",
                ));
            }
            out.extend(structure_findings(&doc));
            out.extend(message_format_findings(&doc, &ftl));
            out.extend(key_naming_findings(&doc));
            out.extend(file_layout_findings(&doc, &ftl));
            out.extend(fallback_findings(&doc));
            out.extend(pseudo_findings(&doc));
            out.extend(rtl_findings(&doc, root, spec));
            out.extend(negotiation_findings(&doc, spec));
            out.extend(formatting_findings(&doc, &content, spec));
            out.extend(not_translated_findings(&doc, spec));
            out.extend(email_findings(&doc, &onboarding));
            out.extend(translator_findings(&doc, &content));
            out.extend(launch_findings(&doc, &profile));
            out.extend(test_strategy_findings(&doc, spec));
        }
        Err(_) => out.push(at(
            I18N,
            "the internationalization and localization strategy does not exist (T-0023 deliverable)",
        )),
    }
    out
}

/// T-0023 step 1: the document has the required level-2 sections in the required order and says honestly what is
/// design only.
pub(crate) fn structure_findings(doc: &str) -> Vec<Finding> {
    let mut out = Vec::new();
    let headings: Vec<String> = doc
        .lines()
        .filter_map(|line| line.trim_start().strip_prefix("## ").map(str::trim))
        .filter(|heading| !heading.is_empty() && !heading.starts_with('#'))
        .map(str::to_owned)
        .collect();
    let mut last = None;
    for required in SECTIONS {
        match headings
            .iter()
            .position(|heading| heading.eq_ignore_ascii_case(required))
        {
            None => out.push(at(
                I18N,
                format!("no `## {required}` section exists (T-0023 step 1 to 8)"),
            )),
            Some(position) => {
                if let Some(previous) = last
                    && position < previous
                {
                    out.push(at(
                        I18N,
                        format!(
                            "the sections are out of order: `## {required}` appears before a section that must follow it (T-0023 step 1 to 8)"
                        ),
                    ));
                }
                last = Some(position);
            }
        }
    }
    for token in ["stub", "T-0082", "T-0083", "T-0034", "i18n check"] {
        if !mentions(doc, token) {
            out.push(at(
                I18N,
                format!(
                    "the document must say that `{token}` is not delivered yet: the runtime is design only today (T-0023 step 1)"
                ),
            ));
        }
    }
    if !mentions(doc, "operator decides") {
        out.push(at(
            I18N,
            "the status section must say that the operator decides which locales ship (T-0023 step 7)",
        ));
    }
    out
}

/// T-0023 A1: at least ten real key examples, each defined in the named `i18n/en/*.ftl` file with the value the
/// document shows.
pub(crate) fn message_format_findings(doc: &str, ftl: &Ftl) -> Vec<Finding> {
    let mut out = Vec::new();
    let Some(table) = first_table(doc, "Message format") else {
        out.push(at(
            I18N,
            "no `## Message format` table with real key examples exists (T-0023 A1)",
        ));
        return out;
    };
    let (Ok(key_column), Ok(file_column), Ok(value_column)) = (
        require_column(&table.header, "Key", I18N),
        require_column(&table.header, "File", I18N),
        require_column(&table.header, "Value", I18N),
    ) else {
        return out;
    };
    let Ok(shape) = Regex::new(KEY_SHAPE) else {
        out.push(at(I18N, "cannot compile the i18n key pattern"));
        return out;
    };
    let mut count = 0_usize;
    for row in &table.rows {
        let (line, key) = cell(row, key_column);
        let (_, file) = cell(row, file_column);
        let (_, value) = cell(row, value_column);
        let key = bare(key);
        let file = bare(file);
        if key.is_empty() && file.is_empty() {
            continue;
        }
        count += 1;
        if !shape.is_match(&key) {
            out.push(at(
                format!("{I18N}:{line}"),
                format!(
                    "the example key `{key}` is not a semantic hyphenated stem (T-0023 A1 and step 1)"
                ),
            ));
        }
        let Some(messages) = ftl.get(&file) else {
            out.push(at(
                format!("{I18N}:{line}"),
                format!(
                    "the example key `{key}` names `{file}`, which is not one of the `.ftl` files under `i18n/en/` (T-0023 step 1)"
                ),
            ));
            continue;
        };
        match message_for(messages, &key) {
            None => out.push(at(
                format!("{I18N}:{line}"),
                format!("the key `{key}` is not defined in `{file}` (T-0023 A1)"),
            )),
            Some(message) if message.value != value => out.push(at(
                format!("{I18N}:{line}"),
                format!(
                    "the value of `{key}` differs from the value in `{file}` (T-0023 A1): the document must quote the real message"
                ),
            )),
            Some(_) => {}
        }
    }
    if count < MIN_KEY_EXAMPLES {
        out.push(at(
            I18N,
            format!(
                "the message-format table has {count} key examples; at least {MIN_KEY_EXAMPLES} are required (T-0023 A1)"
            ),
        ));
    }
    out
}

/// T-0023 step 1: the semantic key-naming convention is stated.
pub(crate) fn key_naming_findings(doc: &str) -> Vec<Finding> {
    let mut out = Vec::new();
    let Some(text) = section_text(doc, "Key naming") else {
        out.push(at(
            I18N,
            "no `## Key naming` section exists (T-0023 step 1)",
        ));
        return out;
    };
    if !text.contains(KEY_SHAPE) {
        out.push(at(
            I18N,
            format!("the key-naming section does not state the pattern `{KEY_SHAPE}` (T-0023 A1)"),
        ));
    }
    for (token, why) in [
        ("never sentences", "a key is never sentences"),
        ("semantic", "a key is semantic"),
    ] {
        if !mentions(&text, token) {
            out.push(at(
                I18N,
                format!("the key-naming section must say that {why} (T-0023 step 1)"),
            ));
        }
    }
    if !mentions(&text, "at least two") && !mentions(&text, "two parts") {
        out.push(at(
            I18N,
            "the key-naming section must say that a key has at least two parts (T-0023 step 1)",
        ));
    }
    out
}

/// T-0023 step 1: the file layout table lists exactly the `.ftl` files that exist, gives the layout pattern and the
/// planned area files.
pub(crate) fn file_layout_findings(doc: &str, ftl: &Ftl) -> Vec<Finding> {
    let mut out = Vec::new();
    let Some(text) = section_text(doc, "File layout") else {
        out.push(at(
            I18N,
            "no `## File layout` section exists (T-0023 step 1)",
        ));
        return out;
    };
    if !text.contains("i18n/<locale>/<area>.ftl") {
        out.push(at(
            I18N,
            "the file layout must give the `i18n/<locale>/<area>.ftl` pattern (T-0023 step 1)",
        ));
    }
    if !mentions(&text, "new area") {
        out.push(at(
            I18N,
            "the file layout must say how a new area maps to a new file (T-0023 step 1)",
        ));
    }
    for area in AREA_FILES {
        if !has_token(&text, area) {
            out.push(at(
                I18N,
                format!(
                    "the file layout does not name the planned area file `{area}` of T-0082 step 7 (T-0023 step 1)"
                ),
            ));
        }
    }
    if !mentions(&text, "email.ftl") {
        out.push(at(
            I18N,
            "the file layout must name `email.ftl`, the email catalog area file of T-0110 (T-0023 step 1)",
        ));
    }
    let Some(table) = first_table(doc, "File layout") else {
        out.push(at(
            I18N,
            "the `## File layout` section has no table (T-0023 step 1)",
        ));
        return out;
    };
    let (Ok(file_column), Ok(area_column)) = (
        require_column(&table.header, "File", I18N),
        require_column(&table.header, "Area", I18N),
    ) else {
        return out;
    };
    let mut listed: BTreeSet<String> = BTreeSet::new();
    for row in &table.rows {
        let (line, file) = cell(row, file_column);
        let (_, area) = cell(row, area_column);
        let file = bare(file);
        if file.is_empty() {
            out.push(at(
                format!("{I18N}:{line}"),
                "a file-layout row has no file (T-0023 step 1)",
            ));
            continue;
        }
        if !ftl.contains_key(&file) {
            out.push(at(
                format!("{I18N}:{line}"),
                format!(
                    "the file layout lists `{file}`, which is not a `.ftl` file that exists under `i18n/en/` (T-0023 step 1)"
                ),
            ));
        }
        if area.trim().is_empty() {
            out.push(at(
                format!("{I18N}:{line}"),
                format!("the file-layout row for `{file}` has no area (T-0023 step 1)"),
            ));
        }
        if !listed.insert(file.clone()) {
            out.push(at(
                format!("{I18N}:{line}"),
                format!("the file layout lists `{file}` more than once (T-0023 step 1)"),
            ));
        }
    }
    for file in ftl.keys() {
        if !listed.contains(file) {
            out.push(at(
                I18N,
                format!(
                    "the `.ftl` file `{file}` exists but the file layout does not list it (T-0023 step 1)"
                ),
            ));
        }
    }
    out
}

/// T-0023 step 1: the fallback chain and the missing-key behaviour are stated.
pub(crate) fn fallback_findings(doc: &str) -> Vec<Finding> {
    let mut out = Vec::new();
    let Some(text) = section_text(doc, "Fallback and missing keys") else {
        out.push(at(
            I18N,
            "no `## Fallback and missing keys` section exists (T-0023 step 1)",
        ));
        return out;
    };
    for (token, why) in [
        (
            "locale → language → en",
            "the fallback chain is `locale → language → en`",
        ),
        (
            "i18n.missing_key",
            "the stable log event `i18n.missing_key` records a missing message",
        ),
        (
            "compile-time embedding",
            "the loader embeds the files at build time",
        ),
        (
            "fails the build",
            "a missing key fails the build or test in CI",
        ),
        ("marker", "a missing key renders the key with a marker"),
        ("counter", "a missing key increments a counter"),
        ("T-0082", "the runtime arrives with T-0082"),
    ] {
        if !mentions(&text, token) {
            out.push(at(
                I18N,
                format!("the fallback section must state that {why} (T-0023 step 1)"),
            ));
        }
    }
    out
}

/// T-0023 step 1: a key defined in two `i18n/en/*.ftl` files is a finding.
pub(crate) fn key_uniqueness_findings(ftl: &Ftl) -> Vec<Finding> {
    let mut out = Vec::new();
    let mut definitions: BTreeMap<String, Vec<(String, usize)>> = BTreeMap::new();
    for (file, messages) in ftl {
        for message in messages {
            if !message.key.is_empty() {
                definitions
                    .entry(message.key.clone())
                    .or_default()
                    .push((file.clone(), message.line));
            }
        }
    }
    for (key, places) in definitions {
        if places.len() <= 1 {
            continue;
        }
        let first = places.first().map(|(file, line)| (file.as_str(), *line));
        let location = match first {
            Some((file, line)) => format!("{file}:{line}"),
            None => I18N.to_owned(),
        };
        let where_text = places
            .iter()
            .map(|(file, line)| format!("{file}:{line}"))
            .collect::<Vec<_>>()
            .join(", ");
        out.push(at(
            location,
            format!(
                "the key `{key}` is defined {} times across the `i18n/en/` files ({where_text}); a key lives in exactly one area file (T-0023 step 1)",
                places.len()
            ),
        ));
    }
    out
}

/// T-0023 step 1: the pseudo-locale transform is defined exactly and the worked examples of the document are
/// evaluated.
pub(crate) fn pseudo_findings(doc: &str) -> Vec<Finding> {
    let mut out = Vec::new();
    let Some(text) = section_text(doc, "Pseudo-locale") else {
        out.push(at(
            I18N,
            "no `## Pseudo-locale` section exists (T-0023 step 1)",
        ));
        return out;
    };
    for (token, why) in [
        ("40%", "the expansion is 40 percent of the letter count"),
        ("ceil", "the expansion rounds up per word"),
        ("capped at 8", "the filler is capped at 8 per word"),
        (
            "deliberate limit",
            "the filler cap is stated as a deliberate limit (D-7)",
        ),
        ("[[", "the message is wrapped in the opening bracket marker"),
        ("]]", "the message is wrapped in the closing bracket marker"),
        (
            "i18n_plan.rs",
            "the reference implementation is this module",
        ),
        ("T-0082", "the generator arrives with T-0082"),
        ("stub", "`cargo xtask i18n check` is a stub until T-0082"),
        (
            "not shipped",
            "the pseudo locale is not shipped in the profile",
        ),
        (
            "placeable reference",
            "a placeable reference is copied unchanged (D-6)",
        ),
        (
            "variant text",
            "the text of a selector variant is transformed (D-6)",
        ),
        ("selector", "a select expression is handled (D-6)"),
    ] {
        if !mentions(&text, token) {
            out.push(at(
                I18N,
                format!("the pseudo-locale section must state that {why} (T-0023 step 1)"),
            ));
        }
    }
    if !text.contains(FILLER) {
        out.push(at(
            I18N,
            format!("the pseudo-locale section must name the `{FILLER}` filler character (T-0023 step 1)"),
        ));
    }
    let tables = section_tables(doc, "Pseudo-locale");
    let examples = tables.iter().find(|table| {
        super::column(&table.header, "Input").is_some()
            && super::column(&table.header, "Expected pseudo").is_some()
    });
    match examples {
        None => out.push(at(
            I18N,
            "no `| Input | Expected pseudo | Measured expansion |` table exists, so the worked examples cannot be evaluated (T-0023 step 1)",
        )),
        Some(table) => {
            let (Ok(input_column), Ok(expected_column), Ok(expansion_column)) = (
                require_column(&table.header, "Input", I18N),
                require_column(&table.header, "Expected pseudo", I18N),
                require_column(&table.header, "Measured expansion", I18N),
            ) else {
                return out;
            };
            if table.rows.len() < 6 {
                out.push(at(
                    I18N,
                    format!(
                        "the pseudo-locale example table has {} rows; at least six worked examples are required (T-0023 step 1)",
                        table.rows.len()
                    ),
                ));
            }
            let mut selector_examples = 0_usize;
            for row in &table.rows {
                let (line, input) = cell(row, input_column);
                let (_, expected) = cell(row, expected_column);
                let (_, expansion) = cell(row, expansion_column);
                let input = bare(input);
                let expected = bare(expected);
                let expansion = bare(expansion);
                if input.is_empty() && expected.is_empty() {
                    continue;
                }
                let metrics = pseudo_metrics(&input);
                let actual = format!("{PSEUDO_OPEN}{}{PSEUDO_CLOSE}", metrics.text);
                if actual != expected {
                    out.push(at(
                        format!("{I18N}:{line}"),
                        format!(
                            "the pseudo-locale example `{input}` evaluates to `{actual}`, not `{expected}` (T-0023 step 1)"
                        ),
                    ));
                }
                let want = metrics.expansion_cell();
                if expansion != want {
                    out.push(at(
                        format!("{I18N}:{line}"),
                        format!(
                            "the measured expansion of `{input}` is `{want}`, not `{expansion}` (T-0023 D-7): the check computes fillers/letters and the rounded percentage"
                        ),
                    ));
                }
                if input.contains("->") {
                    selector_examples += 1;
                    if !actual.contains("[one]") || !actual.contains("*[other]") {
                        out.push(at(
                            format!("{I18N}:{line}"),
                            "the selector example must keep the `[one]` and `*[other]` variant keys (T-0023 D-6)",
                        ));
                    }
                }
            }
            if selector_examples == 0 {
                out.push(at(
                    I18N,
                    "the worked-example table has no select expression (`[one]`/`*[other]`) example, so the plural path is not evaluated (T-0023 D-6)",
                ));
            }
        }
    }
    let accent_table = tables.iter().find(|table| {
        super::column(&table.header, "Letter").is_some()
            && super::column(&table.header, "Pseudo").is_some()
    });
    match accent_table {
        None => out.push(at(
            I18N,
            "no `| Letter | Pseudo |` accent table exists, so the transform cannot be compared (T-0023 step 1)",
        )),
        Some(table) => {
            let (Ok(letter_column), Ok(pseudo_column)) = (
                require_column(&table.header, "Letter", I18N),
                require_column(&table.header, "Pseudo", I18N),
            ) else {
                return out;
            };
            let mut seen: BTreeSet<String> = BTreeSet::new();
            for row in &table.rows {
                let (line, letter) = cell(row, letter_column);
                let (_, shown) = cell(row, pseudo_column);
                let letter = bare(letter);
                let shown = bare(shown);
                if letter.is_empty() && shown.is_empty() {
                    continue;
                }
                seen.insert(letter.clone());
                let expected = ACCENT
                    .iter()
                    .find(|(lower, _)| *lower == letter)
                    .map(|(_, pseudo)| *pseudo);
                match expected {
                    None => out.push(at(
                        format!("{I18N}:{line}"),
                        format!("`{letter}` is not one of the 26 accented letters (T-0023 step 1)"),
                    )),
                    Some(expected) if expected != shown => out.push(at(
                        format!("{I18N}:{line}"),
                        format!(
                            "the accent for `{letter}` is `{shown}` but the reference transform maps it to `{expected}` (T-0023 step 1)"
                        ),
                    )),
                    Some(_) => {}
                }
            }
            for (letter, _) in ACCENT {
                if !seen.contains(letter) {
                    out.push(at(
                        I18N,
                        format!("the accent table has no row for `{letter}` (T-0023 step 1)"),
                    ));
                }
            }
        }
    }
    out
}

/// T-0023 A2: RTL readiness is concrete (real logical properties, `dir` handling, mirrored-icon honesty) and agrees
/// with the accessibility and responsive documents.
pub(crate) fn rtl_findings(doc: &str, root: &Path, spec: &str) -> Vec<Finding> {
    let mut out = Vec::new();
    let Some(text) = section_text(doc, "RTL readiness") else {
        out.push(at(
            I18N,
            "no `## RTL readiness` section exists (T-0023 step 1 and A2)",
        ));
        return out;
    };
    let tables = section_tables(doc, "RTL readiness");
    let logical = tables
        .iter()
        .find(|table| super::column(&table.header, "Logical property").is_some());
    match logical {
        None => out.push(at(
            I18N,
            "no `| Logical property | Replaces | Use |` table exists (T-0023 A2)",
        )),
        Some(table) => {
            let (Ok(logical_column), Ok(replaces_column)) = (
                require_column(&table.header, "Logical property", I18N),
                require_column(&table.header, "Replaces", I18N),
            ) else {
                return out;
            };
            let mut seen: BTreeSet<String> = BTreeSet::new();
            for row in &table.rows {
                let (line, logical) = cell(row, logical_column);
                let (_, replaces) = cell(row, replaces_column);
                let logical = bare(logical);
                let replaces = bare(replaces);
                if logical.is_empty() && replaces.is_empty() {
                    continue;
                }
                match LOGICAL_PROPERTIES
                    .iter()
                    .find(|(property, _)| *property == logical)
                {
                    None => out.push(at(
                        format!("{I18N}:{line}"),
                        format!(
                            "`{logical}` is not a CSS logical property, so it cannot make a component RTL-safe (T-0023 A2)"
                        ),
                    )),
                    Some((_, physical)) if *physical != replaces => out.push(at(
                        format!("{I18N}:{line}"),
                        format!(
                            "`{logical}` replaces `{physical}` but the table says `{replaces}` (T-0023 A2)"
                        ),
                    )),
                    Some(_) => {
                        seen.insert(logical);
                    }
                }
            }
            if seen.len() < MIN_LOGICAL_PROPERTIES {
                out.push(at(
                    I18N,
                    format!(
                        "the RTL table lists {} logical properties; at least {MIN_LOGICAL_PROPERTIES} are required (T-0023 A2)",
                        seen.len()
                    ),
                ));
            }
        }
    }
    if !mentions(&text, "not allowed") {
        out.push(at(
            I18N,
            "the RTL section must say that the physical property is not allowed (T-0023 A2)",
        ));
    }
    for physical in BANNED_PHYSICAL {
        if !mentions(&text, physical) {
            out.push(at(
                I18N,
                format!("the RTL section must ban the physical property `{physical}` (T-0023 A2)"),
            ));
        }
    }
    for token in [
        "<html",
        "dir=",
        "lang=",
        "dir=\"auto\"",
        "dir=\"ltr\"",
        "server-rendered",
    ] {
        if !mentions(&text, token) {
            out.push(at(
                I18N,
                format!("the RTL section must state the `{token}` handling (T-0023 A2)"),
            ));
        }
    }
    // The accessibility document owns the WCAG rules; compare the owners it gives.
    match read_text(&root.join(ACCESSIBILITY)) {
        Err(error) => out.push(at(
            ACCESSIBILITY,
            format!("cannot be read, so the language owners cannot be compared ({error})"),
        )),
        Ok(accessibility) => {
            let (page_pattern, components) = accessibility_language_owners(&accessibility);
            if let Some(page_pattern) = page_pattern
                && !mentions(&text, &page_pattern)
            {
                out.push(at(
                    I18N,
                    format!(
                        "ACCESSIBILITY.md maps WCAG 3.1.1 to the `{page_pattern}` page pattern; the RTL section must name the same owner (T-0023 step 2)"
                    ),
                ));
            }
            for component in components {
                if !has_token(doc, &component) {
                    out.push(at(
                        I18N,
                        format!(
                            "ACCESSIBILITY.md maps WCAG 3.1.2 to `{component}`; the strategy must name the same component (T-0023 step 2)"
                        ),
                    ));
                }
            }
        }
    }
    for component in ["LocaleSwitcher", "MarkdownRender"] {
        if !has_token(spec, component) {
            out.push(at(
                "docs/SPEC.md",
                format!(
                    "the B11.8 component inventory does not define `{component}`, so the locale owners cannot be compared (T-0023 step 1)"
                ),
            ));
        } else if !has_token(doc, component) {
            out.push(at(
                I18N,
                format!(
                    "the B11.8 component `{component}` carries the locale behaviour and the strategy must name it (T-0023 step 1)"
                ),
            ));
        }
    }
    // The mirrored icons are honest about what the design directory holds.
    let icons = design_icons(root);
    let Some(icon_table) = tables
        .iter()
        .find(|table| super::column(&table.header, "Icon role").is_some())
    else {
        out.push(at(
            I18N,
            "no `| Icon role | Mirrors in RTL | Why |` table exists (T-0023 A2)",
        ));
        return out;
    };
    if icon_table.rows.len() < MIN_ICON_ROLES {
        out.push(at(
            I18N,
            format!(
                "the mirrored-icon table has {} rows; at least {MIN_ICON_ROLES} roles are required (T-0023 A2)",
                icon_table.rows.len()
            ),
        ));
    }
    let Ok(mirrors_column) = require_column(&icon_table.header, "Mirrors in RTL", I18N) else {
        return out;
    };
    let mut mirrors_yes = 0_usize;
    for row in &icon_table.rows {
        let (line, mirrors) = cell(row, mirrors_column);
        match mirrors.trim().to_lowercase().as_str() {
            "yes" => mirrors_yes += 1,
            "no" | "same" => {}
            other => out.push(at(
                format!("{I18N}:{line}"),
                format!(
                    "the `Mirrors in RTL` cell `{other}` must be `yes`, `no` or `same` (T-0023 A2)"
                ),
            )),
        }
    }
    if mirrors_yes < 4 {
        out.push(at(
            I18N,
            format!(
                "the mirrored-icon table marks {mirrors_yes} icons as mirrored; at least four directional roles are required (T-0023 A2)"
            ),
        ));
    }
    if icons.is_empty() {
        if !mentions(&text, NO_ICONS_MARKER) {
            out.push(at(
                I18N,
                format!(
                    "the `design/` directory has no icon files, so the mirrored-icon table must say `{NO_ICONS_MARKER}` (T-0023 A2)"
                ),
            ));
        }
        for extension in [".svg", ".png", ".ico", ".webp"] {
            if mentions(&text, extension) {
                out.push(at(
                    I18N,
                    format!(
                        "the RTL section cites a `{extension}` file while `design/` has no icon inventory; the list is a named requirement for T-0034, not a claim about files (T-0023 A2)"
                    ),
                ));
            }
        }
    } else {
        if mentions(&text, NO_ICONS_MARKER) {
            out.push(at(
                I18N,
                format!(
                    "`design/` now holds {} icon file(s), so the statement `{NO_ICONS_MARKER}` is stale; the table must name the real inventory (T-0023 A2)",
                    icons.len()
                ),
            ));
        }
        for path in &icons {
            let stem = Path::new(path)
                .file_stem()
                .and_then(|stem| stem.to_str())
                .unwrap_or(path.as_str());
            if !has_token(doc, stem) {
                out.push(at(
                    I18N,
                    format!(
                        "the design icon `{path}` is not named in the mirrored-icon table (T-0023 A2): every directional icon needs a mirror flag"
                    ),
                ));
            }
        }
    }
    // The seven viewports and the print margin belong to the responsive document.
    match read_text(&root.join(RESPONSIVE)) {
        Err(error) => out.push(at(
            RESPONSIVE,
            format!("cannot be read, so the RTL viewports cannot be compared ({error})"),
        )),
        Ok(responsive) => {
            let viewports = responsive_viewports(&responsive);
            if viewports.len() != 7 {
                out.push(at(
                    RESPONSIVE,
                    format!(
                        "the `## Device matrix` has {} viewports; the strategy compares the seven viewports of T-0024 (T-0023 A2)",
                        viewports.len()
                    ),
                ));
            }
            for viewport in &viewports {
                if !has_token(&text, viewport) {
                    out.push(at(
                        I18N,
                        format!(
                            "the pseudo-RTL run uses the seven viewports of RESPONSIVE.md and `{viewport}` is missing from the RTL section (T-0023 A2)"
                        ),
                    ));
                }
            }
            if !has_token(&text, "pseudo-RTL") {
                out.push(at(
                    I18N,
                    "the RTL section must name the `pseudo-RTL` direction run (T-0023 A2)",
                ));
            }
            if !has_token(&text, "--direction rtl") {
                out.push(at(
                    I18N,
                    "the RTL section must name the `--direction rtl` harness flag (T-0023 A2)",
                ));
            }
            if !has_token(&text, "RESPONSIVE.md") {
                out.push(at(
                    I18N,
                    "the RTL section must point at RESPONSIVE.md for the shared print and viewport rules (T-0023 A2)",
                ));
            }
            if mentions(&text, "A4") && !(mentions(&text, "Letter") && has_token(&text, "T-0048")) {
                out.push(at(
                    I18N,
                    "locale-dependent paper sizes are an open item for T-0048; a document that mentions A4 must say so and name `Letter` (T-0023 step 1)",
                ));
            }
            if let Some(canonical) = responsive_print_margin(&responsive) {
                for value in marked_margins(&text) {
                    if value != canonical {
                        out.push(at(
                            I18N,
                            format!(
                                "the print margin is stated as {value} mm; RESPONSIVE.md owns the canonical {canonical} mm (T-0023 step 1)"
                            ),
                        ));
                    }
                }
            }
        }
    }
    out
}

/// T-0023 step 2: locale negotiation order, the `lang` attribute and the `Content-Language`/`Vary` behaviour.
pub(crate) fn negotiation_findings(doc: &str, spec: &str) -> Vec<Finding> {
    let mut out = Vec::new();
    let Some(text) = section_text(doc, "Locale negotiation") else {
        out.push(at(
            I18N,
            "no `## Locale negotiation` section exists (T-0023 step 2)",
        ));
        return out;
    };
    let lowered = lower(&text);
    let sources = ["account", "cookie", "accept-language", "default"];
    let mut positions: Vec<Option<usize>> = Vec::new();
    for source in sources {
        match lowered.find(source) {
            Some(position) => positions.push(Some(position)),
            None => {
                positions.push(None);
                out.push(at(
                    I18N,
                    format!(
                        "the negotiation section must name the `{source}` source of the order account, cookie, `Accept-Language`, default (T-0023 step 2)"
                    ),
                ));
            }
        }
    }
    if positions.iter().all(Option::is_some) {
        let found: Vec<usize> = positions.iter().flatten().copied().collect();
        if found.windows(2).any(|pair| pair.first() > pair.get(1)) {
            out.push(at(
                I18N,
                "the negotiation order is not account setting, cookie, `Accept-Language`, default (T-0023 step 2)",
            ));
        }
    }
    if !has_token(&text, "Accept-Language") {
        out.push(at(
            I18N,
            "the negotiation section must name the `Accept-Language` header (T-0023 step 2)",
        ));
    }
    for (token, why) in [
        ("server-rendered", "the language is set on the server"),
        ("Content-Language", "the `Content-Language` header is sent"),
        (VARY, "the response sends the `Vary` header"),
        (
            "HDD_I18N_DEFAULT_LOCALE",
            "the default is the configured locale",
        ),
        ("hreflang", "public pages carry `hreflang` tags"),
        ("HDD_SESSION_KEY", "the preference cookie is signed"),
    ] {
        if !mentions(&text, token) {
            out.push(at(
                I18N,
                format!("the negotiation section must state that {why} (T-0023 step 2)"),
            ));
        }
    }
    if !has_token(&text, "lang") {
        out.push(at(
            I18N,
            "the negotiation section must say how the `lang` attribute is set (T-0023 step 2)",
        ));
    }
    if !has_token(spec, "HDD_SESSION_KEY") {
        out.push(at(
            "docs/SPEC.md",
            "the specification does not define the signed preference cookie (`HDD_SESSION_KEY`), so the negotiation rule cannot be compared (T-0023 step 2)",
        ));
    }
    if !has_token(spec, "HDD_I18N_DEFAULT_LOCALE") {
        out.push(at(
            "docs/SPEC.md",
            "the specification does not define `HDD_I18N_DEFAULT_LOCALE`, so the default locale cannot be compared (T-0023 step 2)",
        ));
    }
    out
}

/// T-0023 step 3: the formatting rules of the document and the format examples of the content strategy agree.
pub(crate) fn formatting_findings(doc: &str, content: &str, spec: &str) -> Vec<Finding> {
    let mut out = Vec::new();
    let Some(text) = section_text(doc, "Formatting") else {
        out.push(at(
            I18N,
            "no `## Formatting` section exists (T-0023 step 3)",
        ));
        return out;
    };
    let Some(table) = first_table(doc, "Formatting") else {
        out.push(at(
            I18N,
            "the `## Formatting` section has no table (T-0023 step 3)",
        ));
        return out;
    };
    let (Ok(item_column), Ok(message_column), Ok(example_column)) = (
        require_column(&table.header, "Item", I18N),
        require_column(&table.header, "Fluent message", I18N),
        require_column(&table.header, "Example", I18N),
    ) else {
        return out;
    };
    // D-5: the column is Fluent only. The title may not offer ICU, and no cell may carry ICU `, plural,` or `{#`.
    for header_cell in &table.header {
        if mentions(header_cell, "ICU") {
            out.push(at(
                I18N,
                format!(
                    "the `{header_cell}` column title offers ICU; the formatting column is Fluent only (D-5)"
                ),
            ));
        }
    }
    let icu_tokens = [", plural,", "{#"];
    for row in &table.rows {
        let (line, item) = cell(row, item_column);
        let (_, message) = cell(row, message_column);
        for token in icu_tokens {
            if message.contains(token) {
                out.push(at(
                    format!("{I18N}:{line}"),
                    format!(
                        "the `{item}` message contains the ICU syntax `{token}`; the Fluent column may only use Fluent, for example `{{ $count -> [one] … *[other] … }}` (D-5)"
                    ),
                ));
            }
        }
        // A bare `$count` outside a function call must be a Fluent selector; `NUMBER($count)` is a function call.
        if message.contains("$count")
            && !message.contains('(')
            && !(message.contains("->")
                && message.contains("[one]")
                && message.contains("*[other]"))
        {
            out.push(at(
                format!("{I18N}:{line}"),
                format!(
                    "the `{item}` message uses a bare `$count` without the Fluent selector `{{ $count -> [one] … *[other] … }}` (D-5)"
                ),
            ));
        }
    }
    let required = [
        ("date", "Date"),
        ("time zone", "Time zone"),
        ("time", "Time"),
        ("number", "Number"),
        ("percentage", "Percentage"),
        ("bytes", "Bytes"),
        ("duration", "Duration"),
        ("relative", "Relative time"),
    ];
    for (needle, label) in required {
        let rows: Vec<&(usize, Vec<String>)> = table
            .rows
            .iter()
            .filter(|row| {
                let (_, item) = cell(row, item_column);
                item.to_lowercase().contains(needle)
            })
            .collect();
        let Some(row) = rows.first() else {
            out.push(at(
                I18N,
                format!("the formatting table has no row for `{label}` (T-0023 step 3)"),
            ));
            continue;
        };
        let (line, message) = cell(row, message_column);
        let message = lower(message);
        if !(message.contains("datetime(")
            || message.contains("number(")
            || message.contains("->")
            || message.contains("{ $"))
        {
            out.push(at(
                format!("{I18N}:{line}"),
                format!(
                    "the `{label}` row message must be a Fluent message, not prose (T-0023 step 3, D-5)"
                ),
            ));
        }
        let (_, example) = cell(row, example_column);
        if example.trim().is_empty() {
            out.push(at(
                format!("{I18N}:{line}"),
                format!("the `{label}` row has no example (T-0023 step 3)"),
            ));
        }
    }
    // D-5 says both documents are fixed: the content strategy's format table may not carry ICU syntax either.
    for table in section_tables(content, "Number, date and unit formats") {
        for row in &table.rows {
            for (column, value) in row.1.iter().enumerate() {
                for token in icu_tokens {
                    if value.contains(token) {
                        out.push(at(
                            format!("{CONTENT}:{}", row.0),
                            format!(
                                "the content-strategy format table column {column} contains the ICU syntax `{token}`; counted messages use the Fluent selector (D-5)"
                            ),
                        ));
                    }
                }
            }
        }
    }
    for (item, example) in content_format_examples(content) {
        if !text.contains(&example) {
            out.push(at(
                I18N,
                format!(
                    "CONTENT.md formats `{item}` as `{example}`; the formatting section must carry the same example (T-0023 step 3)"
                ),
            ));
        }
    }
    for (token, why) in [
        ("UTC", "timestamps are stored in UTC"),
        ("IANA", "the display zone is an IANA zone"),
        ("timestamptz", "the stored timestamps are `timestamptz`"),
        (
            "Unknown (reason)",
            "an absent value renders as `Unknown (reason)`",
        ),
        ("user time zone", "the display uses the user time zone"),
        ("B11.9", "the screen rule is B11.9"),
    ] {
        if !mentions(&text, token) {
            out.push(at(
                I18N,
                format!("the formatting section must state that {why} (T-0023 step 3)"),
            ));
        }
    }
    for (token, why) in [
        (
            "keep all stored timestamps in UTC",
            "timestamps are stored in UTC",
        ),
        ("half-hour offsets", "half-hour offset zones are tested"),
        ("org's configured zone", "reports use the organisation zone"),
        (
            "<time datetime>",
            "relative time carries an absolute `<time datetime>`",
        ),
        ("Unknown (reason)", "an absent value is not shown as zero"),
    ] {
        if !has_token(spec, token) && !mentions(spec, token) {
            out.push(at(
                "docs/SPEC.md",
                format!(
                    "the specification no longer states `{token}`, so the formatting rule cannot be compared (T-0023 step 3)"
                ),
            ));
            continue;
        }
        if !mentions(&text, token) {
            out.push(at(
                I18N,
                format!("the formatting section must carry the specification rule `{token}` ({why}) (T-0023 step 3)"),
            ));
        }
    }
    out
}

/// T-0023 step 4: the not-translated list is explicit and its identifier formats match the master specification.
pub(crate) fn not_translated_findings(doc: &str, spec: &str) -> Vec<Finding> {
    let mut out = Vec::new();
    let Some(text) = section_text(doc, "Not translated") else {
        out.push(at(
            I18N,
            "no `## Not translated` section exists (T-0023 step 4 and A4)",
        ));
        return out;
    };
    if !mentions(&text, "never translated") {
        out.push(at(
            I18N,
            "the section must say that these values are never translated (T-0023 A4)",
        ));
    }
    let Some(table) = first_table(doc, "Not translated") else {
        out.push(at(
            I18N,
            "the `## Not translated` section has no table (T-0023 step 4)",
        ));
        return out;
    };
    let (Ok(category_column), Ok(example_column)) = (
        require_column(&table.header, "Category", I18N),
        require_column(&table.header, "Example", I18N),
    ) else {
        return out;
    };
    // category, tokens the Example cell must carry, and the specification token that proves the format.
    let required: [(&str, &[&str], &str); 7] = [
        ("ray id", &["16 hex", "-HDD1"], "-HDD1"),
        ("rule id", &["rule_"], "rule_"),
        ("api identifier", &["ray_id"], "ray_id"),
        ("log line", &["json"], "JSON logs"),
        ("error code", &["err-"], "ERR-"),
        ("audit event id", &["aud-"], "AUD-"),
        ("metric id", &["met-"], "MET-"),
    ];
    for (category, tokens, spec_token) in required {
        let rows: Vec<&(usize, Vec<String>)> = table
            .rows
            .iter()
            .filter(|row| {
                let (_, cell) = cell(row, category_column);
                cell.to_lowercase().contains(category)
            })
            .collect();
        let Some(row) = rows.first() else {
            out.push(at(
                I18N,
                format!("the not-translated table has no `{category}` row (T-0023 A4)"),
            ));
            continue;
        };
        let (line, example) = cell(row, example_column);
        let row_text = row.1.join(" ").to_lowercase();
        for token in tokens {
            if !row_text.contains(&token.to_lowercase()) {
                out.push(at(
                    format!("{I18N}:{line}"),
                    format!(
                        "the `{category}` row must carry `{token}`, so the format can be compared with the specification (T-0023 step 4)"
                    ),
                ));
            }
        }
        if category == "rule id" && !example.to_lowercase().contains("rule_") {
            out.push(at(
                format!("{I18N}:{line}"),
                "the `rule id` example must be a `rule_` identifier (T-0023 step 4)",
            ));
        }
        if !has_token(spec, spec_token) && !mentions(spec, spec_token) {
            out.push(at(
                "docs/SPEC.md",
                format!(
                    "the specification does not define `{spec_token}`, so the `{category}` format cannot be compared (T-0023 step 4)"
                ),
            ));
        }
    }
    if !has_token(&text, "16 hex") || !has_token(&text, "-HDD1") {
        out.push(at(
            I18N,
            "the Ray ID row must state the 16 hex characters plus `-HDD1` format (T-0023 step 4)",
        ));
    }
    if !mentions(&text, "26") {
        out.push(at(
            I18N,
            "the rule ID row must state the 26 character base32 format (T-0023 step 4)",
        ));
    }
    for (token, why) in [
        ("What is translated", "a `What is translated` list"),
        ("UI", "the UI strings are translated"),
        ("email", "the emails are translated"),
        ("error", "the user-facing error sentences are translated"),
        ("documentation", "the user documentation is translated"),
    ] {
        if !mentions(&text, token) {
            out.push(at(
                I18N,
                format!("the section must state {why} (T-0023 step 4)"),
            ));
        }
    }
    out
}

/// T-0023 step 5: every activation email of the onboarding document has a localized template and fallback rule.
pub(crate) fn email_findings(doc: &str, onboarding: &str) -> Vec<Finding> {
    let mut out = Vec::new();
    let Some(text) = section_text(doc, "Email localization") else {
        out.push(at(
            I18N,
            "no `## Email localization` section exists (T-0023 step 5)",
        ));
        return out;
    };
    let emails = activation_emails(onboarding);
    if emails.is_empty() {
        out.push(at(
            ONBOARDING,
            "no `## Activation emails` table exists, so the email localization cannot be compared (T-0023 step 5)",
        ));
    }
    let Some(table) = first_table(doc, "Email localization") else {
        out.push(at(
            I18N,
            "the `## Email localization` section has no table (T-0023 step 5)",
        ));
        return out;
    };
    let Ok(email_column) = require_column(&table.header, "Email", I18N) else {
        return out;
    };
    for name in &emails {
        let found = table.rows.iter().any(|row| {
            let (_, cell) = cell(row, email_column);
            cell.trim().eq_ignore_ascii_case(name)
        });
        if !found {
            out.push(at(
                I18N,
                format!(
                    "the activation email `{name}` of ONBOARDING.md has no row in the email localization table (T-0023 step 5)"
                ),
            ));
        }
    }
    for (token, why) in [
        (
            "i18n/<locale>/email.ftl",
            "the notification catalog is the email area file of T-0110",
        ),
        (
            "onboarding.ftl",
            "the four activation emails live in the onboarding area file",
        ),
        (
            "whole email falls back",
            "the whole email falls back and never half of it",
        ),
        (
            "mail_outbox",
            "the requested locale is stored on `mail_outbox`",
        ),
        ("HTML", "every email has an HTML variant"),
        ("text", "every email has a text variant"),
        ("600 px", "the email layout is 600 px wide at most"),
        ("golden", "a golden file exists per locale"),
    ] {
        if !mentions(&text, token) {
            out.push(at(
                I18N,
                format!("the email section must state that {why} (T-0023 step 5)"),
            ));
        }
    }
    out
}

/// T-0023 step 6: the translator workflow uses no external service and follows the translation guidance of the
/// content strategy.
pub(crate) fn translator_findings(doc: &str, content: &str) -> Vec<Finding> {
    let mut out = Vec::new();
    let Some(text) = section_text(doc, "Translator workflow") else {
        out.push(at(
            I18N,
            "no `## Translator workflow` section exists (T-0023 step 6 and A3)",
        ));
        return out;
    };
    if text.contains("http://") || text.contains("https://") {
        out.push(at(
            I18N,
            "the translator workflow must need no external service: the section names a web URL (T-0023 A3)",
        ));
    }
    for (token, why) in [
        (
            "no external service",
            "the workflow needs no external service",
        ),
        (
            "repository",
            "the hand-off is a directory in the repository",
        ),
        (
            "# context:",
            "each exported key carries a `# context:` note",
        ),
        (
            "maximum length",
            "the context note carries the maximum length",
        ),
        (
            "placeholder",
            "the context note carries the placeholder list",
        ),
        ("missing", "the lint reports missing keys"),
        ("unused", "the lint reports unused keys"),
        (
            "placeholder mismatch",
            "the lint reports placeholder mismatches",
        ),
        ("stub", "`cargo xtask i18n check` is a stub until T-0082"),
        ("T-0082", "the lint arrives with T-0082"),
        ("glossary", "the translator reads the glossary"),
        ("native speaker", "a native speaker reviews the translation"),
    ] {
        if !mentions(&text, token) {
            out.push(at(
                I18N,
                format!("the translator workflow must state that {why} (T-0023 step 6)"),
            ));
        }
    }
    let workflow = section_tables(doc, "Translator workflow")
        .into_iter()
        .find(|table| super::column(&table.header, "Step").is_some());
    match workflow {
        None => out.push(at(
            I18N,
            "no `| Step | Who | Artifact | Gate |` workflow table exists (T-0023 step 6)",
        )),
        Some(table) => {
            if table.rows.len() < MIN_WORKFLOW_STEPS {
                out.push(at(
                    I18N,
                    format!(
                        "the workflow has {} steps; export, translate, import, lint and review are required (T-0023 step 6)",
                        table.rows.len()
                    ),
                ));
            }
        }
    }
    // CONTENT.md owns the translation guidance; compare it, do not restate it.
    let Some(guidance) = section_text(content, "Translation guidance") else {
        out.push(at(
            CONTENT,
            "no `## Translation guidance` section exists, so the workflow cannot be compared (T-0023 step 6)",
        ));
        return out;
    };
    for token in backticked(&guidance) {
        if !doc.contains(&token) {
            out.push(at(
                I18N,
                format!(
                    "CONTENT.md fixes `{token}` in its translation guidance and the strategy must follow it (T-0023 step 6)"
                ),
            ));
        }
    }
    if lower(&guidance).contains("concatenat") && !lower(doc).contains("concatenat") {
        out.push(at(
            I18N,
            "CONTENT.md forbids concatenating sentence fragments and the workflow must say the same (T-0023 step 6)",
        ));
    }
    out
}

/// T-0023 step 7: the launch locales equal the profile `locales` key and the criteria to add a locale exist.
pub(crate) fn launch_findings(doc: &str, profile: &str) -> Vec<Finding> {
    let mut out = Vec::new();
    if profile.trim().is_empty() {
        out.push(at(
            PROFILE_EXAMPLE,
            "the profile example is empty, so the launch locales cannot be compared (T-0023 step 7)",
        ));
        return out;
    }
    if !profile
        .lines()
        .any(|line| line.trim() == "schema_version: 5")
    {
        out.push(at(
            PROFILE_EXAMPLE,
            "the profile example must carry `schema_version: 5`, the schema this check reads (T-0023 step 7)",
        ));
    }
    let Some(locales) = profile_locales(profile) else {
        out.push(at(
            PROFILE_EXAMPLE,
            "the profile example has no `locales: [...]` key, so the launch locales cannot be compared (T-0023 step 7)",
        ));
        return out;
    };
    if locales.is_empty() {
        out.push(at(
            PROFILE_EXAMPLE,
            "the profile `locales` key is empty, so the launch set is undefined (T-0023 step 7)",
        ));
    }
    for tag in &locales {
        if !valid_locale_tag(tag) {
            out.push(at(
                PROFILE_EXAMPLE,
                format!(
                    "`{tag}` in the `locales` key is not a plausible locale tag (T-0023 step 7)"
                ),
            ));
        }
    }
    let Some(text) = section_text(doc, "Launch locales") else {
        out.push(at(
            I18N,
            "no `## Launch locales` section exists (T-0023 step 7)",
        ));
        return out;
    };
    for (token, why) in [
        ("locales", "the profile key is `locales`"),
        (
            "product decision",
            "shipping a locale is a product decision",
        ),
        (
            "operator decides",
            "the operator decides which locales ship",
        ),
        ("English", "the example profile ships English"),
        (
            "hdd.live.example.yaml",
            "the value comes from the profile example",
        ),
    ] {
        if !mentions(&text, token) {
            out.push(at(
                I18N,
                format!("the launch-locale section must state that {why} (T-0023 step 7)"),
            ));
        }
    }
    let Some(table) = first_table(doc, "Launch locales") else {
        out.push(at(
            I18N,
            "the `## Launch locales` section has no table (T-0023 step 7)",
        ));
        return out;
    };
    let (Ok(locale_column), Ok(status_column)) = (
        require_column(&table.header, "Locale", I18N),
        require_column(&table.header, "Status", I18N),
    ) else {
        return out;
    };
    let mut listed: Vec<String> = Vec::new();
    for row in &table.rows {
        let (line, locale) = cell(row, locale_column);
        let (_, status) = cell(row, status_column);
        let locale = bare(locale);
        if locale.is_empty() {
            continue;
        }
        if !mentions(status, "launch") {
            out.push(at(
                format!("{I18N}:{line}"),
                format!(
                    "the locale `{locale}` row must say `launch` in its status (T-0023 step 7)"
                ),
            ));
        }
        if !locales.iter().any(|tag| tag.eq_ignore_ascii_case(&locale)) {
            out.push(at(
                format!("{I18N}:{line}"),
                format!(
                    "the launch table lists `{locale}`, which is not in the profile `locales` key (T-0023 step 7)"
                ),
            ));
        }
        listed.push(locale);
    }
    for tag in &locales {
        if !listed.iter().any(|locale| locale.eq_ignore_ascii_case(tag)) {
            out.push(at(
                I18N,
                format!(
                    "the profile `locales` key carries `{tag}` but the launch table has no row for it (T-0023 step 7)"
                ),
            ));
        }
    }
    let criteria = section_tables(doc, "Launch locales")
        .into_iter()
        .find(|table| super::column(&table.header, "Criterion").is_some());
    match criteria {
        None => out.push(at(
            I18N,
            "no criteria table for adding a locale exists (T-0023 step 7)",
        )),
        Some(table) => {
            if table.rows.len() < MIN_LOCALE_CRITERIA {
                out.push(at(
                    I18N,
                    format!(
                        "the criteria table has {} rows; at least {MIN_LOCALE_CRITERIA} criteria are required (T-0023 step 7)",
                        table.rows.len()
                    ),
                ));
            }
            for row in &table.rows {
                if row.1.iter().all(|cell| cell.trim().is_empty()) {
                    out.push(at(
                        format!("{I18N}:{}", row.0),
                        "a locale criterion row is empty (T-0023 step 7)",
                    ));
                }
            }
        }
    }
    out
}

/// T-0023 step 8 and A5: the test strategy includes the pseudo-locale overflow test, missing-key detection and plural
/// tests.
pub(crate) fn test_strategy_findings(doc: &str, spec: &str) -> Vec<Finding> {
    let mut out = Vec::new();
    let Some(text) = section_text(doc, "Test strategy") else {
        out.push(at(
            I18N,
            "no `## Test strategy` section exists (T-0023 step 8 and A5)",
        ));
        return out;
    };
    let Some(table) = first_table(doc, "Test strategy") else {
        out.push(at(
            I18N,
            "the `## Test strategy` section has no table (T-0023 step 8)",
        ));
        return out;
    };
    let Ok(test_column) = require_column(&table.header, "Test", I18N) else {
        return out;
    };
    if table.rows.len() < MIN_TEST_ROWS {
        out.push(at(
            I18N,
            format!(
                "the test strategy has {} rows; at least {MIN_TEST_ROWS} tests are required (T-0023 step 8)",
                table.rows.len()
            ),
        ));
    }
    let groups: [(&[&str], &str); 10] = [
        (&["pseudo", "overflow"], "the pseudo-locale overflow test"),
        (&["truncation"], "the truncation test"),
        (&["missing", "key"], "the missing-key detection test"),
        (&["unused", "key"], "the unused-key test"),
        (&["placeholder"], "the placeholder test"),
        (&["plural"], "the plural test"),
        (&["negotiation"], "the negotiation test"),
        (&["lang", "dir"], "the `lang` and `dir` test"),
        (&["email"], "the email golden test"),
        (&["proptest"], "the formatting property test"),
    ];
    for (tokens, label) in groups {
        let found = table.rows.iter().any(|row| {
            let (_, test) = cell(row, test_column);
            let test = test.to_lowercase();
            tokens.iter().all(|token| test.contains(token))
        });
        if !found {
            out.push(at(
                I18N,
                format!("the test strategy has no row for {label} (T-0023 step 8 and A5)"),
            ));
        }
    }
    if !mentions(&text, "scroll width") || !mentions(&text, "client width") {
        out.push(at(
            I18N,
            "the pseudo-locale overflow row must compare scroll width vs client width (T-0023 A5)",
        ));
    }
    for (token, why) in [
        (
            "seven viewports",
            "the overflow test runs at the seven viewports",
        ),
        (
            "UNVERIFIED(capability_not_supplied)",
            "the browser part is UNVERIFIED(capability_not_supplied) until T-0082",
        ),
        ("few", "a synthetic few category is tested"),
        ("many", "a synthetic many category is tested"),
    ] {
        if !mentions(&text, token) {
            out.push(at(
                I18N,
                format!("the test strategy must state that {why} (T-0023 step 8)"),
            ));
        }
    }
    for token in ["scroll width", "client width", "proptest", "few/many"] {
        if !mentions(spec, token) {
            out.push(at(
                "docs/SPEC.md",
                format!(
                    "the specification no longer states `{token}`, so the test strategy cannot be compared (T-0023 step 8)"
                ),
            ));
        }
    }
    out
}

#[cfg(test)]
pub(crate) mod fixtures {
    //! Fixture tree for the T-0023 checks: the strategy document, the profile example and the fixture-spec rows.
    //!
    //! The fixture strategy document is structurally complete and cites keys of the other fixture modules, so the
    //! Lead can add [`documents`] to the shared fixture tree without editing the tests. The fixture key examples are
    //! read from the fixture `.ftl` files of `content`, `security_ux` and `onboarding` at generation time, so the
    //! fixture can never cite an invented key. The shared fixture tree also writes `i18n/en/errors.ftl`
    //! (T-0020), so the fixture file-layout table names it too.

    use super::{
        ACCENT, I18N, PROFILE_EXAMPLE, PSEUDO_CLOSE, PSEUDO_OPEN, accent, parse_ftl, pseudo_metrics,
    };

    /// The four `.ftl` files the fixture tree holds, in the order the other fixture modules write them.
    pub(crate) fn ftl_texts() -> Vec<(String, String)> {
        vec![
            (
                "i18n/en/copy-deck.ftl".to_owned(),
                super::super::content::fixtures::copy_deck().to_owned(),
            ),
            (
                "i18n/en/security-ux.ftl".to_owned(),
                super::super::security_ux::fixtures::copy_document(),
            ),
            (
                "i18n/en/onboarding.ftl".to_owned(),
                super::super::onboarding::fixtures::onboarding_ftl(),
            ),
            (
                "i18n/en/errors.ftl".to_owned(),
                super::super::errors::fixtures::copy_document(),
            ),
        ]
    }

    /// The fixture profile example: only the two keys this check reads.
    pub(crate) fn profile() -> String {
        String::from(
            "# hdd.live.example.yaml fixture for the T-0023 checks.\n\
             schema_version: 5\n\
             locales: [en]                           # UI languages shipped\n",
        )
    }

    /// The fixture documents, as `(repository-relative path, text)`.
    pub(crate) fn documents() -> Vec<(String, String)> {
        vec![
            (I18N.to_owned(), i18n_document()),
            (PROFILE_EXAMPLE.to_owned(), profile()),
        ]
    }

    /// One `| key | file | value |` row of the message-format table, taken from a fixture `.ftl` file.
    fn key_row(file: &str, key: &str, messages: &[super::Message]) -> String {
        let value = super::message_for(messages, key).map_or("", |message| message.value.as_str());
        format!("| `{key}` | `{file}` | {value} |\n")
    }

    /// The message-format table rows: four keys of each example fixture `.ftl` file (twelve real examples). The
    /// T-0020 `errors.ftl` fixture is listed in the file layout but contributes no example row, so the table stays at
    /// the twelve examples the other three files prove.
    fn key_rows() -> String {
        let files = ftl_texts();
        let mut out = String::new();
        for (file, text) in &files {
            let messages = parse_ftl(text);
            let chosen: Vec<&str> = match file.as_str() {
                "i18n/en/copy-deck.ftl" => vec![
                    "tagline",
                    "signup-title",
                    "success-saved",
                    "readiness-footnote",
                ],
                "i18n/en/security-ux.ftl" => vec![
                    "fx-domain-remove",
                    "fx-org-delete",
                    "fx-block-mode",
                    "fx-never-ban",
                ],
                "i18n/en/onboarding.ftl" => vec![
                    "empty-domains",
                    "empty-readiness",
                    "empty-alerts",
                    "empty-reports",
                ],
                _ => Vec::new(),
            };
            for key in chosen {
                out.push_str(&key_row(file, key, &messages));
            }
        }
        out
    }

    /// The accent table of the fixture document.
    fn accent_rows() -> String {
        let mut out = String::new();
        for (letter, pseudo) in ACCENT {
            out.push_str(&format!("| `{letter}` | `{pseudo}` |\n"));
        }
        out
    }

    /// The worked pseudo-locale examples, generated from the reference transform, with the measured expansion.
    pub(crate) fn pseudo_rows() -> String {
        let mut out = String::new();
        for input in PSEUDO_INPUTS {
            let metrics = pseudo_metrics(input);
            out.push_str(&format!(
                "| `{}` | `{}{}{}` | {} |\n",
                input,
                PSEUDO_OPEN,
                metrics.text,
                PSEUDO_CLOSE,
                metrics.expansion_cell()
            ));
        }
        out
    }

    /// The pseudo-locale inputs the fixture document evaluates.
    pub(crate) const PSEUDO_INPUTS: [&str; 9] = [
        "Save",
        "Domain added.",
        "Switch { $domain } to block mode?",
        "0 events",
        "OK",
        "a",
        "abcdefghijklmnopqrstuvwxyzabcd",
        "{ $count }",
        SELECTOR_INPUT,
    ];

    /// The selector example of D-6: only the reference and the variant keys stay, the variant text is transformed.
    pub(crate) const SELECTOR_INPUT: &str =
        "{ $count -> [one] { $count } event *[other] { $count } events }";

    /// The fixture strategy document.
    pub(crate) fn i18n_document() -> String {
        let mut s = String::from(
            "# Internationalization and localization strategy (fixture)\n\n\
             Status: fixture for the T-0023 checks. The strategy follows [CONTENT.md](CONTENT.md), \
             [ACCESSIBILITY.md](ACCESSIBILITY.md), [RESPONSIVE.md](RESPONSIVE.md) and \
             [ONBOARDING.md](ONBOARDING.md).\n\n\
             ## Status and limits\n\n\
             The strategy is fixed and the runtime is not built. `cargo xtask i18n check` is a success-and-note stub \
             until T-0082, the pseudo-locale generator arrives with T-0082, the formatting helpers with T-0083 and the \
             icon inventory with T-0034. No locale other than English ships and the operator decides which locales \
             ship.\n\n\
             | Piece | State today | Task |\n| --- | --- | --- |\n\
             | Fluent runtime | design only | T-0082 |\n\
             | `cargo xtask i18n check` | stub | T-0082 |\n\
             | Pseudo-locale generator | design only | T-0082 |\n\
             | Formatting helpers | design only | T-0083 |\n\
             | Icon inventory | absent | T-0034 |\n\
             | Second locale | none | operator |\n\n\
             ## Message format\n\n\
             Messages use the Fluent format: a key, an equals sign and one message with placeables and selectors, never \
             a sentence split across two keys. The value below is the English source and the `ux-docs` check compares \
             it with the named file.\n\n\
             | Key | File | Value |\n| --- | --- | --- |\n",
        );
        s.push_str(&key_rows());
        s.push_str(
            "\n## Key naming\n\n\
             A key is `^[a-z0-9]+(-[a-z0-9]+)*$`: lower-case words joined by hyphens and at least two parts, for \
             example `domain-add-title`. A key is semantic and never sentences; the area word comes first and a \
             number is never the only difference between two keys.\n\n\
             ## File layout\n\n\
             A locale directory holds one file per area: `i18n/<locale>/<area>.ftl`. A new area is a new file in the \
             same locale directory, listed in the table below and owned by the task that adds it; the seven area files \
             planned by T-0082 are `common`, `auth`, `app`, `admin`, `public`, `errors` and `email`, and the email \
             catalog of T-0110 lands in `email.ftl`.\n\n\
             | File | Area | Owner task |\n| --- | --- | --- |\n\
             | `i18n/en/copy-deck.ftl` | the B13 copy deck | T-0019 |\n\
             | `i18n/en/security-ux.ftl` | dangerous-action confirmations | T-0025 |\n\
             | `i18n/en/onboarding.ftl` | onboarding empty states and activation emails | T-0026 |\n\
             | `i18n/en/errors.ftl` | error-handling copy that B13 does not define | T-0020 |\n\n\
             ## Fallback and missing keys\n\n\
             The fallback chain is `locale → language → en`: a message missing in `pt-BR` is read from `pt` and then \
             from `en`. A missing key fails the build or test in CI (T-0082 A1); at runtime the loader renders the key \
             with a marker, increments a counter and records the stable log event `i18n.missing_key`, and a request \
             never fails because of a message. The loader reads the files at build time (compile-time embedding) and \
             the runtime is delivered by T-0082; none of it runs today.\n\n\
             ## Pseudo-locale\n\n\
             The pseudo-locale exposes text that is too long and text that is not translated. The transform is fixed:\n\n\
             1. a placeable reference (`$var`, a term `-term`, a function call) is copied unchanged and does not expand;\n\
             2. in a select expression the selector reference and the `[one]`/`*[other]` variant keys are copied and \
             the variant text is transformed like the rest of the message, so a plural is accented and expanded too;\n\
             3. a maximal run of ASCII letters is accented with the table below, case preserved, and receives \
             `ceil(40%)` of its letter count as `·` filler characters, rounded up per word and capped at 8;\n\
             4. digits, punctuation, spaces and non-ASCII text are copied unchanged;\n\
             5. the whole message is wrapped in `[[` and `]]` bracket markers.\n\n\
             The cap is a deliberate limit: a longer word would otherwise produce an unreadable run of filler, and \
             the Measured expansion column shows where it applies. The expansion is measured against the letter \
             count, not the byte length; the markers sit outside the expansion. The generator writes `i18n/pseudo/` \
             at build time and that locale is not shipped in the profile `locales`. The reference implementation is \
             this `ux-docs` module (`i18n_plan.rs`); the generator and the harness mode arrive with T-0082 and \
             `cargo xtask i18n check` is a stub until then.\n\n\
             | Input | Expected pseudo | Measured expansion |\n| --- | --- | --- |\n",
        );
        s.push_str(&pseudo_rows());
        s.push_str(
            "\nThe accent table, evaluated letter by letter:\n\n\
             | Letter | Pseudo |\n| --- | --- |\n",
        );
        s.push_str(&accent_rows());
        s.push_str(
            "\n## RTL readiness\n\n\
             The direction follows the locale. The server renders `<html lang=\"…\" dir=\"ltr|rtl\">` from the \
             negotiated locale, so the page direction is server-rendered and no client script has to fix it. A user \
             value (a domain name, an organisation \
             name, a display name) gets `dir=\"auto\"`; a machine identifier (a Ray ID, a rule ID, an API key, a \
             hostname, a code sample) gets `dir=\"ltr\"` so bidi does not reorder it. `MarkdownRender` and the \
             `LocaleSwitcher`, `ThemeToggle` and `DensityToggle` components are the owners that ACCESSIBILITY.md maps \
             to WCAG 3.1.1 and 3.1.2 through the `Locale and language` page pattern.\n\n\
             A component stylesheet uses logical properties and the physical property in the second column is not \
             allowed. The banned physical properties are `margin-left`, `margin-right`, `padding-left`, \
             `padding-right`, `border-left`, `border-right`, `text-align: left` and `float: left`.\n\n\
             | Logical property | Replaces | Use |\n| --- | --- | --- |\n\
             | `margin-inline-start` | `margin-left` | start margin of a card |\n\
             | `margin-inline-end` | `margin-right` | end margin of a card |\n\
             | `margin-block-start` | `margin-top` | space above a section |\n\
             | `margin-block-end` | `margin-bottom` | space below a section |\n\
             | `padding-inline-start` | `padding-left` | start padding of a row |\n\
             | `padding-inline-end` | `padding-right` | end padding of a row |\n\
             | `padding-block-start` | `padding-top` | top padding of a cell |\n\
             | `padding-block-end` | `padding-bottom` | bottom padding of a cell |\n\
             | `border-inline-start` | `border-left` | start edge of a table cell |\n\
             | `border-inline-end` | `border-right` | end edge of a table cell |\n\
             | `inset-inline-start` | `left` | drawer edge |\n\
             | `inset-inline-end` | `right` | drawer edge |\n\n\
             ### Mirrored icons\n\n\
             The mirrored-icon table names icon roles, not `design/` file names: no icon inventory exists yet and \
             `design/` holds no icon files; T-0034 owns the icon system and must give every directional icon a \
             mirror flag. A directional icon that points along the reading direction mirrors (`yes`), a \
             non-directional icon does not (`no`).\n\n\
             | Icon role | Mirrors in RTL | Why |\n| --- | --- | --- |\n\
             | back | yes | points against the reading direction |\n\
             | forward | yes | points along the reading direction |\n\
             | chevron start | yes | points to the start edge |\n\
             | chevron end | yes | points to the end edge |\n\
             | undo | yes | restores the previous state in reading order |\n\
             | redo | yes | replays the change in reading order |\n\
             | indent | yes | moves text towards the start edge |\n\
             | outdent | yes | moves text towards the start edge |\n\
             | external link | no | the destination does not change direction |\n\
             | search | no | a magnifier has no direction |\n\n\
             The pseudo-RTL run uses the seven viewports 360x740, 390x844, 768x1024, 1024x768, 1280x800, 1536x864 and \
             1920x1080 with `pseudo-RTL` and `--direction rtl`; the viewport list is compared with RESPONSIVE.md. \
             Printed reports follow RESPONSIVE.md and its 12 mm margins; locale-dependent Letter paper is an open item \
             for T-0048 and is not fixed here.\n\n\
             ## Locale negotiation\n\n\
             The server negotiates one locale per request, in this order:\n\n\
             1. the account setting (`users.locale`, edited through `PATCH /me`);\n\
             2. the signed preference cookie (`hdd_locale`), HMAC-signed with `HDD_SESSION_KEY`, size-capped and \
             ignored when tampered with (T-0081);\n\
             3. the `Accept-Language` header, highest quality value first, base language before a region variant;\n\
             4. the default `HDD_I18N_DEFAULT_LOCALE` (`en`).\n\n\
             The choice is server-rendered: the response carries `lang` and `dir` on the `<html>` element, the \
             `Content-Language` header names the chosen locale and the response sends `Vary: Accept-Language, \
             Cookie` so a shared cache cannot mix two locales. A locale is never put in the URL for the app and no \
             redirect is used to switch it; public pages carry `hreflang` link tags for the shipped locales.\n\n\
             ## Formatting\n\n\
             T-0083 fixes the rule: keep all stored timestamps in UTC, display in the user time zone. The stored \
             column is `timestamptz` and the display zone is an IANA zone. The user zone \
             comes from the account setting, then a browser hint stored once, then UTC; reports use the org's \
             configured zone and state it in the report header. Half-hour offsets such as Asia/Kathmandu (+05:45) \
             are test cases. An absent value renders as `Unknown (reason)`, never as zero. B11.9 fixes the screen \
             rule: relative time with the absolute time in `<time datetime>` and `title`, the UTC offset visible, and \
             the user time zone from the profile; large numbers are abbreviated only in cards and exact in tables, \
             with units explicit.\n\n\
             | Item | Rule (en) | Fluent message | Example |\n| --- | --- | --- | --- |\n\
             | Date | year first, month, day | `DATETIME($ts, dateStyle: \"medium\")` | 2026-10-19 |\n\
             | Time | 24-hour with the zone on the same line | `DATETIME($ts, timeStyle: \"short\", timeZone: $zone)` \
             | 14:05 UTC |\n\
             | Number | whole number grouped in threes | `NUMBER($count)` | 1,204 requests |\n\
             | Percentage | at most one decimal place | `NUMBER($ratio, style: \"percent\", \
             maximumFractionDigits: 1)` | 98.6% |\n\
             | Bytes | decimal unit with one decimal place | `NUMBER($bytes, style: \"unit\", unit: \"megabyte\", \
             unitDisplay: \"short\")` | 1.2 MB |\n\
             | Duration | number and unit, spelled out under one minute | `{ $count -> [one] { $count } second \
             *[other] { $count } seconds }` | 45 seconds |\n\
             | Relative time | absolute time plus a relative span | `{ $count -> [one] { $count } minute ago \
             *[other] { $count } minutes ago }` | 12 minutes ago (14:05 UTC) |\n\
             | Time zone | IANA name, UTC for storage | `DATETIME($ts, timeZone: $zone, timeStyle: \"long\")` | 14:05 \
             UTC |\n\n\
             The examples above are the format table of CONTENT.md, so the two documents are compared.\n\n\
             ## Not translated\n\n\
             These values are machine text and are never translated, because the API, the logs and support scripts \
             match them byte for byte:\n\n\
             | Category | Example | Why it stays the same |\n| --- | --- | --- |\n\
             | Ray ID | `0123456789abcdef-HDD1` | 16 hex characters plus `-HDD1`; the visitor and support quote it |\n\
             | Rule ID | `rule_ab2cd3ef4gh5jk6mn7pq2rs3tu` | `rule_` plus 26 lower-case base32 characters |\n\
             | API identifier | `ray_id` | JSON field names and endpoints are the client contract |\n\
             | Log line | a JSON log line with `event` and `ray_id` | operator searches and support scripts match JSON \
             logs |\n\
             | Error code | `ERR-SYS-001` | the code is stable; the sentence next to it is translated |\n\
             | Audit event id | `AUD-domain.created` | the hash-chained audit names the event |\n\
             | Metric id | `MET-hdd_panics_total` | the exported metric name is the contract |\n\
             | User data | a domain name or an organisation name | user text is shown as written, never translated |\n\n\
             **What is translated:** the UI strings (every user-visible string is a Fluent key), the emails (subject \
             and body), the user-facing error sentences (chosen by code, then translated) and the user documentation \
             (the English page is the source and stays available).\n\n\
             ## Email localization\n\n\
             An email has one subject message and one body message in the area file of its family; the notification \
             catalog of T-0110 lives in `i18n/<locale>/email.ftl` and the four activation emails live in \
             `i18n/<locale>/onboarding.ftl` as ONBOARDING.md declares. Every email has an HTML and a text variant at \
             600 px, no remote image and a golden file per locale. The whole email falls back to `en` when its \
             locale lacks a message, never half of it; `mail_outbox` stores the requested locale and a fallback logs \
             the stable event `i18n.email_fallback`.\n\n\
             | Email | Messages | Fallback |\n| --- | --- | --- |\n\
             | welcome | subject and body | whole email to `en` |\n\
             | verify | subject and body | whole email to `en` |\n\
             | first domain | subject and body | whole email to `en` |\n\
             | weekly summary | subject and body | whole email to `en` |\n\n\
             ## Translator workflow\n\n\
             The hand-off is a directory in the repository: no account, no external service and no network egress. A \
             translator receives the exported files, edits them offline and returns them in a branch; the reviewer \
             reads the same files.\n\n\
             | Step | Who | Artifact | Gate |\n| --- | --- | --- | --- |\n\
             | export | owner | `i18n/<locale>/<area>.ftl` with a `# context:` note per key | the export lists the \
             screen, the maximum length and the placeholder list |\n\
             | translate | translator | the same file, offline | the translator reads the glossary |\n\
             | import | translator | a branch of the repository | the diff names the changed keys |\n\
             | lint | owner | the lint report | missing keys, unused keys and placeholder mismatches are findings |\n\
             | review | a native speaker | the review note | the glossary and the claims policy pass |\n\n\
             The lint is `cargo xtask i18n check`, which is a stub until T-0082; today the `ux-docs` style check runs \
             on the English deck only. A missing key, an unused key, a placeholder mismatch in the two locales, a \
             string over the length limit and a key that breaks the naming convention are the six lint findings. \
             CONTENT.md fixes the translation guidance this workflow follows: never concatenate sentence fragments, \
             use a Fluent placeable such as `{$domain}` inside the sentence, and give a count a selector with `[one]` \
             and `[other]`.\n\n\
             ## Launch locales\n\n\
             The `locales` key of `hdd.live.example.yaml` sets what ships; the example carries `[en]`, so English is \
             the only launch locale and the default (`en`, `HDD_I18N_DEFAULT_LOCALE`). Shipping another locale is a \
             product decision and the operator decides which locales ship.\n\n\
             | Locale | Status | Notes |\n| --- | --- | --- |\n\
             | en | launch | the default and the only locale in the example profile |\n\n\
             A locale ships when every criterion below is met:\n\n\
             | Criterion | How it is checked |\n| --- | --- |\n\
             | native-speaker review | a reviewer signs off the file |\n\
             | glossary complete | every glossary term has a translation |\n\
             | pseudo-locale clean | the overflow test passes at the seven viewports |\n\
             | lint clean | no missing, unused or placeholder finding |\n\
             | plural categories | the CLDR categories of the locale are tested |\n\
             | formats checked | date, number and relative time spot-checked |\n\n\
             ## Test strategy\n\n\
             The tests below are the gates for T-0082 and T-0083; the browser part is `UNVERIFIED(capability_not_supplied)` \
             until T-0082 lands.\n\n\
             | Test | What it proves | Runs in |\n| --- | --- | --- |\n\
             | pseudo-locale overflow | no clipped text: scroll width vs client width at the seven viewports | T-0082 \
             browser |\n\
             | truncation | an ellipsis only with an accessible full text | T-0082 |\n\
             | missing key | a missing key fails the build or test in CI | T-0082 unit |\n\
             | unused key | a key that no template uses is a finding | T-0082 lint |\n\
             | placeholder | a placeholder mismatch between locales is a finding | T-0082 lint |\n\
             | plural | `[one]` and `[other]` for English and a synthetic few and many locale | T-0082 unit |\n\
             | negotiation | the four sources are tried in order | T-0082 unit |\n\
             | lang and dir | the attributes follow the negotiated locale | T-0082 integration |\n\
             | email golden | one golden file per locale | T-0110 |\n\
             | formatting | date, number, relative time and duration values per zone | T-0083 unit |\n\
             | proptest | formatting never panics on extreme input | T-0083 proptest |\n",
        );
        s.push_str(
            "\nThe format examples of [CONTENT.md](CONTENT.md) are compared with this document by the check.\n",
        );
        s
    }

    /// Extra fixture-spec rows this module needs beyond the shared fixture tree.
    ///
    /// The shared fixture specification already carries the B11.8 component inventory, so the fixture strategy
    /// document can name `LocaleSwitcher` and `MarkdownRender`. This string adds the requirement lines the check
    /// compares the document with: the pseudo-locale and identifier formats, the T-0082 and T-0083 rules, the email
    /// catalog, the signed preference cookie and the area file list.
    pub(crate) fn spec_section() -> String {
        String::from(
            "\n### I18N requirements registry (T-0023 fixture)\n\n\
             `T-0082` implements the Fluent runtime with compile-time embedding and runtime fallback to `en`; a \
             missing key fails the build or test in CI, a missing key at runtime renders the key with a marker and \
             increments a metric, and the pseudo-locale generator adds bracket markers and +40% length. Its \
             acceptance includes scroll width vs client width and proptest for argument formatting never panicking; \
             its plural tests cover English plus a synthetic few/many locale. An `i18n check` is the lint; \
             additional locales are added by dropping `.ftl` files and the operator decides which ship.\n\n\
             `T-0083` implements the rule to keep all stored timestamps in UTC, implements `<time datetime>` with \
             relative time, half-hour offsets and the org's configured zone, and renders an absent value as \
             Unknown (reason).\n\n\
             `T-0110` puts the notification email catalog in `i18n/en/email.ftl` with HTML and text variants at \
             600 px and golden files per locale.\n\n\
             `T-0081` signs the locale preference cookie with `HDD_SESSION_KEY`, size-capped, with graceful ignore \
             on tampering.\n\n\
             Identifier formats: a Ray ID is 16 hex characters plus `-HDD1`; a rule ID is `rule_` plus 26 lowercase \
             base32 characters; an API field name such as `ray_id` stays as written; JSON logs use stable field \
             names; an error code starts with `ERR-`, an audit event with `AUD-` and a metric with `MET-` (for \
             example `MET-hdd_panics_total`); the default locale variable is `HDD_I18N_DEFAULT_LOCALE`; `hreflang` \
             is emitted for shipped locales.\n\n\
             An area file is `i18n/<locale>/<area>.ftl` organized by area (`common`, `auth`, `app`, `admin`, \
             `public`, `errors`, `email`). B11.9 fixes user time zone from profile, units explicit and large numbers \
             exact in tables.\n",
        )
    }

    /// A complete fixture master specification for the module's own whole-check test: the B11.8 inventory plus
    /// [`spec_section`].
    pub(crate) fn fixture_spec() -> String {
        let mut spec = String::from(
            "## B11.8 Component inventory (T-0023 fixture)\n\n| Component | Contract |\n| --- | --- |\n\
             | ThemeToggle / LocaleSwitcher / DensityToggle | Persisted display choices. |\n\
             | MarkdownRender | Sanitised Markdown. |\n",
        );
        spec.push_str(&spec_section());
        spec
    }

    /// The unused import guard: the fixture generator keeps the accent helper reachable from the document tests.
    #[allow(
        dead_code,
        reason = "the fixture document is generated from the same map the rule checks"
    )]
    fn accent_probe(letter: char) -> Option<char> {
        accent(letter)
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used, clippy::unwrap_used, reason = "tests")]

    use std::fs;
    use std::path::{Path, PathBuf};

    use super::fixtures;
    use super::*;

    /// A temporary repository for the whole-check tests.
    struct Repo(PathBuf);

    impl Repo {
        fn new(name: &str) -> Repo {
            let dir =
                std::env::temp_dir().join(format!("hdd-xtask-i18n-{}-{name}", std::process::id()));
            let _ = fs::remove_dir_all(&dir);
            fs::create_dir_all(&dir).expect("mkdir");
            Repo(dir)
        }

        fn put(&self, rel: &str, text: &str) {
            let path = self.0.join(rel);
            if let Some(parent) = path.parent() {
                fs::create_dir_all(parent).expect("mkdir");
            }
            fs::write(path, text).expect("write");
        }

        fn root(&self) -> &Path {
            &self.0
        }
    }

    impl Drop for Repo {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn messages(findings: &[Finding]) -> String {
        findings
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>()
            .join("\n")
    }

    fn text() -> String {
        fixtures::i18n_document()
    }

    fn ftl() -> Ftl {
        deck(&fixtures::ftl_texts())
    }

    fn spec() -> String {
        fixtures::fixture_spec()
    }

    /// The fixture tree: the fixture documents of every module whose rule this check compares, the fixture `.ftl`
    /// files and the fixture specification.
    fn good_tree(r: &Repo) {
        for (path, contents) in fixtures::documents() {
            r.put(&path, &contents);
        }
        for (path, contents) in fixtures::ftl_texts() {
            r.put(&path, &contents);
        }
        r.put(CONTENT, &super::super::content::fixtures::content());
        r.put(
            "i18n/glossary.md",
            &super::super::content::fixtures::glossary(),
        );
        r.put(
            ACCESSIBILITY,
            &super::super::a11y::fixtures::accessibility_doc(),
        );
        for (path, contents) in super::super::responsive::fixtures::documents() {
            r.put(&path, &contents);
        }
        r.put(
            ONBOARDING,
            &super::super::onboarding::fixtures::onboarding(),
        );
    }

    #[test]
    fn t23_required_sections_are_present_and_ordered() {
        let doc = text();
        assert!(
            structure_findings(&doc).is_empty(),
            "{}",
            messages(&structure_findings(&doc))
        );
        let missing = doc.replace("## Pseudo-locale", "## Pseudo locale");
        let m = messages(&structure_findings(&missing));
        assert!(m.contains("Pseudo-locale"), "{m}");
        let reordered = doc
            .replace("## Pseudo-locale", "## Tmp")
            .replace("## Test strategy", "## Pseudo-locale")
            .replace("## Tmp", "## Test strategy");
        let m = messages(&structure_findings(&reordered));
        assert!(m.contains("order"), "{m}");
        let no_stub = doc.replace("stub", "planned");
        let m = messages(&structure_findings(&no_stub));
        assert!(m.contains("stub"), "{m}");
    }

    #[test]
    fn t23_key_examples_are_real_keys_with_real_values() {
        let doc = text();
        let deck = ftl();
        assert!(
            message_format_findings(&doc, &deck).is_empty(),
            "{}",
            messages(&message_format_findings(&doc, &deck))
        );
        let invented = doc.replacen("`tagline`", "`invented-key`", 1);
        let m = messages(&message_format_findings(&invented, &deck));
        assert!(m.contains("invented-key"), "{m}");
        let wrong_file = doc.replacen(
            "| `tagline` | `i18n/en/copy-deck.ftl`",
            "| `tagline` | `i18n/en/security-ux.ftl`",
            1,
        );
        let m = messages(&message_format_findings(&wrong_file, &deck));
        assert!(m.contains("tagline"), "{m}");
        let wrong_value = doc.replacen(
            "| `tagline` | `i18n/en/copy-deck.ftl` | Put a firewall in front of your website.",
            "| `tagline` | `i18n/en/copy-deck.ftl` | A paraphrase that is not in the file.",
            1,
        );
        let m = messages(&message_format_findings(&wrong_value, &deck));
        assert!(m.contains("differs"), "{m}");
        let mut fewer = doc.clone();
        for key in [
            "tagline",
            "signup-title",
            "success-saved",
            "fx-domain-remove",
            "fx-org-delete",
            "empty-domains",
        ] {
            let line = fewer
                .lines()
                .find(|line| line.starts_with(&format!("| `{key}` |")))
                .map(str::to_owned);
            if let Some(line) = line {
                fewer = fewer.replace(&format!("{line}\n"), "");
            }
        }
        let m = messages(&message_format_findings(&fewer, &deck));
        assert!(m.contains("at least"), "{m}");
    }

    #[test]
    fn t23_key_naming_convention_is_stated() {
        let doc = text();
        assert!(
            key_naming_findings(&doc).is_empty(),
            "{}",
            messages(&key_naming_findings(&doc))
        );
        let m = messages(&key_naming_findings(
            &doc.replace("never sentences", "short"),
        ));
        assert!(m.contains("never sentences"), "{m}");
        let m = messages(&key_naming_findings(
            &doc.replace("^[a-z0-9]+(-[a-z0-9]+)*$", "any name"),
        ));
        assert!(m.contains("pattern") || m.contains("-"), "{m}");
    }

    #[test]
    fn t23_file_layout_lists_exactly_the_existing_files() {
        let doc = text();
        let deck = ftl();
        assert!(
            file_layout_findings(&doc, &deck).is_empty(),
            "{}",
            messages(&file_layout_findings(&doc, &deck))
        );
        let extra = doc.replacen(
            "| `i18n/en/onboarding.ftl` | onboarding empty states",
            "| `i18n/en/legacy.ftl` | a file that does not exist | none |\n| `i18n/en/onboarding.ftl` | onboarding empty states",
            1,
        );
        let m = messages(&file_layout_findings(&extra, &deck));
        assert!(m.contains("legacy.ftl"), "{m}");
        let removed = doc.replace(
            "| `i18n/en/security-ux.ftl` | dangerous-action confirmations | T-0025 |\n",
            "",
        );
        let m = messages(&file_layout_findings(&removed, &deck));
        assert!(m.contains("security-ux.ftl"), "{m}");
        let no_pattern = doc.replace("i18n/<locale>/<area>.ftl", "the locale files");
        let m = messages(&file_layout_findings(&no_pattern, &deck));
        assert!(m.contains("i18n/<locale>/<area>.ftl"), "{m}");
    }

    #[test]
    fn t23_fallback_chain_and_missing_key_behaviour_are_stated() {
        let doc = text();
        assert!(
            fallback_findings(&doc).is_empty(),
            "{}",
            messages(&fallback_findings(&doc))
        );
        let m = messages(&fallback_findings(
            &doc.replace("locale → language → en", "locale → en"),
        ));
        assert!(m.contains("locale → language → en"), "{m}");
        let m = messages(&fallback_findings(
            &doc.replace("i18n.missing_key", "missing"),
        ));
        assert!(m.contains("i18n.missing_key"), "{m}");
    }

    #[test]
    fn t23_a_key_defined_in_two_files_is_a_finding() {
        let unique = ftl();
        assert!(
            key_uniqueness_findings(&unique).is_empty(),
            "{}",
            messages(&key_uniqueness_findings(&unique))
        );
        let duplicated = deck(&[
            (
                "i18n/en/copy-deck.ftl".to_owned(),
                "shared-key = One value.\n".to_owned(),
            ),
            (
                "i18n/en/onboarding.ftl".to_owned(),
                "shared-key = One value.\n".to_owned(),
            ),
        ]);
        let m = messages(&key_uniqueness_findings(&duplicated));
        assert!(m.contains("shared-key"), "{m}");
    }

    #[test]
    fn t23_pseudo_examples_are_evaluated_by_the_reference_transform() {
        let doc = text();
        assert!(
            pseudo_findings(&doc).is_empty(),
            "{}",
            messages(&pseudo_findings(&doc))
        );
        let bad_example = doc.replace("| `Save` | `[[Šáṽé··]]` |", "| `Save` | `[[Save]]` |");
        let m = messages(&pseudo_findings(&bad_example));
        assert!(m.contains("Save"), "{m}");
        let bad_accent = doc.replace("| `a` | `á` |", "| `a` | `à` |");
        let m = messages(&pseudo_findings(&bad_accent));
        assert!(m.contains("accent") || m.contains('à'), "{m}");
        let missing_cap = doc.replace("capped at 8", "capped");
        let m = messages(&pseudo_findings(&missing_cap));
        assert!(m.contains("cap"), "{m}");
    }

    #[test]
    fn t23_pseudo_selector_variant_text_is_transformed() {
        // D-6: the old rule copied everything between braces, so a selector variant was never accented or expanded.
        assert!(
            !pseudo_transform(fixtures::SELECTOR_INPUT).contains(" event "),
            "the selector variant text is copied unchanged: {}",
            pseudo_transform(fixtures::SELECTOR_INPUT)
        );
        assert_eq!(
            pseudo_transform(fixtures::SELECTOR_INPUT),
            "[[{ $count -> [one] { $count } éṽéñţ·· *[other] { $count } éṽéñţš··· }]]"
        );
        // A placeable reference is still copied unchanged.
        assert_eq!(pseudo_transform("{ $count }"), "[[{ $count }]]");
        assert_eq!(pseudo_transform("{ -brand }"), "[[{ -brand }]]");
        assert_eq!(pseudo_transform("{ NUMBER($n) }"), "[[{ NUMBER($n) }]]");
    }

    #[test]
    fn t23_pseudo_examples_carry_measured_expansion() {
        // D-7: the cap is a deliberate limit and every worked example shows its measured expansion.
        let doc = text();
        assert!(
            doc.contains("Measured expansion"),
            "the worked-example table needs a Measured expansion column (D-7)"
        );
        assert!(
            mentions(&doc, "deliberate limit"),
            "the filler cap must be stated as a deliberate limit (D-7)"
        );
        assert!(
            doc.contains("| `{ $count -> [one]"),
            "the worked-example table needs the evaluated selector example (D-6)"
        );
        let bad = doc.replace("8/30 = 27%", "8/30 = 40%");
        let m = messages(&pseudo_findings(&bad));
        assert!(m.contains("27%"), "{m}");
        let no_cap = doc.replace("deliberate limit", "accident");
        let m = messages(&pseudo_findings(&no_cap));
        assert!(m.contains("deliberate limit"), "{m}");
    }

    #[test]
    fn t23_fluent_only_message_cells() {
        // D-5: the message column is Fluent only, so ICU `, plural,` and `{#` may not appear in it.
        let doc = text();
        let content = super::super::content::fixtures::content();
        assert!(
            !doc.contains("Fluent or ICU"),
            "the formatting column must be titled `Fluent message`, not `Fluent or ICU message`"
        );
        assert!(
            doc.contains("| Item | Rule (en) | Fluent message | Example |"),
            "the formatting table must have the `Fluent message` column"
        );
        assert!(
            formatting_findings(&doc, &content, &spec()).is_empty(),
            "{}",
            messages(&formatting_findings(&doc, &content, &spec()))
        );
        let icu = doc.replace(
            "`{ $count -> [one] { $count } second *[other] { $count } seconds }`",
            "`{ $count, plural, one {# second} other {# seconds} }`",
        );
        let m = messages(&formatting_findings(&icu, &content, &spec()));
        assert!(m.contains("Fluent"), "{m}");
        let hash = doc.replacen(
            "`DATETIME($ts, timeStyle: \"short\", timeZone: $zone)`",
            "`DATETIME($ts, timeStyle: \"short\", timeZone: $zone) {#}`",
            1,
        );
        let m = messages(&formatting_findings(&hash, &content, &spec()));
        assert!(m.contains("Fluent"), "{m}");
        let bad_content = content.replace(
            "| Requests | whole number, grouped in threes |",
            "| Requests | count with `, plural,` |",
        );
        let m = messages(&formatting_findings(&doc, &bad_content, &spec()));
        assert!(m.contains("CONTENT"), "{m}");
    }

    #[test]
    fn t23_pseudo_transform_matches_the_fixture_examples() {
        assert_eq!(pseudo_transform("Save"), "[[Šáṽé··]]");
        assert_eq!(pseudo_transform("Domain added."), "[[Ðóɱáíñ··· áððéð··.]]");
        assert_eq!(
            pseudo_transform("Switch { $domain } to block mode?"),
            "[[Šŵíţçĥ··· { $domain } ţó· ƀĺóçķ·· ɱóðé··?]]"
        );
        assert_eq!(pseudo_transform("0 events"), "[[0 éṽéñţš···]]");
        assert_eq!(pseudo_transform("OK"), "[[ÓĶ·]]");
        assert_eq!(pseudo_transform("a"), "[[á·]]");
        assert_eq!(pseudo_transform("{ $count }"), "[[{ $count }]]");
        assert_eq!(pseudo_transform("A4"), "[[Á·4]]");
        assert_eq!(padding(1), 1);
        assert_eq!(padding(2), 1);
        assert_eq!(padding(5), 2);
        assert_eq!(padding(10), 4);
        assert_eq!(padding(30), MAX_PADDING);
    }

    #[test]
    fn t23_rtl_readiness_lists_real_properties_and_handles_dir() {
        let r = Repo::new("rtl");
        good_tree(&r);
        let doc = text();
        assert!(
            rtl_findings(&doc, r.root(), &spec()).is_empty(),
            "{}",
            messages(&rtl_findings(&doc, r.root(), &spec()))
        );
        let physical = doc.replace(
            "| `margin-inline-start` | `margin-left` |",
            "| `margin-left` | `margin-left` |",
        );
        let m = messages(&rtl_findings(&physical, r.root(), &spec()));
        assert!(m.contains("margin-left"), "{m}");
        let no_dir = doc.replace("dir=\"auto\"", "dir");
        let m = messages(&rtl_findings(&no_dir, r.root(), &spec()));
        assert!(m.contains("dir=\"auto\""), "{m}");
        let no_component = doc.replace("`LocaleSwitcher`, ", "");
        let m = messages(&rtl_findings(&no_component, r.root(), &spec()));
        assert!(m.contains("LocaleSwitcher"), "{m}");
        let wrong_viewport = doc.replace("1920x1080", "1999x999");
        let m = messages(&rtl_findings(&wrong_viewport, r.root(), &spec()));
        assert!(m.contains("1920x1080"), "{m}");
        let wrong_margin = doc.replace("its 12 mm margins", "its 15 mm margins");
        let m = messages(&rtl_findings(&wrong_margin, r.root(), &spec()));
        assert!(m.contains("12 mm"), "{m}");
    }

    #[test]
    fn t23_rtl_icon_table_is_honest_about_the_missing_inventory() {
        let r = Repo::new("icons");
        good_tree(&r);
        let doc = text();
        assert!(
            rtl_findings(&doc, r.root(), &spec()).is_empty(),
            "{}",
            messages(&rtl_findings(&doc, r.root(), &spec()))
        );
        r.put("design/icons/arrow-left.svg", "<svg></svg>\n");
        let m = messages(&rtl_findings(&doc, r.root(), &spec()));
        assert!(m.contains("arrow-left"), "{m}");
        let claimed = doc.replace(
            "no icon inventory exists yet",
            "the inventory is `design/icons`",
        );
        let m = messages(&rtl_findings(&claimed, r.root(), &spec()));
        assert!(
            m.contains("no icon inventory exists yet") || m.contains("arrow-left"),
            "{m}"
        );
    }

    #[test]
    fn t23_negotiation_order_and_headers() {
        let doc = text();
        assert!(
            negotiation_findings(&doc, &spec()).is_empty(),
            "{}",
            messages(&negotiation_findings(&doc, &spec()))
        );
        let cookie_first = doc.replace(
            "## Locale negotiation\n\n",
            "## Locale negotiation\n\nThe cookie is read before the account setting is read.\n\n",
        );
        let m = messages(&negotiation_findings(&cookie_first, &spec()));
        assert!(m.contains("order"), "{m}");
        let no_vary = doc.replace(VARY, "Vary: Accept-Language");
        let m = messages(&negotiation_findings(&no_vary, &spec()));
        assert!(m.contains("Vary"), "{m}");
        let no_language_header = doc.replace("Content-Language", "language header");
        let m = messages(&negotiation_findings(&no_language_header, &spec()));
        assert!(m.contains("Content-Language"), "{m}");
        let client_side = doc.replace("server-rendered", "script rendered");
        let m = messages(&negotiation_findings(&client_side, &spec()));
        assert!(m.contains("server"), "{m}");
    }

    #[test]
    fn t23_formatting_agrees_with_the_content_strategy() {
        let doc = text();
        let content = super::super::content::fixtures::content();
        let examples = content_format_examples(&content);
        assert!(!examples.is_empty(), "no CONTENT examples parsed");
        assert!(
            formatting_findings(&doc, &content, &spec()).is_empty(),
            "{}",
            messages(&formatting_findings(&doc, &content, &spec()))
        );
        let drifted = doc.replace("14:05 UTC", "two in the afternoon");
        let m = messages(&formatting_findings(&drifted, &content, &spec()));
        assert!(m.contains("14:05 UTC"), "{m}");
        let no_datetime = doc.replace("`DATETIME($ts, dateStyle: \"medium\")`", "a date");
        let m = messages(&formatting_findings(&no_datetime, &content, &spec()));
        assert!(m.contains("Fluent") || m.contains("ICU"), "{m}");
        let no_unknown = doc.replace("`Unknown (reason)`", "a dash");
        let m = messages(&formatting_findings(&no_unknown, &content, &spec()));
        assert!(m.contains("Unknown (reason)"), "{m}");
    }

    #[test]
    fn t23_not_translated_list_matches_the_spec_formats() {
        let doc = text();
        assert!(
            not_translated_findings(&doc, &spec()).is_empty(),
            "{}",
            messages(&not_translated_findings(&doc, &spec()))
        );
        let wrong_ray = doc.replace("-HDD1", "-HDD2");
        let m = messages(&not_translated_findings(&wrong_ray, &spec()));
        assert!(m.contains("-HDD1"), "{m}");
        let no_rule = doc.replace("`rule_ab2cd3ef4gh5jk6mn7pq2rs3tu`", "a rule");
        let m = messages(&not_translated_findings(&no_rule, &spec()));
        assert!(m.contains("rule_"), "{m}");
        let no_translated = doc.replace("**What is translated:**", "**More:**");
        let m = messages(&not_translated_findings(&no_translated, &spec()));
        assert!(m.contains("What is translated"), "{m}");
    }

    #[test]
    fn t23_email_localization_covers_the_activation_emails() {
        let doc = text();
        let onboarding = super::super::onboarding::fixtures::onboarding();
        assert!(
            email_findings(&doc, &onboarding).is_empty(),
            "{}",
            messages(&email_findings(&doc, &onboarding))
        );
        let missing_verify = doc.replace("| verify | subject and body | whole email to `en` |", "");
        let m = messages(&email_findings(&missing_verify, &onboarding));
        assert!(m.contains("verify"), "{m}");
        let no_fallback = doc.replace("whole email falls back to `en`", "some of it falls back");
        let m = messages(&email_findings(&no_fallback, &onboarding));
        assert!(m.contains("whole email"), "{m}");
    }

    #[test]
    fn t23_translator_workflow_needs_no_external_service() {
        let doc = text();
        let content = super::super::content::fixtures::content();
        assert!(
            translator_findings(&doc, &content).is_empty(),
            "{}",
            messages(&translator_findings(&doc, &content))
        );
        let network = doc.replace(
            "The hand-off is a directory in the repository:",
            "The hand-off uses https://example.test/dashboard:",
        );
        let m = messages(&translator_findings(&network, &content));
        assert!(m.contains("external") || m.contains("network"), "{m}");
        let no_context = doc.replace("`# context:`", "a comment");
        let m = messages(&translator_findings(&no_context, &content));
        assert!(m.contains("# context:"), "{m}");
        let extra_guidance = content.replace(
            "Use Fluent placeables",
            "Use a new token such as `{$user}` and Fluent placeables",
        );
        let m = messages(&translator_findings(&doc, &extra_guidance));
        assert!(m.contains("{$user}"), "{m}");
    }

    #[test]
    fn t23_launch_locales_equal_the_profile_locales_key() {
        let doc = text();
        let profile = fixtures::profile();
        assert!(
            launch_findings(&doc, &profile).is_empty(),
            "{}",
            messages(&launch_findings(&doc, &profile))
        );
        let more = profile.replace("locales: [en]", "locales: [en, de]");
        let m = messages(&launch_findings(&doc, &more));
        assert!(m.contains("de"), "{m}");
        let extra = doc.replace(
            "| en | launch |",
            "| en | launch | the default |\n| de | launch |",
        );
        let m = messages(&launch_findings(&extra, &profile));
        assert!(m.contains("de"), "{m}");
        let no_criteria = doc
            .replace(
                "| native-speaker review | a reviewer signs off the file |\n",
                "",
            )
            .replace(
                "| glossary complete | every glossary term has a translation |\n",
                "",
            );
        let m = messages(&launch_findings(&no_criteria, &profile));
        assert!(m.contains("criteria") || m.contains("criterion"), "{m}");
        let bad_schema = profile.replace("schema_version: 5", "schema_version: 4");
        let m = messages(&launch_findings(&doc, &bad_schema));
        assert!(m.contains("schema_version"), "{m}");
    }

    #[test]
    fn t23_test_strategy_covers_overflow_missing_keys_and_plurals() {
        let doc = text();
        assert!(
            test_strategy_findings(&doc, &spec()).is_empty(),
            "{}",
            messages(&test_strategy_findings(&doc, &spec()))
        );
        let no_overflow = doc.replace("scroll width vs client width", "screenshot review");
        let m = messages(&test_strategy_findings(&no_overflow, &spec()));
        assert!(m.contains("overflow") || m.contains("scroll width"), "{m}");
        let no_plural = doc.replace(
            "| plural | `[one]` and `[other]` for English and a synthetic few and many locale | T-0082 unit |",
            "",
        );
        let m = messages(&test_strategy_findings(&no_plural, &spec()));
        assert!(m.contains("plural"), "{m}");
        let no_unverified = doc.replace("UNVERIFIED(capability_not_supplied)", "planned");
        let m = messages(&test_strategy_findings(&no_unverified, &spec()));
        assert!(m.contains("UNVERIFIED"), "{m}");
    }

    #[test]
    fn t23_a_complete_fixture_tree_passes_and_a_missing_document_is_named() {
        let r = Repo::new("tree");
        good_tree(&r);
        let f = check_with_spec(r.root(), &spec());
        assert!(f.is_empty(), "{}", messages(&f));
        let empty = Repo::new("empty");
        let m = messages(&check_with_spec(empty.root(), &spec()));
        assert!(m.contains(I18N), "{m}");
        assert!(m.contains(PROFILE_EXAMPLE), "{m}");
    }

    #[test]
    fn t23_malformed_input_is_a_finding_not_a_panic() {
        let r = Repo::new("malformed");
        r.put(
            I18N,
            "# I18N\n\n## Message format\n\n| Key | File |\n| --- | --- |\n| | |\n",
        );
        r.put(PROFILE_EXAMPLE, "not a profile\n");
        let f = check_with_spec(r.root(), &spec());
        assert!(!f.is_empty(), "a malformed tree must produce findings");
        let empty = Repo::new("malformed2");
        empty.put(I18N, "");
        empty.put(PROFILE_EXAMPLE, "");
        let f = check_with_spec(empty.root(), &spec());
        assert!(!f.is_empty(), "an empty document must produce findings");
    }
}
