//! Normalisation of an inspected value (C4.3): decoding rounds, lookalike folding, comment and whitespace
//! canonicalisation, case folding, NUL removal, and the span map back to the value as the attacker sent it.
//!
//! The pipeline is bounded (three decoding layers, at most [`MAX_NORMALIZED_CHARS`] characters), linear in the size
//! of the input and panic-free. The normalised text is what every detector family matches; the span map lets the
//! evidence window come from the original request.

/// The hard limit on the number of characters the pipeline keeps. Bodies are capped at 256 KiB, so this is a
/// belt-and-braces bound for direct callers and fuzzing.
pub(crate) const MAX_NORMALIZED_CHARS: usize = 1 << 20;

/// Percent and escape decoding is iterated to a fixed point for at most this many layers (C4.3: three).
const MAX_DECODE_ROUNDS: usize = 3;

/// A long bound on an HTML entity name; anything longer is left as literal text.
const MAX_ENTITY_NAME: usize = 8;

/// The evasion evidence observed while normalising (C4.3, C4.8). The flags are recorded in the audit trail; the
/// detector also uses some of them for the H8 family.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) struct EvasionFlags {
    /// At least one `%XX` or `%uXXXX` sequence was decoded.
    pub(crate) percent_encoding: bool,
    /// More than one decoding layer changed the value.
    pub(crate) multiple_encoding: bool,
    /// At least one HTML entity was decoded.
    pub(crate) html_entity: bool,
    /// At least one `%uXXXX`, `\uXXXX` or `\xNN` escape was decoded.
    pub(crate) unicode_escape: bool,
    /// A backslash escape such as `\'` was decoded.
    pub(crate) backslash_escape: bool,
    /// A wide-byte (GBK-style) quote sequence such as `%bf%27` was seen.
    pub(crate) multibyte_quote: bool,
    /// A NUL byte was removed.
    pub(crate) null_byte: bool,
    /// An inline `/* ... */` comment was folded to a space.
    pub(crate) inline_comment: bool,
    /// A MySQL versioned comment (`/*!50000 ... */`) was unwrapped.
    pub(crate) versioned_comment: bool,
    /// A `+` was treated as a space (query or form-urlencoded value).
    pub(crate) plus_as_space: bool,
    /// A fullwidth or lookalike character was folded to ASCII.
    pub(crate) lookalike: bool,
    /// Invalid UTF-8 was seen during decoding.
    pub(crate) invalid_utf8: bool,
    /// An overlong UTF-8 sequence was seen during decoding.
    pub(crate) overlong_utf8: bool,
    /// The value was longer than [`MAX_NORMALIZED_CHARS`] and was cut.
    pub(crate) truncated: bool,
}

/// A normalised value: the text the detectors match, the span map to the original, and the evasion flags.
#[derive(Debug, Clone, Default)]
pub(crate) struct Normalized {
    /// The decoded and canonicalised text, lower-cased.
    pub(crate) text: String,
    /// For every character of `text`, the byte offset in the input it came from.
    pub(crate) map: Vec<u32>,
    /// What the pipeline had to undo.
    pub(crate) flags: EvasionFlags,
}

impl Normalized {
    /// The character index in `text` of a byte index (always a character boundary for token starts).
    pub(crate) fn char_index_of(&self, byte_index: usize) -> usize {
        self.text
            .get(..byte_index)
            .map(|head| head.chars().count())
            .unwrap_or(0)
    }
}

/// One decoded character with the byte offset it came from.
type Pairs = Vec<(char, u32)>;

/// Normalise one value. `plus_as_space` is true for query and form-urlencoded values (C4.3: `+` means space there,
/// not in a path segment, header or cookie).
#[cfg(test)]
pub(crate) fn normalize(input: &str, plus_as_space: bool) -> Normalized {
    let mut ops = 0u64;
    normalize_counted(input, plus_as_space, &mut ops)
}

/// Normalise one value and count the characters examined (test instrumentation for the linear-time bound).
pub(crate) fn normalize_counted(input: &str, plus_as_space: bool, ops: &mut u64) -> Normalized {
    let mut flags = EvasionFlags::default();
    let mut pairs: Pairs = input
        .char_indices()
        .map(|(index, c)| (c, index as u32))
        .collect();
    if pairs.len() > MAX_NORMALIZED_CHARS {
        pairs.truncate(MAX_NORMALIZED_CHARS);
        flags.truncated = true;
    }

    for round in 0..MAX_DECODE_ROUNDS {
        let before = pairs.clone();
        let mut next = percent_decode(&pairs, plus_as_space, &mut flags, ops);
        next = entity_decode(&next, &mut flags, ops);
        next = escape_decode(&next, &mut flags, ops);
        if next == before {
            pairs = next;
            break;
        }
        if round > 0 {
            flags.multiple_encoding = true;
        }
        pairs = next;
        if pairs.len() > MAX_NORMALIZED_CHARS {
            pairs.truncate(MAX_NORMALIZED_CHARS);
            flags.truncated = true;
        }
    }

    pairs = fold(pairs, &mut flags, ops);
    pairs = canonicalize(pairs, &mut flags, ops);
    if pairs.len() > MAX_NORMALIZED_CHARS {
        pairs.truncate(MAX_NORMALIZED_CHARS);
        flags.truncated = true;
    }

    let mut text = String::with_capacity(pairs.len());
    let mut map = Vec::with_capacity(pairs.len());
    for (c, offset) in pairs {
        text.push(c);
        map.push(offset);
    }
    Normalized { text, map, flags }
}

fn hex_value(byte: u8) -> Option<u32> {
    match byte {
        b'0'..=b'9' => Some(u32::from(byte - b'0')),
        b'a'..=b'f' => Some(u32::from(byte - b'a') + 10),
        b'A'..=b'F' => Some(u32::from(byte - b'A') + 10),
        _ => None,
    }
}

enum PercentPiece {
    Byte(u8),
    Char(char),
}

/// Decode one `%uXXXX` or `%XX` sequence starting at `start`, returning the piece and the bytes consumed.
fn parse_percent(
    bytes: &[u8],
    start: usize,
    flags: &mut EvasionFlags,
) -> Option<(PercentPiece, usize)> {
    if start > bytes.len().saturating_sub(3) {
        return None;
    }
    if matches!(bytes.get(start + 1), Some(b'u' | b'U')) {
        let mut value = 0u32;
        let mut seen = 0usize;
        for index in 0..4 {
            let digit = bytes.get(start + 2 + index).copied().and_then(hex_value);
            match digit {
                Some(digit) => {
                    value = value.saturating_mul(16).saturating_add(digit);
                    seen += 1;
                }
                None => break,
            }
        }
        if seen == 4 {
            flags.unicode_escape = true;
            let ch = char::from_u32(value).unwrap_or('\u{FFFD}');
            return Some((PercentPiece::Char(ch), 6));
        }
    }
    let high = bytes.get(start + 1).copied().and_then(hex_value)?;
    let low = bytes.get(start + 2).copied().and_then(hex_value)?;
    let byte = u8::try_from(high.saturating_mul(16).saturating_add(low)).unwrap_or(0);
    Some((PercentPiece::Byte(byte), 3))
}

fn to_bytes(pairs: &[(char, u32)]) -> (Vec<u8>, Vec<u32>) {
    let mut bytes = Vec::with_capacity(pairs.len());
    let mut offsets = Vec::with_capacity(pairs.len());
    let mut buffer = [0u8; 4];
    for &(c, offset) in pairs {
        for byte in c.encode_utf8(&mut buffer).as_bytes() {
            bytes.push(*byte);
            offsets.push(offset);
        }
    }
    (bytes, offsets)
}

fn utf8_len(first: u8) -> usize {
    match first {
        0x00..=0x7F => 1,
        0xC2..=0xDF => 2,
        0xE0..=0xEF => 3,
        0xF0..=0xF4 => 4,
        _ => 1,
    }
}

fn from_bytes(bytes: &[u8], offsets: &[u32], flags: &mut EvasionFlags) -> Pairs {
    let mut pairs: Pairs = Vec::with_capacity(bytes.len());
    let mut index = 0usize;
    while let Some(&first) = bytes.get(index) {
        let length = utf8_len(first);
        if length > 1 {
            let chunk = bytes.get(index..index.saturating_add(length));
            let offset = offsets.get(index).copied().unwrap_or(0);
            if let Some(chunk) = chunk
                && let Ok(text) = std::str::from_utf8(chunk)
                && let Some(c) = text.chars().next()
            {
                pairs.push((c, offset));
                index += length;
                continue;
            }
            if first == 0xC0 || first == 0xC1 {
                flags.overlong_utf8 = true;
            }
            flags.invalid_utf8 = true;
            pairs.push(('\u{FFFD}', offset));
            index += 1;
            continue;
        }
        if first >= 0x80 {
            flags.invalid_utf8 = true;
            pairs.push(('\u{FFFD}', offsets.get(index).copied().unwrap_or(0)));
        } else {
            pairs.push((char::from(first), offsets.get(index).copied().unwrap_or(0)));
        }
        index += 1;
    }
    pairs
}

fn percent_decode(
    pairs: &[(char, u32)],
    plus_as_space: bool,
    flags: &mut EvasionFlags,
    ops: &mut u64,
) -> Pairs {
    let (bytes, offsets) = to_bytes(pairs);
    let mut out_bytes: Vec<u8> = Vec::with_capacity(bytes.len());
    let mut out_offsets: Vec<u32> = Vec::with_capacity(bytes.len());
    let mut from_percent: Vec<bool> = Vec::with_capacity(bytes.len());
    let mut index = 0usize;
    while let Some(&byte) = bytes.get(index) {
        *ops = ops.saturating_add(1);
        let offset = offsets.get(index).copied().unwrap_or(0);
        if byte == b'%'
            && let Some((piece, consumed)) = parse_percent(&bytes, index, flags)
        {
            match piece {
                PercentPiece::Byte(decoded) => {
                    flags.percent_encoding = true;
                    out_bytes.push(decoded);
                    out_offsets.push(offset);
                    from_percent.push(true);
                }
                PercentPiece::Char(c) => {
                    let mut buffer = [0u8; 4];
                    for encoded in c.encode_utf8(&mut buffer).as_bytes() {
                        out_bytes.push(*encoded);
                        out_offsets.push(offset);
                        from_percent.push(false);
                    }
                }
            }
            index += consumed;
            continue;
        }
        if plus_as_space && byte == b'+' {
            flags.plus_as_space = true;
            out_bytes.push(b' ');
            out_offsets.push(offset);
            from_percent.push(false);
            index += 1;
            continue;
        }
        out_bytes.push(byte);
        out_offsets.push(offset);
        from_percent.push(false);
        index += 1;
    }
    // A percent-decoded 0x27 right after a percent-decoded wide-byte lead is a GBK-style quote evasion (C4.8.6).
    for (position, &byte) in out_bytes.iter().enumerate() {
        if byte == b'\'' {
            let previous = position.checked_sub(1);
            if let Some(previous) = previous
                && from_percent.get(previous).copied().unwrap_or(false)
                && from_percent.get(position).copied().unwrap_or(false)
                && out_bytes
                    .get(previous)
                    .map(|lead| (0x81..=0xFE).contains(lead))
                    .unwrap_or(false)
            {
                flags.multibyte_quote = true;
            }
        }
    }
    from_bytes(&out_bytes, &out_offsets, flags)
}

fn entity_decode(pairs: &[(char, u32)], flags: &mut EvasionFlags, ops: &mut u64) -> Pairs {
    let mut out: Pairs = Vec::with_capacity(pairs.len());
    let mut index = 0usize;
    while let Some(&(c, offset)) = pairs.get(index) {
        *ops = ops.saturating_add(1);
        if c == '&'
            && let Some((decoded, consumed)) = parse_entity(pairs, index)
        {
            flags.html_entity = true;
            out.push((decoded, offset));
            index += consumed;
            continue;
        }
        out.push((c, offset));
        index += 1;
    }
    out
}

/// Parse one HTML entity starting at the `&` at `start`; returns the decoded character and characters consumed.
fn parse_entity(pairs: &[(char, u32)], start: usize) -> Option<(char, usize)> {
    let mut index = start + 1;
    match pairs.get(index).map(|(c, _)| *c) {
        Some('#') => {
            index += 1;
            let hexadecimal = matches!(pairs.get(index).map(|(c, _)| *c), Some('x' | 'X'));
            if hexadecimal {
                index += 1;
            }
            let mut value = 0u32;
            let mut seen = 0usize;
            while let Some(&(c, _)) = pairs.get(index) {
                let digit = match c {
                    '0'..='9' => Some(u32::from(c as u8 - b'0')),
                    'a'..='f' if hexadecimal => Some(u32::from(c as u8 - b'a') + 10),
                    'A'..='F' if hexadecimal => Some(u32::from(c as u8 - b'A') + 10),
                    _ => None,
                };
                let Some(digit) = digit else { break };
                value = value
                    .saturating_mul(if hexadecimal { 16 } else { 10 })
                    .saturating_add(digit);
                index += 1;
                seen += 1;
                if seen > 8 {
                    return None;
                }
            }
            if seen == 0 {
                return None;
            }
            if pairs.get(index).map(|(c, _)| *c) == Some(';') {
                index += 1;
            }
            Some((char::from_u32(value).unwrap_or('\u{FFFD}'), index - start))
        }
        Some(_) => {
            let mut name = String::new();
            while let Some(&(c, _)) = pairs.get(index) {
                if c.is_ascii_alphanumeric() && name.len() < MAX_ENTITY_NAME {
                    name.push(c);
                    index += 1;
                } else {
                    break;
                }
            }
            if name.is_empty() {
                return None;
            }
            let decoded = match name.to_ascii_lowercase().as_str() {
                "amp" => '&',
                "lt" => '<',
                "gt" => '>',
                "quot" => '"',
                "apos" => '\'',
                "nbsp" => ' ',
                "sol" => '/',
                "bsol" => '\\',
                "comma" => ',',
                "colon" => ':',
                "semi" => ';',
                "lpar" => '(',
                "rpar" => ')',
                "equals" => '=',
                "num" => '#',
                "percnt" => '%',
                "plus" => '+',
                "period" => '.',
                "lowbar" => '_',
                "ast" => '*',
                "tab" => '\t',
                "newline" => '\n',
                _ => return None,
            };
            if pairs.get(index).map(|(c, _)| *c) == Some(';') {
                index += 1;
            }
            Some((decoded, index - start))
        }
        None => None,
    }
}

fn escape_decode(pairs: &[(char, u32)], flags: &mut EvasionFlags, ops: &mut u64) -> Pairs {
    let mut out: Pairs = Vec::with_capacity(pairs.len());
    let mut index = 0usize;
    while let Some(&(c, offset)) = pairs.get(index) {
        *ops = ops.saturating_add(1);
        if c != '\\' {
            out.push((c, offset));
            index += 1;
            continue;
        }
        let next = pairs.get(index + 1).map(|(c, _)| *c);
        let mut handled = true;
        match next {
            Some('u' | 'x') => {
                let hexadecimal = next == Some('x');
                let digits = if hexadecimal { 2 } else { 4 };
                let mut value = 0u32;
                let mut seen = 0usize;
                for step in 0..digits {
                    let digit = pairs.get(index + 2 + step).and_then(|(c, _)| match c {
                        '0'..='9' => Some(u32::from(*c as u8 - b'0')),
                        'a'..='f' => Some(u32::from(*c as u8 - b'a') + 10),
                        'A'..='F' => Some(u32::from(*c as u8 - b'A') + 10),
                        _ => None,
                    });
                    match digit {
                        Some(digit) => {
                            value = value.saturating_mul(16).saturating_add(digit);
                            seen += 1;
                        }
                        None => break,
                    }
                }
                if seen == digits {
                    flags.unicode_escape = true;
                    out.push((char::from_u32(value).unwrap_or('\u{FFFD}'), offset));
                    index += 2 + digits;
                } else {
                    handled = false;
                }
            }
            Some('\'') => {
                flags.backslash_escape = true;
                out.push(('\'', offset));
                index += 2;
            }
            Some('"') => {
                flags.backslash_escape = true;
                out.push(('"', offset));
                index += 2;
            }
            Some('\\') => {
                out.push(('\\', offset));
                index += 2;
            }
            Some('/') => {
                out.push(('/', offset));
                index += 2;
            }
            Some('n') => {
                out.push(('\n', offset));
                index += 2;
            }
            Some('t') => {
                out.push(('\t', offset));
                index += 2;
            }
            Some('r') => {
                out.push(('\r', offset));
                index += 2;
            }
            Some('b') => {
                out.push(('\u{0008}', offset));
                index += 2;
            }
            Some('f') => {
                out.push(('\u{000C}', offset));
                index += 2;
            }
            Some(_) => handled = false,
            None => handled = false,
        }
        if !handled {
            out.push((c, offset));
            index += 1;
        }
    }
    out
}

/// Fold fullwidth and lookalike characters to their ASCII equivalents and drop NUL bytes (C4.3).
fn fold(pairs: Pairs, flags: &mut EvasionFlags, ops: &mut u64) -> Pairs {
    let mut out: Pairs = Vec::with_capacity(pairs.len());
    for (c, offset) in pairs {
        *ops = ops.saturating_add(1);
        if c == '\0' {
            flags.null_byte = true;
            continue;
        }
        match fold_char(c) {
            Some(folded) => {
                flags.lookalike = true;
                out.push((folded, offset));
            }
            None => out.push((c, offset)),
        }
    }
    out
}

fn fold_char(c: char) -> Option<char> {
    let code = u32::from(c);
    if (0xFF01..=0xFF5E).contains(&code) {
        return char::from_u32(code - 0xFEE0);
    }
    match c {
        '\u{02BC}' | '\u{2018}' | '\u{2019}' | '\u{201B}' | '\u{00B4}' | '\u{2032}' => Some('\''),
        '\u{201C}' | '\u{201D}' => Some('"'),
        '\u{2010}'..='\u{2015}' => Some('-'),
        '\u{00A0}'
        | '\u{2000}'..='\u{200A}'
        | '\u{2028}'
        | '\u{2029}'
        | '\u{202F}'
        | '\u{205F}'
        | '\u{3000}' => Some(' '),
        _ => None,
    }
}

/// Unwrap versioned comments, fold terminated inline comments to a space, collapse whitespace and controls, and
/// fold case.
fn canonicalize(pairs: Pairs, flags: &mut EvasionFlags, ops: &mut u64) -> Pairs {
    let mut unfolded: Pairs = Vec::with_capacity(pairs.len());
    let mut index = 0usize;
    // Once an opener has no closing `*/` after it, no later opener can have one either; this flag keeps the scan
    // linear on values full of unterminated comment openers (review R1-2).
    let mut no_more_closers = false;
    while let Some(&(c, offset)) = pairs.get(index) {
        *ops = ops.saturating_add(1);
        let opens_comment = c == '/'
            && pairs.get(index + 1).map(|(next, _)| *next) == Some('*')
            && index + 1 < pairs.len();
        if opens_comment && !no_more_closers {
            let mut close = None;
            let mut scan = index + 2;
            while scan < pairs.len() {
                let is_close = pairs.get(scan).map(|(c, _)| *c) == Some('*')
                    && pairs.get(scan + 1).map(|(c, _)| *c) == Some('/');
                if is_close {
                    close = Some(scan);
                    break;
                }
                scan += 1;
            }
            if let Some(close) = close {
                flags.inline_comment = true;
                let inner = pairs.get(index + 2..close).unwrap_or(&[]);
                let (content, versioned) = match inner {
                    [('!', _), rest @ ..] => (rest, true),
                    _ => (inner, false),
                };
                if versioned {
                    flags.versioned_comment = true;
                    let mut start = 0usize;
                    while let Some((c, _)) = content.get(start) {
                        if c.is_ascii_digit() {
                            start += 1;
                        } else {
                            break;
                        }
                    }
                    let content = content.get(start..).unwrap_or(&[]);
                    unfolded.push((' ', offset));
                    unfolded.extend_from_slice(content);
                    if !content.is_empty() {
                        unfolded.push((' ', offset));
                    }
                } else {
                    unfolded.push((' ', offset));
                }
                index = close + 2;
                continue;
            }
            // No closing `*/` exists at or after this position, so no later opener can be closed either.
            no_more_closers = true;
            // An unterminated `/*` stays visible: it is the H2 comment-open signal.
        }
        unfolded.push((c, offset));
        index += 1;
    }

    let mut out: Pairs = Vec::with_capacity(unfolded.len());
    let mut previous_space = false;
    for (c, offset) in unfolded {
        *ops = ops.saturating_add(1);
        if c.is_whitespace() || c.is_control() {
            if previous_space {
                continue;
            }
            previous_space = true;
            out.push((' ', offset));
        } else {
            previous_space = false;
            out.push((c.to_ascii_lowercase(), offset));
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn text_of(input: &str) -> String {
        normalize(input, false).text
    }

    fn query_text(input: &str) -> String {
        normalize(input, true).text
    }

    #[test]
    fn lowercases_and_collapses_whitespace_and_controls() {
        assert_eq!(text_of("'   OR\t1\n=1--"), "' or 1 =1--");
        assert_eq!(text_of("A\u{0000}B"), "ab");
    }

    #[test]
    fn decodes_percent_encoding_to_three_layers() {
        assert_eq!(text_of("%27%20OR%201=1--"), "' or 1=1--");
        assert_eq!(text_of("%2527%2520OR%25201=1--"), "' or 1=1--");
        assert_eq!(text_of("%252527%25"), "'%");
        assert_eq!(text_of("%u0027 OR 1=1--"), "' or 1=1--");
        assert_eq!(text_of("%C3%A9"), "\u{e9}");
    }

    #[test]
    fn decodes_html_entities_and_json_escapes() {
        assert_eq!(text_of("&#39; OR 1=1--"), "' or 1=1--");
        assert_eq!(text_of("&#x27; OR 1=1--"), "' or 1=1--");
        assert_eq!(text_of("&apos; OR 1=1--"), "' or 1=1--");
        assert_eq!(text_of("\\u0027 OR 1=1--"), "' or 1=1--");
        assert_eq!(text_of("\\x27 OR 1=1--"), "' or 1=1--");
        assert_eq!(text_of("\\' OR 1=1--"), "' or 1=1--");
    }

    #[test]
    fn folds_lookalike_quotes_and_fullwidth() {
        assert_eq!(text_of("\u{2019} OR 1=1--"), "' or 1=1--");
        assert_eq!(text_of("\u{02BC} OR 1=1--"), "' or 1=1--");
        assert_eq!(text_of("\u{FF07} OR \u{FF11}=\u{FF11}--"), "' or 1=1--");
        assert_eq!(
            text_of("\u{201C} or \u{201D}\u{201D}=\u{201D}"),
            "\" or \"\"=\""
        );
    }

    #[test]
    fn plus_is_a_space_only_in_query_and_form_values() {
        assert_eq!(query_text("' OR+1=1--"), "' or 1=1--");
        assert_eq!(text_of("' OR+1=1--"), "' or+1=1--");
    }

    #[test]
    fn inline_comments_are_spaces_and_versioned_comments_are_unwrapped() {
        assert_eq!(text_of("'/**/OR/**/1=1--"), "' or 1=1--");
        assert_eq!(text_of("/*!50000union*//*!50000select*/"), " union select ");
        assert_eq!(text_of("admin'/*"), "admin'/*");
    }

    #[test]
    fn flags_record_evasions() {
        let normalised = normalize("%2527/*x*/&apos;", false);
        assert!(normalised.flags.percent_encoding);
        assert!(normalised.flags.multiple_encoding);
        assert!(normalised.flags.inline_comment);
        assert!(normalised.flags.html_entity);
        assert!(normalize("%bf%27", false).flags.multibyte_quote);
        assert!(normalize("a\0b", false).flags.null_byte);
        assert!(normalize("\u{FF07}", false).flags.lookalike);
        assert!(normalize("\u{2019}", false).flags.lookalike);
    }

    #[test]
    fn normalisation_is_idempotent() {
        for sample in [
            "' OR 1=1--",
            "%2527 OR 1=1--",
            "&#39;/**/OR/**/1=1--",
            "admin' --",
            "1 UNION ALL SELECT username,password FROM users",
            "O'Brien",
            "it's -- fine",
            "\u{FF07} or \u{FF11}=\u{FF11}--",
        ] {
            let once = normalize(sample, true).text;
            let twice = normalize(&once, true).text;
            assert_eq!(once, twice, "not idempotent for {sample:?}");
        }
    }

    #[test]
    fn span_map_points_back_into_the_original() {
        let raw = "abc' OR 1=1--";
        let normalised = normalize(raw, false);
        assert_eq!(normalised.map.len(), normalised.text.chars().count());
        let byte = normalised.text.find("or").unwrap_or(0);
        let character = normalised.char_index_of(byte);
        let offset = normalised.map.get(character).copied().unwrap_or(0) as usize;
        assert_eq!(
            raw.get(offset..)
                .and_then(|tail| tail.chars().next())
                .map(|c| c.to_ascii_lowercase()),
            Some('o')
        );
    }

    #[test]
    fn wide_byte_quote_decodes_to_a_quote() {
        assert!(
            normalize("%bf%27 OR 1=1--", false)
                .text
                .starts_with('\u{FFFD}')
        );
        assert!(normalize("%bf%27 OR 1=1--", false).text.contains('\''));
    }
}
