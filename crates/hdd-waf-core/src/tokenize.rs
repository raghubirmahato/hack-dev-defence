//! A small SQL tokenizer over the canonical (normalised) text.
//!
//! The detector families (C4.4 D1 to D3) work on token classes rather than on raw characters so that whitespace,
//! comment placement and encoding do not matter. The tokenizer is linear in the text length and panic-free.

/// The class of one token.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum TokenKind {
    /// A SQL-ish word (`union`, `select`, `username`, `@@version`, ...).
    Word,
    /// A number, hex literal or scientific-notation token (`1`, `0x27`, `1e0`).
    Number,
    /// A single quote, double quote or backtick character.
    Quote(char),
    /// An operator (`=`, `<>`, `||`, `&&`, ...).
    Op,
    /// Punctuation (`,`, `;`, `(`, `)`, `.`, `*`, ...).
    Punct,
    /// A comment starter: `--` and `#` and an unterminated `/*` run to the end of the value.
    Comment,
}

/// One token with its byte range in the source text.
#[derive(Debug, Clone, Copy)]
pub(crate) struct Token {
    pub(crate) kind: TokenKind,
    pub(crate) start: usize,
    pub(crate) end: usize,
}

impl Token {
    /// The source slice for this token.
    pub(crate) fn text<'a>(&self, source: &'a str) -> &'a str {
        source.get(self.start..self.end).unwrap_or("")
    }
}

fn two_char_op(bytes: &[u8], i: usize) -> Option<usize> {
    let a = bytes.get(i).copied()?;
    let b = bytes.get(i + 1).copied()?;
    let pair = (a, b);
    let known = matches!(
        pair,
        (b'<', b'=')
            | (b'>', b'=')
            | (b'<', b'>')
            | (b'!', b'=')
            | (b'=', b'=')
            | (b'|', b'|')
            | (b'&', b'&')
            | (b':', b':')
    );
    known.then_some(2)
}

fn char_len(first: u8) -> usize {
    match first {
        0x00..=0x7F => 1,
        0xC2..=0xDF => 2,
        0xE0..=0xEF => 3,
        0xF0..=0xF4 => 4,
        _ => 1,
    }
}

/// Tokenize the canonical text. `ops` counts the characters examined (test instrumentation for the linear bound).
pub(crate) fn tokenize(text: &str, ops: &mut u64) -> Vec<Token> {
    let bytes = text.as_bytes();
    let mut tokens: Vec<Token> = Vec::new();
    let mut i = 0usize;
    while let Some(&b) = bytes.get(i) {
        *ops = ops.saturating_add(1);
        if b.is_ascii_whitespace() {
            i += 1;
            continue;
        }
        let start = i;
        match b {
            b'\'' | b'"' | b'`' => {
                tokens.push(Token {
                    kind: TokenKind::Quote(b as char),
                    start,
                    end: i + 1,
                });
                i += 1;
            }
            b'-' if bytes.get(i + 1) == Some(&b'-') => {
                tokens.push(Token {
                    kind: TokenKind::Comment,
                    start,
                    end: bytes.len(),
                });
                i = bytes.len();
            }
            b'#' => {
                tokens.push(Token {
                    kind: TokenKind::Comment,
                    start,
                    end: bytes.len(),
                });
                i = bytes.len();
            }
            b'/' if bytes.get(i + 1) == Some(&b'*') => {
                tokens.push(Token {
                    kind: TokenKind::Comment,
                    start,
                    end: bytes.len(),
                });
                i = bytes.len();
            }
            b'@' | b'$' | b'_' | b'0'..=b'9' | b'a'..=b'z' | b'A'..=b'Z' => {
                let mut j = i + 1;
                while let Some(&c) = bytes.get(j) {
                    if c.is_ascii_alphanumeric() || matches!(c, b'_' | b'$' | b'@' | b'.') {
                        j += 1;
                    } else {
                        break;
                    }
                }
                let kind = if b.is_ascii_digit() {
                    TokenKind::Number
                } else {
                    TokenKind::Word
                };
                tokens.push(Token {
                    kind,
                    start,
                    end: j,
                });
                i = j;
            }
            b'<' | b'>' | b'!' | b'|' | b'&' | b'=' => {
                let len = two_char_op(bytes, i).unwrap_or(1);
                tokens.push(Token {
                    kind: TokenKind::Op,
                    start,
                    end: i + len,
                });
                i += len;
            }
            b'(' | b')' | b',' | b';' | b'.' | b'*' | b'+' | b'%' | b'~' | b'[' | b']' | b'{'
            | b'}' | b':' | b'/' | b'\\' | b'-' | b'^' | b'?' => {
                tokens.push(Token {
                    kind: TokenKind::Punct,
                    start,
                    end: i + 1,
                });
                i += 1;
            }
            _ => {
                let end = i + char_len(b);
                tokens.push(Token {
                    kind: TokenKind::Punct,
                    start,
                    end,
                });
                i = end;
            }
        }
    }
    tokens
}

#[cfg(test)]
mod tests {
    use super::*;

    fn kinds(text: &str) -> Vec<TokenKind> {
        let mut ops = 0u64;
        tokenize(text, &mut ops)
            .iter()
            .map(|token| token.kind)
            .collect()
    }

    #[test]
    fn tokenizes_a_quote_breakout_payload() {
        let mut ops = 0u64;
        let tokens = tokenize("admin' --", &mut ops);
        assert_eq!(tokens.len(), 3);
        assert_eq!(tokens.first().map(|t| t.kind), Some(TokenKind::Word));
        assert_eq!(tokens.get(1).map(|t| t.kind), Some(TokenKind::Quote('\'')));
        assert_eq!(tokens.get(2).map(|t| t.kind), Some(TokenKind::Comment));
    }

    #[test]
    fn tokenizes_tautology_and_union() {
        assert_eq!(
            kinds("' or 1=1--"),
            vec![
                TokenKind::Quote('\''),
                TokenKind::Word,
                TokenKind::Number,
                TokenKind::Op,
                TokenKind::Number,
                TokenKind::Comment
            ]
        );
        assert_eq!(
            kinds("1 union all select null"),
            vec![
                TokenKind::Number,
                TokenKind::Word,
                TokenKind::Word,
                TokenKind::Word,
                TokenKind::Word
            ]
        );
    }

    #[test]
    fn unterminated_comment_open_is_visible() {
        assert_eq!(
            kinds("admin'/*"),
            vec![TokenKind::Word, TokenKind::Quote('\''), TokenKind::Comment]
        );
    }
}
