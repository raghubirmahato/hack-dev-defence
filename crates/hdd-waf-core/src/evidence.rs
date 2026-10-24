//! Evidence extraction and redaction (C4.12, R-25): at most [`MAX_EVIDENCE_BYTES`] bytes of the value as the
//! attacker sent it, around the span that matched, with digit runs and token-like secrets redacted.

use crate::normalize::Normalized;
use crate::types::MAX_EVIDENCE_BYTES;

/// Redact and cut one policy value (used by the request-level policy blocks that have no normalised span).
pub(crate) fn redact(raw: &str) -> String {
    cut_to(&sanitize(raw), MAX_EVIDENCE_BYTES)
}

/// A short, redacted evidence window from `raw` around the normalised match at `normalized_char`.
pub(crate) fn from_value(norm: &Normalized, raw: &str, normalized_char: usize) -> String {
    let offset = norm
        .map
        .get(normalized_char)
        .copied()
        .unwrap_or(0)
        .min(raw.len() as u32) as usize;
    let mut start = offset.saturating_sub(32);
    while start > 0 && !raw.is_char_boundary(start) {
        start = start.saturating_sub(1);
    }
    let mut end = start.saturating_add(MAX_EVIDENCE_BYTES).min(raw.len());
    while end > start && !raw.is_char_boundary(end) {
        end = end.saturating_sub(1);
    }
    let window = raw.get(start..end).unwrap_or("");
    let cleaned = sanitize(window);
    cut_to(&cleaned, MAX_EVIDENCE_BYTES)
}

/// Replace controls with spaces, redact long digit runs and token-looking secrets.
fn sanitize(text: &str) -> String {
    let chars: Vec<char> = text.chars().collect();
    let mut out = String::with_capacity(text.len());
    let mut i = 0usize;
    while let Some(&c) = chars.get(i) {
        if c.is_ascii_digit() {
            let mut j = i;
            while chars.get(j).map(|d| d.is_ascii_digit()).unwrap_or(false) {
                j = j.saturating_add(1);
            }
            if j.saturating_sub(i) >= 7 {
                out.push_str("<digits>");
            } else {
                for k in i..j {
                    if let Some(d) = chars.get(k) {
                        out.push(*d);
                    }
                }
            }
            i = j;
            continue;
        }
        out.push(if c.is_control() { ' ' } else { c });
        i = i.saturating_add(1);
    }
    redact_tokens(&out)
}

fn token_char(c: char) -> bool {
    c.is_ascii_alphanumeric() || matches!(c, '_' | '-' | '+' | '/' | '=' | '.')
}

fn redact_tokens(text: &str) -> String {
    let chars: Vec<char> = text.chars().collect();
    let mut out = String::with_capacity(text.len());
    let mut i = 0usize;
    while let Some(&c) = chars.get(i) {
        if !token_char(c) {
            out.push(c);
            i = i.saturating_add(1);
            continue;
        }
        let mut j = i;
        while chars.get(j).map(|d| token_char(*d)).unwrap_or(false) {
            j = j.saturating_add(1);
        }
        let run: Vec<char> = chars.get(i..j).unwrap_or(&[]).to_vec();
        if token_run_is_secret(&run) {
            out.push_str("<token>");
        } else {
            out.extend(run.iter());
        }
        i = j;
    }
    out
}

fn token_run_is_secret(run: &[char]) -> bool {
    if run.len() < 24 {
        return false;
    }
    let has_digit = run.iter().any(char::is_ascii_digit);
    let has_lower = run.iter().any(char::is_ascii_lowercase);
    let has_upper = run.iter().any(char::is_ascii_uppercase);
    has_digit && has_lower && has_upper
}

/// Cut a string to at most `max` bytes on a character boundary.
fn cut_to(text: &str, max: usize) -> String {
    if text.len() <= max {
        return text.to_owned();
    }
    let mut end = max;
    while end > 0 && !text.is_char_boundary(end) {
        end = end.saturating_sub(1);
    }
    text.get(..end).unwrap_or("").to_owned()
}

#[cfg(test)]
mod tests {
    use super::super::normalize::normalize;
    use super::*;

    fn char_of_byte(norm: &Normalized, byte_index: usize) -> usize {
        norm.text
            .get(..byte_index)
            .map(|head| head.chars().count())
            .unwrap_or(0)
    }

    #[test]
    fn evidence_is_at_most_128_bytes_and_utf8() {
        let raw = format!("x{}' or 1=1--", "é".repeat(400));
        let norm = normalize(&raw, false);
        let byte = norm.text.find("or 1=1").unwrap_or(0);
        let evidence = from_value(&norm, &raw, char_of_byte(&norm, byte));
        assert!(evidence.len() <= MAX_EVIDENCE_BYTES);
        assert!(evidence.is_char_boundary(evidence.len()));
        assert!(!evidence.is_empty());
    }

    #[test]
    fn evidence_redacts_long_digit_runs() {
        let raw = "card 4111111111111111 ' or 1=1--";
        let norm = normalize(raw, false);
        let byte = norm.text.find("or 1=1").unwrap_or(0);
        let evidence = from_value(&norm, raw, char_of_byte(&norm, byte));
        assert!(evidence.contains("<digits>"), "got {evidence}");
        assert!(!evidence.contains("4111111111111111"));
    }

    #[test]
    fn evidence_keeps_the_attack_shape_visible() {
        let raw = "admin' --";
        let norm = normalize(raw, false);
        let byte = norm.text.find("--").unwrap_or(0);
        assert_eq!(
            from_value(&norm, raw, char_of_byte(&norm, byte)),
            "admin' --"
        );
    }
}
