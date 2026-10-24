//! Field-kind inference (C4.6): from the parameter name and the request vector to the [`FieldKind`] the policy uses.
//!
//! The operator can override the heuristic with `SiteSettings::field_hints`; the first hint whose name matches wins.

use crate::types::{FieldKind, Vector};

/// Infer the field kind for one extracted value.
pub(crate) fn infer(field: &str, vector: Vector, hints: &[(String, FieldKind)]) -> FieldKind {
    if let Some(kind) = hint_for(field, hints) {
        return kind;
    }
    match vector {
        Vector::Header => return FieldKind::Header,
        Vector::Cookie => return FieldKind::Cookie,
        Vector::MultipartFilename => return FieldKind::Filename,
        _ => {}
    }
    classify_name(field)
}

fn hint_for(field: &str, hints: &[(String, FieldKind)]) -> Option<FieldKind> {
    let lower = field.to_ascii_lowercase();
    let last = lower.rsplit('.').next().unwrap_or(&lower).to_owned();
    for (name, kind) in hints {
        let hint = name.trim().to_ascii_lowercase();
        if hint.is_empty() {
            continue;
        }
        if lower == hint || last == hint {
            return Some(*kind);
        }
        let hinted_tokens: Vec<&str> = hint.split(|c: char| !c.is_ascii_alphanumeric()).collect();
        if hinted_tokens
            .iter()
            .any(|t| !t.is_empty() && tokens(&last).contains(t))
        {
            return Some(*kind);
        }
    }
    None
}

fn tokens(name: &str) -> Vec<&str> {
    name.split(|c: char| !c.is_ascii_alphanumeric())
        .filter(|part| !part.is_empty())
        .collect()
}

fn classify_name(field: &str) -> FieldKind {
    let lower = field.trim().to_ascii_lowercase();
    let last = lower.rsplit('.').next().unwrap_or(&lower).to_owned();
    let parts = tokens(&last);

    if parts.iter().any(|t| {
        matches!(
            *t,
            "pass" | "passwd" | "pwd" | "password" | "passphrase" | "secret" | "pin"
        )
    }) {
        return FieldKind::Password;
    }
    if last.ends_with("_id") || last.ends_with("-id") || parts.contains(&"id") {
        return FieldKind::NumericId;
    }
    if parts.iter().any(|t| {
        matches!(
            *t,
            "uid"
                | "pid"
                | "page"
                | "limit"
                | "offset"
                | "num"
                | "qty"
                | "count"
                | "amount"
                | "total"
        )
    }) {
        return FieldKind::NumericId;
    }
    if parts.iter().any(|t| {
        matches!(
            *t,
            "q" | "s" | "search" | "query" | "keyword" | "term" | "filter" | "pattern" | "find"
        )
    }) {
        return FieldKind::Search;
    }
    if parts.iter().any(|t| {
        matches!(
            *t,
            "comment"
                | "message"
                | "body"
                | "description"
                | "desc"
                | "bio"
                | "note"
                | "text"
                | "content"
        )
    }) {
        return FieldKind::FreeText;
    }
    if parts.iter().any(|t| {
        matches!(
            *t,
            "user"
                | "username"
                | "login"
                | "uname"
                | "email"
                | "mail"
                | "account"
                | "userid"
                | "loginname"
        )
    }) {
        return FieldKind::Username;
    }
    if parts.iter().any(|t| *t == "file" || *t == "filename") {
        return FieldKind::Filename;
    }
    FieldKind::Unknown
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hints_win_over_the_heuristic() {
        let hints = vec![("q".to_owned(), FieldKind::NumericId)];
        assert_eq!(infer("q", Vector::Query, &hints), FieldKind::NumericId);
        assert_eq!(infer("q", Vector::Query, &[]), FieldKind::Search);
    }

    #[test]
    fn common_names_are_classified() {
        assert_eq!(
            infer("password", Vector::FormBody, &[]),
            FieldKind::Password
        );
        assert_eq!(
            infer("new_password", Vector::FormBody, &[]),
            FieldKind::Password
        );
        assert_eq!(
            infer("username", Vector::FormBody, &[]),
            FieldKind::Username
        );
        assert_eq!(infer("email", Vector::FormBody, &[]), FieldKind::Username);
        assert_eq!(infer("user_id", Vector::Query, &[]), FieldKind::NumericId);
        assert_eq!(infer("page", Vector::Query, &[]), FieldKind::NumericId);
        assert_eq!(infer("id", Vector::Query, &[]), FieldKind::NumericId);
        assert_eq!(infer("q", Vector::Query, &[]), FieldKind::Search);
        assert_eq!(infer("comment", Vector::FormBody, &[]), FieldKind::FreeText);
        assert_eq!(
            infer("anything", Vector::Header, &[]),
            FieldKind::Header,
            "a header value is header kind"
        );
        assert_eq!(
            infer("anything", Vector::MultipartFilename, &[]),
            FieldKind::Filename
        );
        assert_eq!(infer("token", Vector::Query, &[]), FieldKind::Unknown);
    }
}
