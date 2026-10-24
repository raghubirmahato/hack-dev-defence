//! The C4.1 mandated payloads M1 to M6 must be a hard hit with category `sqli` in every vector and every field
//! kind, including case, whitespace, comment, percent-encoding and lookalike variants.
//!
//! The one documented exception is the password field: H2 (M3, M4, M5) is soft 4 under Balanced and hard under
//! Paranoid (C4.6 password row); H1 payloads (M1, M2, M6) stay hard there.

use hdd_waf_core::{
    Action, CustomRule, FieldKind, InspectInput, SiteSettings, Strictness, Vector, Verdict, inspect,
};

/// The six mandated payloads of C4.1.
const MANDATED: [&str; 6] = [
    "' OR 1=1--",
    "' OR '1'='1",
    "admin' --",
    "admin' #",
    "admin'/*",
    "' or 1=1 LIMIT 1 --",
];

/// The H2-only mandated payloads (M3, M4, M5), soft in password fields under Balanced.
const H2_ONLY: [&str; 3] = ["admin' --", "admin' #", "admin'/*"];

fn settings(strictness: Strictness) -> SiteSettings {
    SiteSettings {
        strictness,
        field_hints: Vec::new(),
        extra_rules: Vec::<CustomRule>::new(),
    }
}

fn percent_encode(text: &str) -> String {
    let mut out = String::new();
    for byte in text.as_bytes() {
        if byte.is_ascii_alphanumeric() || matches!(*byte, b'-' | b'.' | b'_' | b'~') {
            out.push(char::from(*byte));
        } else {
            out.push_str(&format!("%{byte:02X}"));
        }
    }
    out
}

fn inspect_value(
    payload: &str,
    vector: Vector,
    field_name: &str,
    strictness: Strictness,
) -> Verdict {
    let settings = settings(strictness);
    match vector {
        Vector::Query => {
            let query = format!("{field_name}={}", percent_encode(payload));
            let input = InspectInput {
                method: "GET",
                path: "/login",
                query: Some(&query),
                headers: &[],
                content_type: None,
                body: b"",
            };
            inspect(&input, &settings)
        }
        Vector::FormBody => {
            let body = format!("{field_name}={}", percent_encode(payload));
            let input = InspectInput {
                method: "POST",
                path: "/login",
                query: None,
                headers: &[],
                content_type: Some("application/x-www-form-urlencoded"),
                body: body.as_bytes(),
            };
            inspect(&input, &settings)
        }
        Vector::JsonBody => {
            let body = serde_json::json!({ field_name: payload }).to_string();
            let input = InspectInput {
                method: "POST",
                path: "/login",
                query: None,
                headers: &[],
                content_type: Some("application/json"),
                body: body.as_bytes(),
            };
            inspect(&input, &settings)
        }
        Vector::Path => {
            let path = format!("/login/{}", percent_encode(payload));
            let input = InspectInput {
                method: "GET",
                path: &path,
                query: None,
                headers: &[],
                content_type: None,
                body: b"",
            };
            inspect(&input, &settings)
        }
        Vector::Header => {
            let headers = vec![("User-Agent".to_owned(), payload.to_owned())];
            let input = InspectInput {
                method: "GET",
                path: "/login",
                query: None,
                headers: &headers,
                content_type: None,
                body: b"",
            };
            inspect(&input, &settings)
        }
        Vector::Cookie => {
            let headers = vec![(
                "Cookie".to_owned(),
                format!("{field_name}={}", percent_encode(payload)),
            )];
            let input = InspectInput {
                method: "GET",
                path: "/login",
                query: None,
                headers: &headers,
                content_type: None,
                body: b"",
            };
            inspect(&input, &settings)
        }
        Vector::MultipartField => {
            let body = format!(
                "--X\r\nContent-Disposition: form-data; name=\"{field_name}\"\r\n\r\n{payload}\r\n--X--\r\n"
            );
            let input = InspectInput {
                method: "POST",
                path: "/login",
                query: None,
                headers: &[],
                content_type: Some("multipart/form-data; boundary=X"),
                body: body.as_bytes(),
            };
            inspect(&input, &settings)
        }
        Vector::MultipartFilename => {
            let body = format!(
                "--X\r\nContent-Disposition: form-data; name=\"upload\"; filename=\"{payload}\"\r\n\r\ncontent\r\n--X--\r\n"
            );
            let input = InspectInput {
                method: "POST",
                path: "/login",
                query: None,
                headers: &[],
                content_type: Some("multipart/form-data; boundary=X"),
                body: body.as_bytes(),
            };
            inspect(&input, &settings)
        }
    }
}

/// Parameter vectors where the field name selects the field kind.
fn param_vectors() -> [Vector; 4] {
    [
        Vector::Query,
        Vector::FormBody,
        Vector::JsonBody,
        Vector::MultipartField,
    ]
}

fn assert_block(
    verdict: &Verdict,
    payload: &str,
    vector: Vector,
    field: &str,
    strictness: Strictness,
) {
    assert_eq!(
        verdict.action,
        Action::Block,
        "payload {payload:?} not blocked (vector {vector:?}, field {field}, strictness {strictness:?}): {verdict:?}"
    );
    assert_eq!(verdict.category, Some("sqli"), "payload {payload:?}");
    assert_eq!(verdict.vector, Some(vector), "payload {payload:?}");
    assert_eq!(verdict.field.as_deref(), Some(field), "payload {payload:?}");
}

#[test]
fn mandated_payloads_block_in_every_parameter_vector_and_field_kind() {
    let kinds = [
        ("username", FieldKind::Username),
        ("id", FieldKind::NumericId),
        ("q", FieldKind::Search),
        ("comment", FieldKind::FreeText),
        ("data", FieldKind::Unknown),
    ];
    for payload in MANDATED {
        for vector in param_vectors() {
            for (field, _kind) in kinds {
                let verdict = inspect_value(payload, vector, field, Strictness::Balanced);
                assert_block(&verdict, payload, vector, field, Strictness::Balanced);
            }
        }
    }
}

#[test]
fn mandated_payloads_block_in_the_path_header_cookie_and_filename_vectors() {
    for payload in MANDATED {
        for vector in [
            Vector::Path,
            Vector::Header,
            Vector::Cookie,
            Vector::MultipartFilename,
        ] {
            let verdict = inspect_value(payload, vector, "field", Strictness::Balanced);
            assert_eq!(
                verdict.action,
                Action::Block,
                "payload {payload:?} not blocked in vector {vector:?}: {verdict:?}"
            );
            assert_eq!(verdict.category, Some("sqli"), "payload {payload:?}");
        }
    }
}

#[test]
fn password_field_h1_payloads_stay_hard_and_h2_payloads_are_soft_under_balanced() {
    // C4.6 password row: H1 (with break-out), H3 to H6 hard; H2 soft 4 under Balanced and hard under Paranoid.
    for payload in ["' OR 1=1--", "' OR '1'='1", "' or 1=1 LIMIT 1 --"] {
        for vector in param_vectors() {
            let balanced = inspect_value(payload, vector, "password", Strictness::Balanced);
            assert_block(&balanced, payload, vector, "password", Strictness::Balanced);
            assert_eq!(
                balanced.field_kind,
                Some(FieldKind::Password),
                "payload {payload:?}"
            );
        }
    }
    for payload in H2_ONLY {
        for vector in param_vectors() {
            let balanced = inspect_value(payload, vector, "password", Strictness::Balanced);
            assert_eq!(
                balanced.action,
                Action::Allow,
                "documented password exception: {payload:?} in {vector:?} must be soft under Balanced: {balanced:?}"
            );
            let paranoid = inspect_value(payload, vector, "password", Strictness::Paranoid);
            assert_eq!(
                paranoid.action,
                Action::Block,
                "Paranoid must make H2 hard in a password field: {payload:?} in {vector:?}"
            );
        }
    }
}

#[test]
fn case_whitespace_comment_and_encoding_variants_block_in_every_vector() {
    let variants = [
        "' oR 1=1--",
        "'\tOR\t1=1--",
        "'  OR  1  =  1  --",
        "'/**/OR/**/1=1--",
        "' OR 1=1-- -",
        "' OR 1=1#",
        "' OR 1=1/*",
        "%27%20OR%201%3D1--",
        "%2527%2520OR%25201%253D1--",
        "%u0027%20OR%201=1--",
        "&#39; OR 1=1--",
        "\\u0027 OR 1=1--",
        "\u{FF07} OR \u{FF11}\u{FF1D}\u{FF11}--",
        "\u{2019} OR 1=1--",
        "%bf%27 OR 1=1--",
        "ADMIN' --",
        "admin'%23",
        "admin'%2F*",
        "admin'%20--",
        "admin'/*",
        "admin' -- -",
    ];
    for payload in variants {
        for vector in [
            Vector::Query,
            Vector::FormBody,
            Vector::JsonBody,
            Vector::Header,
            Vector::Cookie,
        ] {
            let verdict = inspect_value(payload, vector, "username", Strictness::Balanced);
            assert_eq!(
                verdict.action,
                Action::Block,
                "variant {payload:?} not blocked in {vector:?}: {verdict:?}"
            );
            assert_eq!(verdict.category, Some("sqli"), "variant {payload:?}");
        }
    }
}
