//! Request-vector extraction (C4.2 surfaces used by the HK1 demo track): path segments, query pairs, form-urlencoded
//! bodies, JSON strings, multipart fields and filenames, selected headers and cookies.
//!
//! The extractor is bounded: at most [`INSPECT_BODY_CAP`] body bytes and [`MAX_VALUES`] values; hitting either bound
//! sets [`Extraction::truncated`] so the verdict can say so (never a silent pass).
//!
//! JSON is parsed by the small bounded parser in this module: `serde_json` is only a dev-dependency of this crate
//! (the detector itself takes no serialisation dependency).

use std::collections::{HashMap, HashSet};

use crate::types::{INSPECT_BODY_CAP, InspectInput, Vector};

/// The maximum number of values one request may contribute. Reaching it sets
/// [`Extraction::truncated`] and [`Extraction::limit_exceeded`]: the detector then blocks with the policy
/// `truncated` verdict, never fails open (R-26, review R1-1).
const MAX_VALUES: usize = 4096;

/// The maximum number of body/query pairs the duplicate-name grouping collects (review R1-3: bound the map work).
const MAX_PAIRS: usize = 4096;

/// The maximum nesting depth traversed in a JSON body; a deeper document falls back to whole-body inspection.
const MAX_JSON_DEPTH: usize = 32;

/// The maximum length of one header value that is inspected (review round 1 LOW: inspect every header, capped).
const MAX_HEADER_VALUE_BYTES: usize = 8 * 1024;

/// One value to inspect: where it came from and what it is.
#[derive(Debug, Clone)]
pub(crate) struct Value {
    pub(crate) vector: Vector,
    pub(crate) field: String,
    pub(crate) text: String,
    pub(crate) plus_as_space: bool,
}

/// Everything the detector should inspect for one request.
#[derive(Debug, Default)]
pub(crate) struct Extraction {
    pub(crate) values: Vec<Value>,
    /// The body was longer than the inspection cap, or the value cap was hit.
    pub(crate) truncated: bool,
    /// The value cap ([`MAX_VALUES`]) was hit: the detector must block rather than silently pass.
    pub(crate) limit_exceeded: bool,
    /// A multipart Content-Type declared a boundary the body does not contain (review round 1 LOW).
    pub(crate) boundary_mismatch: bool,
}

impl Extraction {
    fn push(
        &mut self,
        vector: Vector,
        field: impl Into<String>,
        text: impl Into<String>,
        plus_as_space: bool,
    ) {
        if self.values.len() >= MAX_VALUES {
            self.truncated = true;
            self.limit_exceeded = true;
            return;
        }
        self.values.push(Value {
            vector,
            field: field.into(),
            text: text.into(),
            plus_as_space,
        });
    }

    fn mark_limit(&mut self) {
        self.truncated = true;
        self.limit_exceeded = true;
    }
}

/// Extract every inspectable value from the request.
pub(crate) fn extract(input: &InspectInput<'_>) -> Extraction {
    let mut extraction = Extraction::default();
    let body_bytes = input.body.get(..INSPECT_BODY_CAP).unwrap_or(input.body);
    if input.body.len() > INSPECT_BODY_CAP {
        extraction.truncated = true;
    }
    let body = String::from_utf8_lossy(body_bytes).into_owned();
    let content_type_raw = input.content_type.unwrap_or("");
    let content_type = content_type_raw.to_ascii_lowercase();

    add_path(&mut extraction, input.path);
    if let Some(query) = input.query {
        add_urlencoded(&mut extraction, query, Vector::Query);
    }
    if !body.is_empty() {
        let trimmed = body.trim_start();
        let looks_json = trimmed.starts_with('{') || trimmed.starts_with('[');
        if content_type.contains("multipart/form-data") {
            add_multipart(&mut extraction, &body, content_type_raw);
        } else if content_type.contains("application/x-www-form-urlencoded") {
            add_urlencoded(&mut extraction, &body, Vector::FormBody);
            if looks_json {
                add_json(&mut extraction, &body);
            }
        } else if content_type.contains("json") || looks_json {
            add_json(&mut extraction, &body);
        } else {
            // An unknown or binary content type: the raw body is still inspected as one value so an attack cannot
            // hide behind a missing or confusable Content-Type (C4.8.11).
            extraction.push(Vector::FormBody, "body", body.clone(), false);
        }
    }
    add_headers(&mut extraction, input.headers);
    extraction
}

fn add_path(extraction: &mut Extraction, path: &str) {
    for (index, segment) in path.split('/').enumerate() {
        if segment.is_empty() {
            continue;
        }
        let field = format!("path[{index}]");
        extraction.push(Vector::Path, field.clone(), segment.to_owned(), false);
        if segment.contains(';') {
            for matrix in segment.split(';') {
                if matrix.is_empty() || matrix == segment {
                    continue;
                }
                extraction.push(Vector::Path, field.clone(), matrix.to_owned(), false);
            }
        }
    }
}

fn add_urlencoded(extraction: &mut Extraction, encoded: &str, vector: Vector) {
    // Review R1-1: a repeated parameter name is inspected once (not once per occurrence), so a legitimate form with
    // many repeated array parameters does not trip the value cap; values are still all inspected.
    let mut seen_names: HashSet<String> = HashSet::new();
    // Review R1-3: HashMap lookup, bounded pair collection and insertion order kept separately (no O(n^2) scan).
    let mut combined: HashMap<String, Vec<String>> = HashMap::new();
    let mut combined_order: Vec<String> = Vec::new();
    let mut pairs = 0usize;
    for pair in encoded.split('&') {
        if pair.is_empty() {
            continue;
        }
        if pairs >= MAX_PAIRS {
            extraction.mark_limit();
            break;
        }
        pairs += 1;
        match pair.split_once('=') {
            Some((name, value)) => {
                if !name.is_empty() && seen_names.insert(name.to_owned()) {
                    extraction.push(vector, name.to_owned(), name.to_owned(), true);
                }
                extraction.push(vector, name.to_owned(), value.to_owned(), true);
                match combined.get_mut(name) {
                    Some(values) => values.push(value.to_owned()),
                    None => {
                        combined.insert(name.to_owned(), vec![value.to_owned()]);
                        combined_order.push(name.to_owned());
                    }
                }
            }
            None => {
                if seen_names.insert("parameter".to_owned()) {
                    extraction.push(vector, "parameter".to_owned(), "parameter".to_owned(), true);
                }
                extraction.push(vector, "parameter".to_owned(), pair.to_owned(), true);
                match combined.get_mut("parameter") {
                    Some(values) => values.push(pair.to_owned()),
                    None => {
                        combined.insert("parameter".to_owned(), vec![pair.to_owned()]);
                        combined_order.push("parameter".to_owned());
                    }
                }
            }
        }
    }
    // Duplicate and array parameters are also inspected concatenated, so a payload split across `a[0]`/`a[1]` or two
    // duplicate `a=` pairs is still seen as one shape (C4.8.10).
    for name in combined_order {
        let Some(values) = combined.remove(&name) else {
            continue;
        };
        if values.len() > 1 {
            extraction.push(vector, name, values.join(" "), true);
        }
    }
}

/// One parsed JSON value: the string leaves, numbers and booleans are inspected.
#[derive(Debug)]
enum JsonValue {
    Null,
    Bool(bool),
    Number(String),
    String(String),
    Array(Vec<JsonValue>),
    Object(Vec<(String, JsonValue)>),
}

struct JsonParser {
    chars: Vec<char>,
    position: usize,
}

impl JsonParser {
    fn new(body: &str) -> Self {
        Self {
            chars: body.chars().collect(),
            position: 0,
        }
    }

    fn peek(&self) -> Option<char> {
        self.chars.get(self.position).copied()
    }

    fn bump(&mut self) -> Option<char> {
        let next = self.peek();
        if next.is_some() {
            self.position += 1;
        }
        next
    }

    fn skip_whitespace(&mut self) {
        while self
            .peek()
            .map(|c| c.is_ascii_whitespace())
            .unwrap_or(false)
        {
            self.position += 1;
        }
    }

    fn parse_document(&mut self) -> Option<JsonValue> {
        self.skip_whitespace();
        let value = self.parse_value(0)?;
        self.skip_whitespace();
        (self.position == self.chars.len()).then_some(value)
    }

    fn parse_value(&mut self, depth: usize) -> Option<JsonValue> {
        if depth > MAX_JSON_DEPTH {
            return None;
        }
        self.skip_whitespace();
        match self.peek()? {
            '{' => self.parse_object(depth),
            '[' => self.parse_array(depth),
            '"' => Some(JsonValue::String(self.parse_string()?)),
            't' => {
                self.expect_word("true")?;
                Some(JsonValue::Bool(true))
            }
            'f' => {
                self.expect_word("false")?;
                Some(JsonValue::Bool(false))
            }
            'n' => {
                self.expect_word("null")?;
                Some(JsonValue::Null)
            }
            c if c == '-' || c.is_ascii_digit() => Some(JsonValue::Number(self.parse_number())),
            _ => None,
        }
    }

    fn expect_word(&mut self, wanted: &str) -> Option<()> {
        for expected in wanted.chars() {
            if self.bump()? != expected {
                return None;
            }
        }
        Some(())
    }

    fn parse_string(&mut self) -> Option<String> {
        if self.bump()? != '"' {
            return None;
        }
        let mut out = String::new();
        loop {
            match self.bump()? {
                '"' => return Some(out),
                '\\' => {
                    let escaped = self.bump()?;
                    out.push('\\');
                    out.push(escaped);
                }
                c => out.push(c),
            }
        }
    }

    fn parse_number(&mut self) -> String {
        let mut out = String::new();
        while let Some(c) = self.peek() {
            if c.is_ascii_digit() || matches!(c, '+' | '-' | '.' | 'e' | 'E') {
                out.push(c);
                self.position += 1;
            } else {
                break;
            }
        }
        out
    }

    fn parse_array(&mut self, depth: usize) -> Option<JsonValue> {
        self.bump();
        let mut items: Vec<JsonValue> = Vec::new();
        self.skip_whitespace();
        if self.peek() == Some(']') {
            self.position += 1;
            return Some(JsonValue::Array(items));
        }
        loop {
            items.push(self.parse_value(depth + 1)?);
            self.skip_whitespace();
            match self.bump()? {
                ',' => self.skip_whitespace(),
                ']' => return Some(JsonValue::Array(items)),
                _ => return None,
            }
        }
    }

    fn parse_object(&mut self, depth: usize) -> Option<JsonValue> {
        self.bump();
        let mut members: Vec<(String, JsonValue)> = Vec::new();
        self.skip_whitespace();
        if self.peek() == Some('}') {
            self.position += 1;
            return Some(JsonValue::Object(members));
        }
        loop {
            let key = self.parse_string()?;
            self.skip_whitespace();
            if self.bump()? != ':' {
                return None;
            }
            let value = self.parse_value(depth + 1)?;
            members.push((key, value));
            self.skip_whitespace();
            match self.bump()? {
                ',' => self.skip_whitespace(),
                '}' => return Some(JsonValue::Object(members)),
                _ => return None,
            }
        }
    }
}

fn add_json(extraction: &mut Extraction, body: &str) {
    let mut parser = JsonParser::new(body);
    let Some(parsed) = parser.parse_document() else {
        // A malformed or over-deep JSON body is still attack-shaped; inspect the raw text rather than dropping it.
        extraction.push(Vector::JsonBody, "json", body.to_owned(), false);
        return;
    };
    let mut stack: Vec<(&JsonValue, String, usize)> = vec![(&parsed, String::new(), 0)];
    while let Some((value, path, depth)) = stack.pop() {
        match value {
            JsonValue::String(text) => {
                extraction.push(Vector::JsonBody, capped_path(&path), text.clone(), false)
            }
            JsonValue::Number(number) => {
                extraction.push(Vector::JsonBody, capped_path(&path), number.clone(), false)
            }
            JsonValue::Bool(flag) => extraction.push(
                Vector::JsonBody,
                capped_path(&path),
                flag.to_string(),
                false,
            ),
            JsonValue::Null => {}
            JsonValue::Array(items) => {
                let mut scalars: Vec<String> = Vec::new();
                for (index, item) in items.iter().enumerate().rev() {
                    let child = format!("{path}[{index}]");
                    match item {
                        JsonValue::String(text) => scalars.push(text.clone()),
                        JsonValue::Number(number) => scalars.push(number.clone()),
                        JsonValue::Bool(flag) => scalars.push(flag.to_string()),
                        _ => {}
                    }
                    if depth < MAX_JSON_DEPTH {
                        stack.push((item, child, depth + 1));
                    }
                }
                if scalars.len() > 1 {
                    scalars.reverse();
                    extraction.push(
                        Vector::JsonBody,
                        capped_path(&path),
                        scalars.join(" "),
                        false,
                    );
                }
            }
            JsonValue::Object(members) => {
                for (key, member) in members {
                    let child = if path.is_empty() {
                        key.clone()
                    } else {
                        format!("{path}.{key}")
                    };
                    // Review round 1 LOW: object keys are inspected too (a payload can arrive in a key name).
                    extraction.push(Vector::JsonBody, capped_path(&child), key.clone(), false);
                    if depth < MAX_JSON_DEPTH {
                        stack.push((member, child, depth + 1));
                    }
                }
            }
        }
    }
}

fn capped_path(path: &str) -> String {
    if path.len() <= 256 {
        return path.to_owned();
    }
    let mut end = 256;
    while end > 0 && !path.is_char_boundary(end) {
        end -= 1;
    }
    path.get(..end).unwrap_or("").to_owned()
}

fn cap_header_value(value: &str) -> &str {
    if value.len() <= MAX_HEADER_VALUE_BYTES {
        return value;
    }
    let mut end = MAX_HEADER_VALUE_BYTES;
    while end > 0 && !value.is_char_boundary(end) {
        end -= 1;
    }
    value.get(..end).unwrap_or("")
}

fn add_headers(extraction: &mut Extraction, headers: &[(String, String)]) {
    for (name, value) in headers {
        let lower = name.trim().to_ascii_lowercase();
        if lower == "cookie" {
            add_cookies(extraction, value);
            continue;
        }
        // Review round 1 LOW: every header value is inspected with the header vector (not only the documented safe
        // list), capped at 8 KiB so one huge header cannot dominate the inspection.
        let capped = cap_header_value(value);
        if !capped.is_empty() {
            extraction.push(Vector::Header, name.clone(), capped.to_owned(), false);
        }
        if lower == "x-forwarded-for" {
            for hop in value.split(',') {
                extraction.push(Vector::Header, name.clone(), hop.trim().to_owned(), false);
            }
        }
    }
}

fn add_cookies(extraction: &mut Extraction, header: &str) {
    for cookie in header.split(';') {
        let cookie = cookie.trim();
        if cookie.is_empty() {
            continue;
        }
        match cookie.split_once('=') {
            Some((name, value)) => {
                extraction.push(
                    Vector::Cookie,
                    name.trim().to_owned(),
                    name.trim().to_owned(),
                    false,
                );
                extraction.push(
                    Vector::Cookie,
                    name.trim().to_owned(),
                    value.trim().to_owned(),
                    false,
                );
            }
            None => extraction.push(
                Vector::Cookie,
                "cookie".to_owned(),
                cookie.to_owned(),
                false,
            ),
        }
    }
}

fn add_multipart(extraction: &mut Extraction, body: &str, content_type: &str) {
    let boundary = match boundary_of(content_type) {
        Some(boundary) if !boundary.is_empty() => boundary,
        _ => {
            extraction.push(Vector::FormBody, "body", body.to_owned(), false);
            return;
        }
    };
    let delimiter = format!("--{boundary}");
    if !body.contains(&delimiter) {
        // Review round 1 LOW: the Content-Type declares a boundary the body does not contain. That is a parser
        // differential, not a form; refuse it as policy and still inspect the raw body.
        extraction.boundary_mismatch = true;
        extraction.push(Vector::FormBody, "body", body.to_owned(), false);
        return;
    }
    let mut saw_part = false;
    for part in body.split(&delimiter).skip(1) {
        let part = part.trim_start_matches("\r\n").trim_start_matches('\n');
        if part.starts_with("--") {
            break;
        }
        saw_part = true;
        let (header_block, content) = match part.split_once("\r\n\r\n") {
            Some((headers, content)) => (headers, content),
            None => match part.split_once("\n\n") {
                Some((headers, content)) => (headers, content),
                None => ("", part),
            },
        };
        let mut name: Option<String> = None;
        let mut filename: Option<String> = None;
        for line in header_block.lines() {
            let Some((header_name, header_value)) = line.split_once(':') else {
                continue;
            };
            if header_name
                .trim()
                .eq_ignore_ascii_case("content-disposition")
            {
                name = disposition_param(header_value, "name");
                filename = disposition_param(header_value, "filename")
                    .or_else(|| disposition_param_star(header_value));
            }
        }
        let field = name.unwrap_or_else(|| "part".to_owned());
        let content = content.trim_end_matches(['\r', '\n']);
        if let Some(filename) = filename {
            extraction.push(Vector::MultipartFilename, field.clone(), filename, false);
        }
        if !content.is_empty() {
            extraction.push(Vector::MultipartField, field, content.to_owned(), false);
        }
    }
    if !saw_part {
        extraction.push(Vector::FormBody, "body", body.to_owned(), false);
    }
}

fn boundary_of(content_type: &str) -> Option<String> {
    // Search case-insensitively but slice the original value: the boundary parameter is case-sensitive.
    let lower = content_type.to_ascii_lowercase();
    let index = lower.find("boundary=")?;
    let rest = content_type.get(index + "boundary=".len()..)?;
    let raw = rest.split(';').next().unwrap_or(rest).trim();
    let unquoted = raw.trim_matches('"');
    Some(unquoted.to_owned())
}

fn disposition_param(header_value: &str, wanted: &str) -> Option<String> {
    let lower = header_value.to_ascii_lowercase();
    let needle = format!("{wanted}=");
    let mut search_from = 0usize;
    while let Some(found) = lower.get(search_from..).and_then(|rest| rest.find(&needle)) {
        let value_start = search_from + found + needle.len();
        let previous = lower
            .get(search_from..value_start.saturating_sub(needle.len()))
            .and_then(|head| head.chars().next_back());
        let boundary_ok = previous
            .map(|c| !(c.is_ascii_alphanumeric() || c == '_' || c == '-'))
            .unwrap_or(true);
        if boundary_ok {
            let tail = header_value.get(value_start..)?;
            let value = if let Some(quoted) = tail.strip_prefix('"') {
                quoted.find('"').and_then(|end| quoted.get(..end))
            } else {
                tail.split(';').next()
            }?;
            return Some(value.trim().to_owned());
        }
        search_from = value_start;
    }
    None
}

/// Parse an RFC 5987 `filename*=` parameter: returns the percent-encoded value after the `charset''` prefix, so the
/// normaliser decodes it with the rest of the extracted values.
fn disposition_param_star(header_value: &str) -> Option<String> {
    let lower = header_value.to_ascii_lowercase();
    let index = lower.find("filename*=")?;
    let tail = header_value.get(index + "filename*=".len()..)?;
    let value = tail
        .split(';')
        .next()
        .unwrap_or(tail)
        .trim()
        .trim_matches('"');
    let encoded = match value.split_once("''") {
        Some((_charset, encoded)) => encoded,
        None => value,
    };
    (!encoded.is_empty()).then(|| encoded.to_owned())
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

    fn texts(extraction: &Extraction, vector: Vector) -> Vec<String> {
        extraction
            .values
            .iter()
            .filter(|value| value.vector == vector)
            .map(|value| value.text.clone())
            .collect()
    }

    #[test]
    fn extracts_path_segments_query_pairs_and_form_values() {
        let owned = headers(&[]);
        let input = InspectInput {
            method: "POST",
            path: "/item/1%27or%271%27%3D%271/login",
            query: Some("q=union&page=2"),
            headers: &owned,
            content_type: Some("application/x-www-form-urlencoded"),
            body: b"user=admin&pass=x",
        };
        let extraction = extract(&input);
        let path = texts(&extraction, Vector::Path);
        assert!(path.iter().any(|text| text == "1%27or%271%27%3D%271"));
        let query = texts(&extraction, Vector::Query);
        assert!(query.iter().any(|text| text == "union"));
        assert!(query.iter().any(|text| text == "q"));
        let form = texts(&extraction, Vector::FormBody);
        assert!(form.iter().any(|text| text == "admin"));
        assert!(form.iter().any(|text| text == "pass"));
    }

    #[test]
    fn extracts_json_strings_numbers_and_arrays() {
        let owned = headers(&[]);
        let body = br#"{"user":"admin'--","id":1,"roles":["x'"," or 1=1--"]}"#;
        let input = InspectInput {
            method: "POST",
            path: "/login",
            query: None,
            headers: &owned,
            content_type: Some("application/json"),
            body,
        };
        let extraction = extract(&input);
        let json = texts(&extraction, Vector::JsonBody);
        assert!(json.iter().any(|text| text == "admin'--"), "{json:?}");
        assert!(json.iter().any(|text| text == "1"));
        assert!(
            json.iter().any(|text| text.contains("or 1=1--")),
            "{json:?}"
        );
    }

    #[test]
    fn malformed_json_falls_back_to_the_raw_body() {
        let owned = headers(&[]);
        let input = InspectInput {
            method: "POST",
            path: "/login",
            query: None,
            headers: &owned,
            content_type: Some("application/json"),
            body: br#"{"user":"admin'--" "#,
        };
        let extraction = extract(&input);
        let json = texts(&extraction, Vector::JsonBody);
        assert!(
            json.iter().any(|text| text.contains("admin'--")),
            "{json:?}"
        );
    }

    #[test]
    fn extracts_multipart_fields_and_filenames() {
        let owned = headers(&[]);
        let body = b"--X\r\nContent-Disposition: form-data; name=\"user\"\r\n\r\nadmin' --\r\n--X\r\nContent-Disposition: form-data; name=\"f\"; filename=\"a'b.txt\"\r\n\r\ncontent\r\n--X--\r\n";
        let input = InspectInput {
            method: "POST",
            path: "/upload",
            query: None,
            headers: &owned,
            content_type: Some("multipart/form-data; boundary=X"),
            body,
        };
        let extraction = extract(&input);
        let fields = texts(&extraction, Vector::MultipartField);
        assert!(fields.iter().any(|text| text == "admin' --"), "{fields:?}");
        let names = texts(&extraction, Vector::MultipartFilename);
        assert_eq!(names, vec!["a'b.txt".to_owned()]);
    }

    #[test]
    fn extracts_selected_headers_and_cookies() {
        let owned = headers(&[
            ("User-Agent", "' or 1=1--"),
            ("Referer", "https://example.com/"),
            ("X-Forwarded-For", "1.2.3.4, ' or 1=1--"),
            ("Cookie", "session=abc; q=' or 1=1--"),
            ("Accept-Language", "en"),
        ]);
        let input = InspectInput {
            method: "GET",
            path: "/",
            query: None,
            headers: &owned,
            content_type: None,
            body: b"",
        };
        let extraction = extract(&input);
        let header_texts = texts(&extraction, Vector::Header);
        assert!(header_texts.iter().any(|text| text == "' or 1=1--"));
        // Every header value is inspected (review round 1 LOW), and X-Forwarded-For is additionally inspected hop by
        // hop, so the address appears in the whole-header value and in the reported hop value.
        assert_eq!(
            header_texts
                .iter()
                .filter(|text| text.contains("1.2.3.4"))
                .count(),
            2
        );
        assert!(header_texts.iter().any(|text| text == "1.2.3.4"));
        let cookie_texts = texts(&extraction, Vector::Cookie);
        assert!(cookie_texts.iter().any(|text| text == "' or 1=1--"));
        assert!(cookie_texts.iter().any(|text| text == "session"));
    }

    #[test]
    fn body_over_the_cap_is_marked_truncated_and_cut() {
        let owned = headers(&[]);
        let body = vec![b'a'; INSPECT_BODY_CAP + 10];
        let input = InspectInput {
            method: "POST",
            path: "/",
            query: None,
            headers: &owned,
            content_type: Some("text/plain"),
            body: &body,
        };
        let extraction = extract(&input);
        assert!(extraction.truncated);
        assert_eq!(
            texts(&extraction, Vector::FormBody)
                .first()
                .map(String::len),
            Some(INSPECT_BODY_CAP)
        );
    }
}
