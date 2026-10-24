//! Small shared helpers: Ray IDs, RFC 3339 UTC timestamps without a clock crate, host/authority and origin-URL
//! parsing, CIDR matching for `trusted_proxies`, header/cookie helpers, hop-by-hop header lists, the client-IP
//! resolution rule (COLLAB.md: `X-Forwarded-For` is trusted only from `trusted_proxies`, rightmost untrusted hop) and
//! the boxed response-body type both listeners use.
//!
//! Nothing here does I/O except reading the system clock; nothing here logs request bodies or secrets.

use std::fmt::Write as _;
use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Mutex, MutexGuard};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use bytes::Bytes;
use http_body_util::combinators::BoxBody;
use http_body_util::{BodyExt, Full};

/// The suffix every Ray ID carries (`16 hex + -HDD1`, spec C14/T-0208 step 7).
pub const RAY_SUFFIX: &str = "-HDD1";

/// A boxed error carried by response bodies (hyper connection errors, never inspected in HK1 responses).
pub type BoxError = Box<dyn std::error::Error + Send + Sync>;

/// The response body both listeners return.
pub type ResBody = BoxBody<Bytes, BoxError>;

/// Fallback Ray-ID entropy when the operating system random source is unavailable: a monotonic counter mixed with
/// the clock, so two Ray IDs emitted in the same process still differ.
static RAY_FALLBACK: AtomicU64 = AtomicU64::new(0);

/// Generate a new Ray ID in the documented `[0-9a-f]{16}-HDD1` format.
#[must_use]
pub fn new_ray_id() -> String {
    let mut bytes = [0_u8; 8];
    if getrandom::fill(&mut bytes).is_err() {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        let counter = RAY_FALLBACK.fetch_add(1, Ordering::Relaxed);
        let mixed = (nanos as u64) ^ ((nanos >> 64) as u64) ^ counter;
        bytes = mixed.to_be_bytes();
    }
    let mut out = String::with_capacity(21);
    for byte in bytes {
        let _ = write!(out, "{byte:02x}");
    }
    out.push_str(RAY_SUFFIX);
    out
}

/// Whether `value` is a well-formed Ray ID (`[0-9a-f]{16}-HDD1`). Used by tests and the verify flow.
#[must_use]
pub fn is_ray_id(value: &str) -> bool {
    let Some(raw) = value.strip_suffix(RAY_SUFFIX) else {
        return false;
    };
    raw.len() == 16
        && raw
            .bytes()
            .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
}

/// Seconds since the Unix epoch, saturating at zero for clocks before it.
#[must_use]
pub fn unix_secs(time: SystemTime) -> u64 {
    time.duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Milliseconds since the Unix epoch, saturating at zero for clocks before it.
#[must_use]
pub fn unix_millis(time: SystemTime) -> u64 {
    time.duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

/// Format a timestamp as RFC 3339 UTC with millisecond precision (`2026-10-23T21:45:00.123Z`).
#[must_use]
pub fn rfc3339(time: SystemTime) -> String {
    let millis = unix_millis(time);
    let secs = (millis / 1000) as i64;
    let millis_part = millis % 1000;
    let days = secs.div_euclid(86_400);
    let secs_of_day = secs.rem_euclid(86_400);
    let (year, month, day) = civil_from_days(days);
    let hour = secs_of_day / 3_600;
    let minute = (secs_of_day % 3_600) / 60;
    let second = secs_of_day % 60;
    let mut out = String::with_capacity(24);
    let _ = write!(
        out,
        "{year:04}-{month:02}-{day:02}T{hour:02}:{minute:02}:{second:02}.{millis_part:03}Z"
    );
    out
}

/// Format the current time as RFC 3339 UTC.
#[must_use]
pub fn rfc3339_now() -> String {
    rfc3339(SystemTime::now())
}

/// Convert a civil date to days since the Unix epoch (Howard Hinnant's algorithm; used by the timestamp tests).
#[cfg(test)]
fn days_from_civil(year: i64, month: u32, day: u32) -> i64 {
    let year = if month <= 2 { year - 1 } else { year };
    let era = if year >= 0 { year } else { year - 399 } / 400;
    let year_of_era = year - era * 400;
    let month_index = i64::from(month) + if month > 2 { -3 } else { 9 };
    let day_of_year = (153 * month_index + 2) / 5 + i64::from(day) - 1;
    let day_of_era = year_of_era * 365 + year_of_era / 4 - year_of_era / 100 + day_of_year;
    era * 146_097 + day_of_era - 719_468
}

/// Convert days since the Unix epoch to `(year, month, day)` (Howard Hinnant's algorithm).
fn civil_from_days(days: i64) -> (i64, u32, u32) {
    let z = days + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let day_of_era = z - era * 146_097;
    let year_of_era =
        (day_of_era - day_of_era / 1460 + day_of_era / 36_524 - day_of_era / 146_096) / 365;
    let year = year_of_era + era * 400;
    let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    let month_index = (5 * day_of_year + 2) / 153;
    let day = day_of_year - (153 * month_index + 2) / 5 + 1;
    let month = if month_index < 10 {
        month_index + 3
    } else {
        month_index - 9
    };
    (
        year + i64::from(u32::from(month <= 2)),
        month as u32,
        day as u32,
    )
}

/// A parsed IPv4/IPv6 CIDR block (for `trusted_proxies`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Cidr {
    /// The network address.
    network: IpAddr,
    /// The prefix length in bits.
    prefix: u8,
}

impl Cidr {
    /// Parse a CIDR block such as `198.51.100.0/24` or `2001:db8::/32`.
    ///
    /// # Errors
    /// Returns a human message when the text is not a CIDR block with an in-range prefix.
    pub fn parse(text: &str) -> Result<Self, String> {
        let trimmed = text.trim();
        let Some((address_part, prefix_part)) = trimmed.split_once('/') else {
            return Err(format!(
                "`{trimmed}` is not a CIDR block; write it as an address and a prefix, for example `198.51.100.0/24`"
            ));
        };
        let network: IpAddr = address_part.trim().parse().map_err(|_| {
            format!("`{trimmed}` is not a CIDR block: `{address_part}` is not an IP address")
        })?;
        let prefix: u8 = prefix_part.trim().parse().map_err(|_| {
            format!("`{trimmed}` is not a CIDR block: `{prefix_part}` is not a prefix length")
        })?;
        let max = match network {
            IpAddr::V4(_) => 32,
            IpAddr::V6(_) => 128,
        };
        if prefix > max {
            return Err(format!(
                "`{trimmed}` is not a valid CIDR block: /{prefix} is out of range for this address family (maximum /{max})"
            ));
        }
        Ok(Self { network, prefix })
    }

    /// Whether `ip` falls inside this block.
    #[must_use]
    pub fn contains(&self, ip: IpAddr) -> bool {
        match (self.network, ip) {
            (IpAddr::V4(network), IpAddr::V4(candidate)) => {
                let mask = if self.prefix == 0 {
                    0
                } else {
                    u32::MAX << (32 - u32::from(self.prefix))
                };
                (u32::from(network) & mask) == (u32::from(candidate) & mask)
            }
            (IpAddr::V6(network), IpAddr::V6(candidate)) => {
                let mask = if self.prefix == 0 {
                    0
                } else {
                    u128::MAX << (128 - u32::from(self.prefix))
                };
                (u128::from(network) & mask) == (u128::from(candidate) & mask)
            }
            _ => false,
        }
    }
}

/// Whether `peer` is inside one of the configured `trusted_proxies` CIDR blocks.
#[must_use]
pub fn peer_is_trusted(peer: IpAddr, trusted: &[Cidr]) -> bool {
    trusted.iter().any(|cidr| cidr.contains(peer))
}

/// Resolve the client IP of a request.
///
/// For an untrusted peer the socket address is the answer and every `X-Forwarded-For` byte is ignored (spoofing
/// resistance). For a trusted peer the header is walked from the right and the first hop that is not a trusted proxy
/// is the client (the rightmost untrusted hop); a fully-trusted chain falls back to its leftmost entry.
#[must_use]
pub fn resolve_client_ip(
    peer: SocketAddr,
    headers: &[(String, String)],
    trusted: &[Cidr],
) -> IpAddr {
    let peer_ip = peer.ip();
    if !peer_is_trusted(peer_ip, trusted) {
        return peer_ip;
    }
    let Some(forwarded) = header(headers, "x-forwarded-for") else {
        return peer_ip;
    };
    let hops: Vec<IpAddr> = forwarded
        .split(',')
        .filter_map(|hop| hop.trim().parse::<IpAddr>().ok())
        .collect();
    // A request that came through the front door (the app's wrapper sets `X-HDD-Gate-Hop`) names the visitor first: a
    // tunnel in front of HDD (Cloudflare, for one) appends the address of the host that called it, which is the app's
    // platform, not the visitor, and banning that address would ban every visitor at once.
    if header(headers, "x-hdd-gate-hop").is_some()
        && let Some(first) = hops.first()
    {
        return *first;
    }
    for hop in hops.iter().rev() {
        if !peer_is_trusted(*hop, trusted) {
            return *hop;
        }
    }
    hops.first().copied().unwrap_or(peer_ip)
}

/// First value of a header (case-insensitive name match).
#[must_use]
pub fn header<'a>(headers: &'a [(String, String)], name: &str) -> Option<&'a str> {
    headers
        .iter()
        .find(|(key, _)| key.eq_ignore_ascii_case(name))
        .map(|(_, value)| value.as_str())
}

/// First value of a cookie by name.
#[must_use]
pub fn cookie_value(headers: &[(String, String)], name: &str) -> Option<String> {
    let raw = header(headers, "cookie")?;
    for pair in raw.split(';') {
        let pair = pair.trim();
        if let Some((key, value)) = pair.split_once('=')
            && key.trim() == name
        {
            return Some(value.trim().to_owned());
        }
    }
    None
}

/// Hop-by-hop headers (RFC 9110 section 7.6.1) that are never forwarded.
#[must_use]
pub fn is_hop_by_hop(name: &str) -> bool {
    matches!(
        name.to_ascii_lowercase().as_str(),
        "connection"
            | "keep-alive"
            | "proxy-authenticate"
            | "proxy-authorization"
            | "proxy-connection"
            | "te"
            | "trailer"
            | "transfer-encoding"
            | "upgrade"
    )
}

/// The header names listed in the `Connection` header, which are also hop-by-hop for this exchange.
#[must_use]
pub fn connection_tokens(headers: &[(String, String)]) -> Vec<String> {
    headers
        .iter()
        .filter(|(name, _)| name.eq_ignore_ascii_case("connection"))
        .flat_map(|(_, value)| value.split(','))
        .map(|token| token.trim().to_ascii_lowercase())
        .filter(|token| !token.is_empty())
        .collect()
}

/// Remove hop-by-hop headers and the ones named by `Connection`.
#[must_use]
pub fn strip_hop_by_hop(headers: &[(String, String)]) -> Vec<(String, String)> {
    let tokens = connection_tokens(headers);
    headers
        .iter()
        .filter(|(name, _)| {
            !is_hop_by_hop(name) && !tokens.iter().any(|token| token.eq_ignore_ascii_case(name))
        })
        .cloned()
        .collect()
}

/// Normalise a `Host`/authority value: lower-case host, no port, no trailing dot, no brackets for IPv6.
///
/// Returns `None` for a value that cannot be a host (empty, whitespace, a URL with a scheme or path, invalid
/// characters).
#[must_use]
pub fn normalize_host(value: &str) -> Option<String> {
    let trimmed = value.trim();
    if trimmed.is_empty() || trimmed.len() > 300 {
        return None;
    }
    // A `Host` header or a route key is a host, never a URL: reject schemes, paths and queries outright.
    if trimmed.contains("://")
        || trimmed.contains('/')
        || trimmed.contains('?')
        || trimmed.contains('#')
    {
        return None;
    }
    let host = if let Some(rest) = trimmed.strip_prefix('[') {
        let close = rest.find(']')?;
        let address = rest.get(..close)?;
        let _: std::net::Ipv6Addr = address.parse().ok()?;
        address.to_ascii_lowercase()
    } else {
        let without_port = trimmed.split(':').next().unwrap_or(trimmed);
        let lowered = without_port.trim_end_matches('.').to_ascii_lowercase();
        if lowered.is_empty() {
            return None;
        }
        if lowered
            .bytes()
            .any(|b| !(b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-' | b'_')))
        {
            return None;
        }
        lowered
    };
    Some(host)
}

/// Split an authority (`example.com:8443`, `[::1]:8080`) into a normalised host and an optional port.
#[must_use]
pub fn parse_authority(value: &str) -> Option<(String, Option<u16>)> {
    let trimmed = value.trim();
    if let Some(rest) = trimmed.strip_prefix('[') {
        let close = rest.find(']')?;
        let address = rest.get(..close)?;
        let after = rest.get(close + 1..)?;
        let port = if after.is_empty() {
            None
        } else {
            Some(after.strip_prefix(':')?.parse::<u16>().ok()?)
        };
        let host = normalize_host(&format!("[{address}]"))?;
        return Some((host, port));
    }
    let (host_part, port) = match trimmed.rsplit_once(':') {
        Some((host, port_text)) => match port_text.parse::<u16>() {
            Ok(port) => (host, Some(port)),
            Err(_) => (trimmed, None),
        },
        None => (trimmed, None),
    };
    let host = normalize_host(host_part)?;
    Some((host, port))
}

/// Whether an `Origin` header authority names the same host as the request `Host` (CSRF check).
///
/// Ports are compared when both sides carry one; a missing port on either side matches.
#[must_use]
pub fn authority_matches_host(origin_authority: &str, request_host: &str) -> bool {
    let Some((origin_host, origin_port)) = parse_authority(origin_authority) else {
        return false;
    };
    let Some((request_host_name, request_port)) = parse_authority(request_host) else {
        return false;
    };
    if origin_host != request_host_name {
        return false;
    }
    match (origin_port, request_port) {
        (Some(a), Some(b)) => a == b,
        _ => true,
    }
}

/// An origin a site forwards to (`http://127.0.0.1:8081` or `https://app.example.com`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Origin {
    /// Whether the origin is HTTPS (the proxy verifies the certificate; there is no disable switch).
    pub https: bool,
    /// The origin host without brackets for IPv6.
    pub host: String,
    /// The origin port (default 80 or 443).
    pub port: u16,
    /// The optional base path the origin is mounted under (no trailing slash, `""` when none).
    pub base_path: String,
}

impl Origin {
    /// Parse an origin URL, rejecting credentials, query strings and fragments.
    ///
    /// # Errors
    /// Returns a human message for anything that is not an `http://` or `https://` base URL.
    pub fn parse(url: &str) -> Result<Self, String> {
        let trimmed = url.trim();
        let Some((scheme, rest)) = trimmed.split_once("://") else {
            return Err(format!(
                "origin `{trimmed}` must start with `http://` or `https://`"
            ));
        };
        let (https, default_port) = match scheme.to_ascii_lowercase().as_str() {
            "http" => (false, 80_u16),
            "https" => (true, 443_u16),
            other => {
                return Err(format!(
                    "origin `{trimmed}` uses unsupported scheme `{other}`; only `http` and `https` are allowed"
                ));
            }
        };
        let authority_end = rest.find(['/', '?', '#']).unwrap_or(rest.len());
        let authority = rest.get(..authority_end).unwrap_or(rest);
        if authority.contains('@') {
            return Err(format!(
                "origin `{trimmed}` must not contain credentials (user:password@)"
            ));
        }
        let Some((host, explicit_port)) = parse_authority(authority) else {
            return Err(format!(
                "origin `{trimmed}` has an invalid host `{authority}`"
            ));
        };
        let tail = rest.get(authority_end..).unwrap_or("");
        if tail.contains('?') || tail.contains('#') {
            return Err(format!(
                "origin `{trimmed}` must be a base URL without a query string or fragment"
            ));
        }
        let base_path = tail.trim_end_matches('/').to_owned();
        Ok(Self {
            https,
            host,
            port: explicit_port.unwrap_or(default_port),
            base_path,
        })
    }

    /// The scheme name.
    #[must_use]
    pub fn scheme(&self) -> &'static str {
        if self.https { "https" } else { "http" }
    }

    /// The default port for the scheme.
    #[must_use]
    pub fn default_port(&self) -> u16 {
        if self.https { 443 } else { 80 }
    }

    /// The host part for a `Host` header or a connect address (brackets restored for IPv6).
    #[must_use]
    pub fn host_for_header(&self) -> String {
        if self.host.contains(':') {
            format!("[{}]", self.host)
        } else {
            self.host.clone()
        }
    }

    /// The authority (`host` without a default port, `host:port` otherwise).
    #[must_use]
    pub fn authority(&self) -> String {
        if self.port == self.default_port() {
            self.host_for_header()
        } else {
            format!("{}:{}", self.host_for_header(), self.port)
        }
    }

    /// The full origin URL.
    #[must_use]
    pub fn url(&self) -> String {
        format!("{}://{}", self.scheme(), self.authority())
    }

    /// Build the absolute URL for a request target (path and optional query).
    #[must_use]
    pub fn join(&self, path_and_query: &str) -> String {
        format!("{}{}{}", self.url(), self.base_path, path_and_query)
    }
}

/// Percent-decode a URL component, treating `+` as a space (query and form convention).
#[must_use]
pub fn percent_decode(input: &str) -> String {
    let bytes = input.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while let Some(byte) = bytes.get(index).copied() {
        match byte {
            b'%' => {
                let high = bytes.get(index + 1).copied().and_then(hex_value);
                let low = bytes.get(index + 2).copied().and_then(hex_value);
                match (high, low) {
                    (Some(high), Some(low)) => {
                        out.push(high.wrapping_mul(16).wrapping_add(low));
                        index += 3;
                    }
                    _ => {
                        out.push(b'%');
                        index += 1;
                    }
                }
            }
            b'+' => {
                out.push(b' ');
                index += 1;
            }
            other => {
                out.push(other);
                index += 1;
            }
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// The numeric value of one ASCII hex digit.
fn hex_value(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

/// Parse a query string into decoded name/value pairs, preserving order and repeated names.
#[must_use]
pub fn parse_query(query: Option<&str>) -> Vec<(String, String)> {
    let Some(query) = query else {
        return Vec::new();
    };
    query
        .split('&')
        .filter(|pair| !pair.is_empty())
        .map(|pair| match pair.split_once('=') {
            Some((name, value)) => (percent_decode(name), percent_decode(value)),
            None => (percent_decode(pair), String::new()),
        })
        .collect()
}

/// Percent-encode one URL component (unreserved characters kept, everything else as upper-case `%XX`).
#[must_use]
pub fn percent_encode_component(value: &str) -> String {
    let mut out = String::with_capacity(value.len() * 3);
    for byte in value.bytes() {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~') {
            out.push(char::from(byte));
        } else {
            out.push('%');
            out.push(hex_digit(byte >> 4));
            out.push(hex_digit(byte & 0x0f));
        }
    }
    out
}

/// One upper-case hex digit.
fn hex_digit(value: u8) -> char {
    match value {
        0..=9 => char::from(b'0' + value),
        _ => char::from(b'A' + (value - 10)),
    }
}

/// A display approximation of the detector's normalisation for the Test console (`/api/inspect`).
///
/// The detector's canonical form is internal to `hdd-waf-core`; this helper performs the documented visible steps
/// (repeated percent-decoding, case folding, whitespace collapse) and cuts to the evidence limit. It is labelled as an
/// approximation in the UI and is never used for a decision.
#[must_use]
pub fn display_normalized(input: &str) -> String {
    let mut current = input.to_owned();
    for _ in 0..3 {
        let decoded = percent_decode(&current);
        if decoded == current {
            break;
        }
        current = decoded;
    }
    let mut collapsed = String::with_capacity(current.len());
    let mut previous_space = false;
    for c in current.chars() {
        if c.is_whitespace() {
            if !previous_space {
                collapsed.push(' ');
                previous_space = true;
            }
        } else {
            collapsed.push(c.to_ascii_lowercase());
            previous_space = false;
        }
    }
    truncate_utf8(collapsed.trim(), 128).to_owned()
}

/// The serde name of a detector [`hdd_waf_core::Vector`] (used in events and the inspect console).
#[must_use]
pub fn vector_name(vector: hdd_waf_core::Vector) -> &'static str {
    use hdd_waf_core::Vector;
    match vector {
        Vector::Path => "path",
        Vector::Query => "query",
        Vector::FormBody => "form_body",
        Vector::JsonBody => "json_body",
        Vector::MultipartField => "multipart_field",
        Vector::MultipartFilename => "multipart_filename",
        Vector::Header => "header",
        Vector::Cookie => "cookie",
    }
}

/// The serde name of a detector [`hdd_waf_core::FieldKind`] (used in events and the inspect console).
#[must_use]
pub fn field_kind_name(kind: hdd_waf_core::FieldKind) -> &'static str {
    use hdd_waf_core::FieldKind;
    match kind {
        FieldKind::Password => "password",
        FieldKind::Username => "username",
        FieldKind::NumericId => "numeric_id",
        FieldKind::Search => "search",
        FieldKind::FreeText => "free_text",
        FieldKind::Filename => "filename",
        FieldKind::Header => "header",
        FieldKind::Cookie => "cookie",
        FieldKind::Unknown => "unknown",
    }
}

/// Escape the five HTML-significant characters (used by the locally rendered error pages only).
#[must_use]
pub fn html_escape(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    for c in input.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#39;"),
            other => out.push(other),
        }
    }
    out
}

/// Cut a string to at most `max` bytes on a UTF-8 boundary.
#[must_use]
pub fn truncate_utf8(input: &str, max: usize) -> &str {
    if input.len() <= max {
        return input;
    }
    let mut cut = max;
    while cut > 0 && !input.is_char_boundary(cut) {
        cut -= 1;
    }
    input.get(..cut).unwrap_or("")
}

/// Constant-time string comparison for the bootstrap admin token (R-20: no timing side channel).
#[must_use]
pub fn constant_time_eq(left: &str, right: &str) -> bool {
    let left_bytes = left.as_bytes();
    let right_bytes = right.as_bytes();
    if left_bytes.len() != right_bytes.len() {
        return false;
    }
    let mut difference = 0_u8;
    for (a, b) in left_bytes.iter().zip(right_bytes.iter()) {
        difference |= a ^ b;
    }
    difference == 0
}

/// Whether an IP address is a loopback address (the admin listener is loopback-only by default).
#[must_use]
pub fn is_loopback(ip: IpAddr) -> bool {
    ip.is_loopback()
}

/// Lock a mutex, recovering the guard when a previous holder panicked (a poisoned mutex must not take the proxy down).
pub fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    match mutex.lock() {
        Ok(guard) => guard,
        Err(poisoned) => poisoned.into_inner(),
    }
}

/// Build an empty body.
#[must_use]
pub fn empty_body() -> ResBody {
    Full::new(Bytes::new())
        .map_err(|never| -> BoxError { match never {} })
        .boxed()
}

/// Build a full in-memory body.
#[must_use]
pub fn full_body(bytes: impl Into<Bytes>) -> ResBody {
    Full::new(bytes.into())
        .map_err(|never| -> BoxError { match never {} })
        .boxed()
}

/// Box an incoming request body for forwarding without reading it (pure `off`-mode pass-through).
#[must_use]
pub fn stream_body(incoming: hyper::body::Incoming) -> ResBody {
    incoming
        .map_err(|error| -> BoxError { Box::new(error) })
        .boxed()
}

/// Parse a duration in whole seconds, saturating at `u64::MAX`.
#[must_use]
pub fn seconds(count: u64) -> Duration {
    Duration::from_secs(count)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ray_ids_have_the_documented_shape_and_are_unique() {
        let first = new_ray_id();
        let second = new_ray_id();
        assert!(is_ray_id(&first), "ray id {first} does not match");
        assert!(is_ray_id(&second));
        assert_ne!(first, second);
    }

    #[test]
    fn a_front_door_request_names_the_visitor_not_the_platform_that_called_the_tunnel() {
        let trusted = vec![Cidr::parse("127.0.0.1/32").expect("valid cidr")];
        let peer: SocketAddr = "127.0.0.1:50000".parse().expect("valid address");
        let through_door = vec![
            (
                "x-forwarded-for".to_owned(),
                "203.0.113.7, 34.205.154.144".to_owned(),
            ),
            ("x-hdd-gate-hop".to_owned(), "1".to_owned()),
        ];
        assert_eq!(
            resolve_client_ip(peer, &through_door, &trusted).to_string(),
            "203.0.113.7"
        );
        let plain = vec![(
            "x-forwarded-for".to_owned(),
            "203.0.113.7, 34.205.154.144".to_owned(),
        )];
        assert_eq!(
            resolve_client_ip(peer, &plain, &trusted).to_string(),
            "34.205.154.144",
            "without the front door the rightmost untrusted hop is still the client"
        );
    }

    #[test]
    fn ray_id_format_rejects_other_shapes() {
        assert!(!is_ray_id("0123456789ABCDEF-HDD1"));
        assert!(!is_ray_id("0123456789abcdef"));
        assert!(!is_ray_id("xyz"));
        assert!(is_ray_id("0123456789abcdef-HDD1"));
    }

    #[test]
    fn rfc3339_matches_known_instants() {
        assert_eq!(rfc3339(UNIX_EPOCH), "1970-01-01T00:00:00.000Z");
        assert_eq!(
            rfc3339(UNIX_EPOCH + Duration::from_millis(1_699_400_000_123)),
            "2023-11-07T23:33:20.123Z"
        );
    }

    #[test]
    fn civil_round_trip_is_stable() {
        for days in [-1_000_i64, 0, 1, 19_000, 20_000, 30_000] {
            let (year, month, day) = civil_from_days(days);
            assert_eq!(days_from_civil(year, month, day), days);
        }
    }

    #[test]
    fn hosts_are_normalised_and_ports_stripped() {
        assert_eq!(
            normalize_host("Example.COM:8080").as_deref(),
            Some("example.com")
        );
        assert_eq!(
            normalize_host("example.com.").as_deref(),
            Some("example.com")
        );
        assert_eq!(normalize_host("[::1]:8080").as_deref(), Some("::1"));
        assert_eq!(normalize_host("bad host"), None);
        assert_eq!(normalize_host("http://example.com"), None);
    }

    #[test]
    fn authority_matching_compares_hosts_and_ports() {
        assert!(authority_matches_host(
            "admin.example.com:9090",
            "admin.example.com:9090"
        ));
        assert!(authority_matches_host(
            "admin.example.com",
            "admin.example.com:9090"
        ));
        assert!(!authority_matches_host(
            "evil.example.com",
            "admin.example.com"
        ));
        assert!(!authority_matches_host(
            "admin.example.com:1234",
            "admin.example.com:9090"
        ));
    }

    #[test]
    fn cidr_matching_handles_both_families_and_edges() {
        let v4 = Cidr::parse("192.0.2.0/24").ok();
        let v4 = v4.expect("test cidr parses");
        assert!(
            v4.contains(
                "192.0.2.55"
                    .parse()
                    .unwrap_or(IpAddr::V4(std::net::Ipv4Addr::LOCALHOST))
            )
        );
        assert!(
            !v4.contains(
                "192.0.3.1"
                    .parse()
                    .unwrap_or(IpAddr::V4(std::net::Ipv4Addr::LOCALHOST))
            )
        );
        let all = Cidr::parse("0.0.0.0/0").expect("0/0 parses");
        assert!(
            all.contains(
                "127.0.0.1"
                    .parse()
                    .unwrap_or(IpAddr::V4(std::net::Ipv4Addr::LOCALHOST))
            )
        );
        let v6 = Cidr::parse("2001:db8::/32").expect("v6 cidr parses");
        assert!(
            v6.contains(
                "2001:db8::1"
                    .parse()
                    .unwrap_or(IpAddr::V6(std::net::Ipv6Addr::LOCALHOST))
            )
        );
        assert!(
            !v6.contains(
                "2001:db9::1"
                    .parse()
                    .unwrap_or(IpAddr::V6(std::net::Ipv6Addr::LOCALHOST))
            )
        );
        assert!(Cidr::parse("192.0.2.0/33").is_err());
        assert!(Cidr::parse("192.0.2.0").is_err());
    }

    #[test]
    fn untrusted_xff_is_ignored_and_trusted_chain_takes_rightmost_untrusted_hop() {
        let peer = SocketAddr::from(([127, 0, 0, 1], 5555));
        let headers = vec![(
            "X-Forwarded-For".to_owned(),
            "203.0.113.7, 198.51.100.4".to_owned(),
        )];
        assert_eq!(resolve_client_ip(peer, &headers, &[]), peer.ip());
        let trusted = vec![Cidr::parse("127.0.0.1/32").expect("cidr")];
        assert_eq!(
            resolve_client_ip(peer, &headers, &trusted),
            "198.51.100.4".parse::<IpAddr>().unwrap_or(peer.ip())
        );
    }

    #[test]
    fn origins_parse_and_join() {
        let origin = Origin::parse("http://127.0.0.1:8081").expect("origin parses");
        assert_eq!(origin.authority(), "127.0.0.1:8081");
        assert_eq!(origin.join("/login?q=1"), "http://127.0.0.1:8081/login?q=1");
        let tls = Origin::parse("https://app.example.com").expect("https origin parses");
        assert!(tls.https);
        assert_eq!(tls.port, 443);
        assert!(Origin::parse("ftp://example.com").is_err());
        assert!(Origin::parse("http://user:pass@example.com").is_err()); // hdd-secret-scan:allow (test vector: credentials in a URL must be refused)
        assert!(Origin::parse("http://example.com/?q=1").is_err());
    }

    #[test]
    fn percent_decoding_handles_plus_and_invalid_sequences() {
        assert_eq!(percent_decode("a+b%27%2F"), "a b'/");
        assert_eq!(percent_decode("%zz"), "%zz");
        assert_eq!(percent_decode("100%25"), "100%");
    }

    #[test]
    fn hop_by_hop_stripping_also_removes_connection_tokens() {
        let headers = vec![
            ("Connection".to_owned(), "X-Custom-Hop".to_owned()),
            ("X-Custom-Hop".to_owned(), "1".to_owned()),
            ("Content-Type".to_owned(), "text/plain".to_owned()),
            ("Transfer-Encoding".to_owned(), "chunked".to_owned()),
        ];
        let stripped = strip_hop_by_hop(&headers);
        assert!(stripped.iter().all(|(name, _)| name != "X-Custom-Hop"));
        assert!(stripped.iter().all(|(name, _)| name != "Connection"));
        assert!(stripped.iter().any(|(name, _)| name == "Content-Type"));
    }

    #[test]
    fn constant_time_comparison_is_correct() {
        assert!(constant_time_eq("token", "token"));
        assert!(!constant_time_eq("token", "toke"));
        assert!(!constant_time_eq("token", "tokem"));
    }
}
