//! Strict URL parsing for the egress client (http and https only).
//!
//! The parser is deliberately small and rejects everything ambiguous: credentials, control characters, backslashes,
//! non-ASCII, ambiguous numeric hosts (`2130706433`, `0x7f.1`, `017700000001`), empty labels, zero ports. It never panics
//! (the property tests below and `egress::fuzz_entry`, which a libFuzzer target will call once `cargo-fuzz` is available, T-0259).

use std::fmt;
use std::net::IpAddr;

use super::allow::Scheme;

/// Longest accepted URL.
pub const MAX_URL_BYTES: usize = 8192;

/// A parsed absolute URL.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParsedUrl {
    /// `Https` or `Http`.
    pub scheme: Scheme,
    /// Lower-case host without brackets or trailing dot.
    pub host: String,
    /// The host as an IP address when it is a literal.
    pub ip: Option<IpAddr>,
    /// Port (scheme default when absent).
    pub port: u16,
    /// Path and query, always starting with `/`.
    pub path_and_query: String,
}

/// Why a URL is refused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UrlError {
    /// Longer than [`MAX_URL_BYTES`] or empty.
    Length,
    /// Contains a space, control character, backslash or non-ASCII byte.
    Character,
    /// Scheme other than http or https.
    Scheme,
    /// No `//` authority.
    Authority,
    /// Credentials (`user:pass@`) are not allowed.
    Userinfo,
    /// Invalid or empty host.
    Host,
    /// A numeric host that is not a strict dotted-quad or IPv6 literal (decimal, octal and hex tricks).
    AmbiguousNumericHost,
    /// Invalid port.
    Port,
}

impl fmt::Display for UrlError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            UrlError::Length => "URL is empty or longer than 8192 bytes",
            UrlError::Character => {
                "URL contains a space, control character, backslash or non-ASCII byte"
            }
            UrlError::Scheme => "only http and https URLs are allowed",
            UrlError::Authority => "URL has no `//host` part",
            UrlError::Userinfo => "credentials in URLs are not allowed",
            UrlError::Host => "invalid host",
            UrlError::AmbiguousNumericHost => {
                "numeric host in a non-standard form (decimal, octal or hex IPv4) is refused"
            }
            UrlError::Port => "invalid port",
        })
    }
}

impl std::error::Error for UrlError {}

fn label_ok(l: &str) -> bool {
    !l.is_empty()
        && l.len() <= 63
        && !l.starts_with('-')
        && !l.ends_with('-')
        && l.chars().all(|c| c.is_ascii_alphanumeric() || c == '-')
}

/// Parse an absolute http(s) URL.
pub fn parse_url(s: &str) -> Result<ParsedUrl, UrlError> {
    if s.is_empty() || s.len() > MAX_URL_BYTES {
        return Err(UrlError::Length);
    }
    if !s.bytes().all(|b| (0x21..=0x7e).contains(&b)) || s.contains('\\') {
        return Err(UrlError::Character);
    }
    let (scheme_s, rest) = s.split_once("://").ok_or(UrlError::Authority)?;
    let scheme = match scheme_s.to_ascii_lowercase().as_str() {
        "https" => Scheme::Https,
        "http" => Scheme::Http,
        _ => return Err(UrlError::Scheme),
    };
    let rest = rest.split('#').next().unwrap_or("");
    let end = rest.find(['/', '?']).unwrap_or(rest.len());
    let authority = rest.get(..end).unwrap_or("");
    let tail = rest.get(end..).unwrap_or("");
    if authority.contains('@') {
        return Err(UrlError::Userinfo);
    }
    let (host_s, port_s) = if let Some(stripped) = authority.strip_prefix('[') {
        let close = stripped.find(']').ok_or(UrlError::Host)?;
        let after = stripped.get(close + 1..).unwrap_or("");
        let port = if after.is_empty() {
            None
        } else {
            Some(after.strip_prefix(':').ok_or(UrlError::Host)?)
        };
        (stripped.get(..close).unwrap_or(""), port)
    } else {
        match authority.rsplit_once(':') {
            Some((h, p)) => (h, Some(p)),
            None => (authority, None),
        }
    };
    let port = match port_s {
        None => scheme.default_port().ok_or(UrlError::Port)?,
        Some(p) => {
            if p.is_empty() || p.len() > 5 || !p.bytes().all(|b| b.is_ascii_digit()) {
                return Err(UrlError::Port);
            }
            match p.parse::<u16>() {
                Ok(n) if n != 0 => n,
                _ => return Err(UrlError::Port),
            }
        }
    };
    let bracketed = authority.starts_with('[');
    let host_trimmed = host_s.trim_end_matches('.');
    if host_trimmed.is_empty() || host_s.ends_with("..") {
        return Err(UrlError::Host);
    }
    let host = host_trimmed.to_ascii_lowercase();
    let ip = if bracketed {
        Some(host.parse::<IpAddr>().map_err(|_| UrlError::Host)?)
    } else if host.contains(':') {
        return Err(UrlError::Host);
    } else {
        match host.parse::<IpAddr>() {
            Ok(ip) => Some(ip),
            Err(_) => {
                if host.split('.').any(|l| !label_ok(l)) || host.len() > 253 {
                    return Err(UrlError::Host);
                }
                // the last label decides: all digits, or a hex/octal-looking first label, means an IPv4 spelled in a non-strict way
                let last_numeric = host
                    .rsplit('.')
                    .next()
                    .is_some_and(|l| l.bytes().all(|b| b.is_ascii_digit()));
                let hexish = host.split('.').any(|l| l.starts_with("0x"));
                if last_numeric || hexish {
                    return Err(UrlError::AmbiguousNumericHost);
                }
                None
            }
        }
    };
    let path_and_query = if tail.is_empty() {
        "/".to_owned()
    } else if tail.starts_with('?') {
        format!("/{tail}")
    } else {
        tail.to_owned()
    };
    let host = match ip {
        Some(ip) => ip.to_string(),
        None => host,
    };
    Ok(ParsedUrl {
        scheme,
        host,
        ip,
        port,
        path_and_query,
    })
}

/// True when `s` starts with `scheme://` (a scheme is a letter followed by letters, digits, `+`, `-` or `.`).
fn has_scheme(s: &str) -> bool {
    let mut chars = s.chars();
    if !chars.next().is_some_and(|c| c.is_ascii_alphabetic()) {
        return false;
    }
    for c in chars {
        if c == ':' {
            return s.contains("://") && s.find(':') == s.find("://");
        }
        if !(c.is_ascii_alphanumeric() || c == '+' || c == '-' || c == '.') {
            return false;
        }
    }
    false
}

impl ParsedUrl {
    /// The path without the query.
    pub fn path(&self) -> &str {
        self.path_and_query.split('?').next().unwrap_or("/")
    }

    /// `scheme://host:port/path` without the query (for logs: queries may carry secrets, R-21).
    pub fn display_no_query(&self) -> String {
        let host = if self.ip.is_some_and(|i| i.is_ipv6()) {
            format!("[{}]", self.host)
        } else {
            self.host.clone()
        };
        let mut path: String = self.path().chars().take(200).collect();
        if self.path().chars().count() > 200 {
            path.push('…');
        }
        format!("{}://{host}:{}{path}", self.scheme.as_str(), self.port)
    }

    /// `scheme://host:port` plus `/` or `/…` when a path exists: what the deny log records. The path is left out because
    /// webhook URLs often carry their secret in it (R-21).
    pub fn display_origin(&self) -> String {
        let host = if self.ip.is_some_and(|i| i.is_ipv6()) {
            format!("[{}]", self.host)
        } else {
            self.host.clone()
        };
        let tail = if self.path() == "/" { "/" } else { "/…" };
        format!("{}://{host}:{}{tail}", self.scheme.as_str(), self.port)
    }

    /// Value of the `Host` header.
    pub fn host_header(&self) -> String {
        let host = if self.ip.is_some_and(|i| i.is_ipv6()) {
            format!("[{}]", self.host)
        } else {
            self.host.clone()
        };
        if Some(self.port) == self.scheme.default_port() {
            host
        } else {
            format!("{host}:{}", self.port)
        }
    }

    /// Resolve a `Location` header value against this URL (absolute, protocol-relative, path-absolute or relative).
    pub fn join(&self, location: &str) -> Result<ParsedUrl, UrlError> {
        let location = location.trim();
        if has_scheme(location) {
            return parse_url(location);
        }
        let base_host = if self.ip.is_some_and(|i| i.is_ipv6()) {
            format!("[{}]", self.host)
        } else {
            self.host.clone()
        };
        let origin = format!("{}://{base_host}:{}", self.scheme.as_str(), self.port);
        if let Some(rest) = location.strip_prefix("//") {
            return parse_url(&format!("{}://{rest}", self.scheme.as_str()));
        }
        if location.starts_with('/') {
            return parse_url(&format!("{origin}{location}"));
        }
        let dir = self.path().rsplit_once('/').map_or("", |(d, _)| d);
        parse_url(&format!("{origin}{dir}/{location}"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    #[test]
    fn valid_urls() {
        let u = parse_url("HTTPS://Example.COM/a/b?x=1#frag").expect("url");
        assert_eq!(
            (u.scheme, u.host.as_str(), u.port, u.path_and_query.as_str()),
            (Scheme::Https, "example.com", 443, "/a/b?x=1")
        );
        let u = parse_url("http://example.com:8080").expect("url");
        assert_eq!((u.port, u.path_and_query.as_str()), (8080, "/"));
        let u = parse_url("https://example.com?x=1").expect("url");
        assert_eq!(u.path_and_query, "/?x=1");
        let u = parse_url("http://[2001:db8::1]:81/p").expect("url");
        assert_eq!((u.host.as_str(), u.port), ("2001:db8::1", 81));
        assert_eq!(u.display_no_query(), "http://[2001:db8::1]:81/p");
        let u = parse_url("https://127.0.0.1:9/").expect("url");
        assert_eq!(u.ip, Some("127.0.0.1".parse().expect("ip")));
        assert_eq!(
            parse_url("https://example.com./x").expect("url").host,
            "example.com"
        );
        assert_eq!(
            parse_url("https://example.com/x?token=secret")
                .expect("url")
                .display_no_query(),
            "https://example.com:443/x"
        );
        assert_eq!(
            parse_url("http://localhost:3000/").expect("url").host,
            "localhost"
        );
    }

    #[test]
    fn invalid_urls() {
        let cases: [(&str, UrlError); 17] = [
            ("", UrlError::Length),
            ("example.com", UrlError::Authority),
            ("ftp://example.com", UrlError::Scheme),
            ("file:///etc/passwd", UrlError::Scheme),
            ("https://user:pw@example.com", UrlError::Userinfo),
            ("https://example.com\\@evil.net", UrlError::Character),
            ("https://exa mple.com", UrlError::Character),
            ("https://example.com/\u{7f}", UrlError::Character),
            ("https://bücher.example", UrlError::Character),
            ("https://", UrlError::Host),
            ("https://a..b.com", UrlError::Host),
            ("https://-a.com", UrlError::Host),
            ("https://example.com:0", UrlError::Port),
            ("https://example.com:70000", UrlError::Port),
            ("https://example.com:", UrlError::Port),
            ("https://[::1", UrlError::Host),
            ("https://::1/", UrlError::Host),
        ];
        for (input, err) in cases {
            assert_eq!(parse_url(input).err(), Some(err), "{input}");
        }
    }

    #[test]
    fn numeric_host_tricks_are_refused() {
        for bad in [
            "http://2130706433/",
            "http://0x7f.0.0.1/",
            "http://0x7f000001/",
            "http://017700000001/",
            "http://127.1/",
            "http://1.2.3/",
            "http://0300.0250.0.1/",
            "http://10.0.0.1.1/",
        ] {
            assert_eq!(
                parse_url(bad).err(),
                Some(UrlError::AmbiguousNumericHost),
                "{bad}"
            );
        }
        assert!(parse_url("http://127.0.0.1/").is_ok());
    }

    #[test]
    fn join_resolves_locations() {
        let base = parse_url("https://a.example.com:8443/dir/page?q=1").expect("url");
        assert_eq!(
            base.join("/x").expect("abs path").display_no_query(),
            "https://a.example.com:8443/x"
        );
        assert_eq!(
            base.join("next").expect("relative").display_no_query(),
            "https://a.example.com:8443/dir/next"
        );
        assert_eq!(
            base.join("//b.example.net/y")
                .expect("protocol relative")
                .display_no_query(),
            "https://b.example.net:443/y"
        );
        assert_eq!(
            base.join("http://169.254.169.254/latest")
                .expect("absolute")
                .host,
            "169.254.169.254"
        );
        assert_eq!(
            base.join("javascript:alert(1)").map(|u| u.host).as_deref(),
            Ok("a.example.com"),
            "a scheme-looking relative reference stays a path on the same host"
        );
        assert!(base.join("ftp://x.example.com/").is_err());
        // a `://` inside the query of a relative reference does not make it absolute
        assert_eq!(
            base.join("/p?next=http://x.example.net/")
                .expect("relative with url in query")
                .host,
            "a.example.com"
        );
        assert_eq!(
            base.join("go?u=https://z.example.org")
                .expect("relative")
                .host,
            "a.example.com"
        );
    }

    #[test]
    fn host_header_omits_default_ports() {
        assert_eq!(
            parse_url("https://a.example.com/")
                .expect("url")
                .host_header(),
            "a.example.com"
        );
        assert_eq!(
            parse_url("http://a.example.com:8080/")
                .expect("url")
                .host_header(),
            "a.example.com:8080"
        );
        assert_eq!(
            parse_url("https://[::1]:8443/").expect("url").host_header(),
            "[::1]:8443"
        );
    }

    proptest! {
        #[test]
        fn url_parsing_never_panics(s in ".{0,300}") {
            if let Ok(u) = parse_url(&s) {
                let _ = u.display_no_query();
                let _ = u.host_header();
                let _ = u.join("../x?y");
            }
        }

        #[test]
        fn structured_urls_never_panic(host in "[ -~]{0,40}", port in "[0-9a-z]{0,7}", path in "[ -~]{0,40}") {
            let _ = parse_url(&format!("https://{host}:{port}/{path}"));
            let _ = parse_url(&format!("http://[{host}]:{port}{path}"));
        }

        #[test]
        fn accepted_hosts_are_stable_after_reparse(host in "[a-z0-9.-]{1,60}") {
            if let Ok(u) = parse_url(&format!("https://{host}/")) {
                let again = parse_url(&u.display_no_query()).expect("display form reparses");
                prop_assert_eq!(again.host, u.host);
                prop_assert_eq!(again.port, u.port);
            }
        }
    }
}
