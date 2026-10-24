//! Egress allowlist entries (`egress_allowlist` of the profile, section 2.1).
//!
//! Grammar: `[scheme://]host[:port][/path-prefix]` where `scheme` is `https` (the default when omitted), `http`, `tcp` or
//! `dns`; `host` is an exact name, an IP literal, or `*.suffix` (the suffix itself and any subdomain). The port defaults
//! to the scheme's port (443, 80, 53); `tcp` entries must name a port. Matching is by scheme, host, port and an optional
//! path prefix aligned on `/` boundaries.

use std::fmt;
use std::net::IpAddr;

use crate::net::validate_hostname;

/// Scheme of an outbound destination.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Scheme {
    /// HTTPS.
    Https,
    /// Plain HTTP (never to tenant-controlled hosts; allowlist entries must opt in explicitly).
    Http,
    /// A raw TCP connection (SMTP, for example).
    Tcp,
    /// DNS resolution traffic (the `dns_resolution` class).
    Dns,
}

impl Scheme {
    /// Default port of the scheme, if it has one.
    pub fn default_port(self) -> Option<u16> {
        match self {
            Scheme::Https => Some(443),
            Scheme::Http => Some(80),
            Scheme::Dns => Some(53),
            Scheme::Tcp => None,
        }
    }

    /// Scheme name as written in entries.
    pub fn as_str(self) -> &'static str {
        match self {
            Scheme::Https => "https",
            Scheme::Http => "http",
            Scheme::Tcp => "tcp",
            Scheme::Dns => "dns",
        }
    }

    fn parse(s: &str) -> Option<Scheme> {
        match s.to_ascii_lowercase().as_str() {
            "https" => Some(Scheme::Https),
            "http" => Some(Scheme::Http),
            "tcp" => Some(Scheme::Tcp),
            "dns" => Some(Scheme::Dns),
            _ => None,
        }
    }
}

/// Host part of an entry.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum HostPattern {
    /// An exact lower-case host name.
    Exact(String),
    /// `*.suffix`: the suffix and any subdomain of it (stored lower-case without the `*.`).
    Suffix(String),
    /// An IP literal.
    Ip(IpAddr),
}

/// Why an entry is rejected.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AllowError {
    /// Empty entry.
    Empty,
    /// Unknown scheme.
    Scheme(String),
    /// Bad host.
    Host(String),
    /// Bad port.
    Port,
    /// A `tcp` entry without a port.
    TcpNeedsPort,
    /// Wildcard anywhere but the leading `*.` label, or a bare `*`.
    Wildcard,
    /// Credentials, query or fragment present.
    Forbidden,
    /// Path prefix is not absolute or contains `..`/backslash.
    Path,
}

impl fmt::Display for AllowError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            AllowError::Empty => f.write_str("empty entry"),
            AllowError::Scheme(s) => {
                write!(f, "unknown scheme `{s}` (use https, http, tcp or dns)")
            }
            AllowError::Host(e) => write!(f, "invalid host: {e}"),
            AllowError::Port => f.write_str("invalid port"),
            AllowError::TcpNeedsPort => {
                f.write_str("tcp entries must name a port (for example tcp://smtp.example.com:587)")
            }
            AllowError::Wildcard => {
                f.write_str("a wildcard is allowed only as the leading `*.` label")
            }
            AllowError::Forbidden => {
                f.write_str("credentials, query strings and fragments are not allowed in entries")
            }
            AllowError::Path => {
                f.write_str("a path prefix must start with `/` and contain no `..` or backslash")
            }
        }
    }
}

impl std::error::Error for AllowError {}

/// One parsed allowlist entry.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct AllowEntry {
    /// Scheme.
    pub scheme: Scheme,
    /// Host pattern.
    pub host: HostPattern,
    /// Port (resolved from the scheme default).
    pub port: u16,
    /// Optional path prefix.
    pub path_prefix: Option<String>,
}

impl AllowEntry {
    /// Parse an entry.
    pub fn parse(raw: &str) -> Result<AllowEntry, AllowError> {
        let s = raw.trim();
        if s.is_empty() {
            return Err(AllowError::Empty);
        }
        if s.contains(['?', '#', '@']) || s.chars().any(char::is_whitespace) {
            return Err(AllowError::Forbidden);
        }
        let (scheme, rest) = match s.split_once("://") {
            Some((sch, rest)) => (
                Scheme::parse(sch).ok_or_else(|| AllowError::Scheme(sch.to_owned()))?,
                rest,
            ),
            None => (Scheme::Https, s),
        };
        let (authority, path) = match rest.find('/') {
            Some(i) => (
                rest.get(..i).unwrap_or(rest),
                Some(rest.get(i..).unwrap_or("/")),
            ),
            None => (rest, None),
        };
        let (host_s, port_s) = split_host_port(authority);
        let port = match port_s {
            Some(p) => {
                if p.is_empty() || p.len() > 5 || !p.chars().all(|c| c.is_ascii_digit()) {
                    return Err(AllowError::Port);
                }
                let n: u16 = p.parse().map_err(|_| AllowError::Port)?;
                if n == 0 {
                    return Err(AllowError::Port);
                }
                n
            }
            None => scheme.default_port().ok_or(AllowError::TcpNeedsPort)?,
        };
        let host = parse_host(host_s)?;
        let path_prefix = match path {
            None | Some("/") => None,
            Some(p) => {
                if !p.starts_with('/') || p.contains("..") || p.contains('\\') || p.contains("//") {
                    return Err(AllowError::Path);
                }
                Some(p.trim_end_matches('/').to_owned())
            }
        };
        Ok(AllowEntry {
            scheme,
            host,
            port,
            path_prefix,
        })
    }

    /// True when a request to (`scheme`, `host`, `port`, `path`) is permitted by this entry. `host` is compared
    /// case-insensitively and must not carry a trailing dot or brackets.
    pub fn matches(&self, scheme: Scheme, host: &str, port: u16, path: &str) -> bool {
        if self.scheme != scheme || self.port != port {
            return false;
        }
        let h = host.to_ascii_lowercase();
        let host_ok = match &self.host {
            HostPattern::Exact(e) => *e == h,
            HostPattern::Suffix(sfx) => {
                h == *sfx
                    || (h.len() > sfx.len() + 1
                        && h.ends_with(sfx.as_str())
                        && h.as_bytes().get(h.len() - sfx.len() - 1) == Some(&b'.'))
            }
            HostPattern::Ip(ip) => h
                .parse::<IpAddr>()
                .is_ok_and(|x| crate::net::canonical_ip(x) == crate::net::canonical_ip(*ip)),
        };
        if !host_ok {
            return false;
        }
        match &self.path_prefix {
            None => true,
            Some(prefix) => {
                let p = path.split(['?', '#']).next().unwrap_or("");
                if path_is_ambiguous(p) {
                    return false;
                }
                p == prefix
                    || (p.starts_with(prefix.as_str())
                        && p.as_bytes().get(prefix.len()) == Some(&b'/'))
            }
        }
    }
}

/// True when a request path could be read differently by this matcher and by the server: dot segments, encoded dots,
/// slashes or backslashes, doubled slashes. Such paths never satisfy a path-prefix entry.
pub fn path_is_ambiguous(p: &str) -> bool {
    let lower = p.to_ascii_lowercase();
    lower.contains("%2e")
        || lower.contains("%2f")
        || lower.contains("%5c")
        || lower.contains("%00")
        || lower.contains('\\')
        || lower.contains("//")
        || p.split('/').any(|seg| seg == "." || seg == "..")
}

impl fmt::Display for AllowEntry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let host = match &self.host {
            HostPattern::Exact(h) => h.clone(),
            HostPattern::Suffix(h) => format!("*.{h}"),
            HostPattern::Ip(IpAddr::V6(ip)) => format!("[{ip}]"),
            HostPattern::Ip(ip) => ip.to_string(),
        };
        write!(
            f,
            "{}://{}:{}{}",
            self.scheme.as_str(),
            host,
            self.port,
            self.path_prefix.as_deref().unwrap_or("")
        )
    }
}

fn split_host_port(authority: &str) -> (&str, Option<&str>) {
    if let Some(stripped) = authority.strip_prefix('[') {
        // [v6]:port
        if let Some(end) = stripped.find(']') {
            let host = stripped.get(..end).unwrap_or("");
            let after = stripped.get(end + 1..).unwrap_or("");
            return (host, after.strip_prefix(':'));
        }
        return (authority, None);
    }
    match authority.rsplit_once(':') {
        Some((h, p)) if !h.contains(':') => (h, Some(p)),
        _ => (authority, None),
    }
}

fn parse_host(h: &str) -> Result<HostPattern, AllowError> {
    if h.is_empty() {
        return Err(AllowError::Host("empty".into()));
    }
    if let Ok(ip) = h.parse::<IpAddr>() {
        return Ok(HostPattern::Ip(ip));
    }
    if let Some(sfx) = h.strip_prefix("*.") {
        if sfx.contains('*') {
            return Err(AllowError::Wildcard);
        }
        validate_hostname(sfx).map_err(|e| AllowError::Host(e.to_string()))?;
        return Ok(HostPattern::Suffix(sfx.to_ascii_lowercase()));
    }
    if h.contains('*') {
        return Err(AllowError::Wildcard);
    }
    validate_hostname(h).map_err(|e| AllowError::Host(e.to_string()))?;
    Ok(HostPattern::Exact(h.to_ascii_lowercase()))
}

/// A parsed allowlist.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Allowlist {
    entries: Vec<AllowEntry>,
}

impl Allowlist {
    /// Parse a list of textual entries; every invalid entry is reported with its index.
    pub fn parse<S: AsRef<str>>(raw: &[S]) -> Result<Allowlist, Vec<(usize, AllowError)>> {
        let mut entries = Vec::new();
        let mut errors = Vec::new();
        for (i, r) in raw.iter().enumerate() {
            match AllowEntry::parse(r.as_ref()) {
                Ok(e) => entries.push(e),
                Err(e) => errors.push((i, e)),
            }
        }
        if errors.is_empty() {
            Ok(Allowlist { entries })
        } else {
            Err(errors)
        }
    }

    /// An empty list: everything is denied.
    pub fn deny_all() -> Allowlist {
        Allowlist::default()
    }

    /// True when some entry permits the destination.
    pub fn permits(&self, scheme: Scheme, host: &str, port: u16, path: &str) -> bool {
        self.entries
            .iter()
            .any(|e| e.matches(scheme, host, port, path))
    }

    /// The entries.
    pub fn entries(&self) -> &[AllowEntry] {
        &self.entries
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    #[test]
    fn parsing_table() {
        let ok = [
            (
                "acme-v02.api.letsencrypt.org",
                "https://acme-v02.api.letsencrypt.org:443",
            ),
            (
                "https://Example.COM/directory/",
                "https://example.com:443/directory",
            ),
            ("*.letsencrypt.org", "https://*.letsencrypt.org:443"),
            ("tcp://smtp.example.com:587", "tcp://smtp.example.com:587"),
            ("dns://1.1.1.1", "dns://1.1.1.1:53"),
            (
                "dns://[2606:4700:4700::1111]:53",
                "dns://[2606:4700:4700::1111]:53",
            ),
            (
                "http://feeds.example.net:8080/x",
                "http://feeds.example.net:8080/x",
            ),
        ];
        for (raw, canon) in ok {
            assert_eq!(
                AllowEntry::parse(raw).map(|e| e.to_string()).as_deref(),
                Ok(canon),
                "{raw}"
            );
        }
        let bad: [(&str, AllowError); 10] = [
            ("", AllowError::Empty),
            ("ftp://example.com", AllowError::Scheme("ftp".into())),
            ("tcp://smtp.example.com", AllowError::TcpNeedsPort),
            ("https://example.com:0", AllowError::Port),
            ("https://example.com:99999", AllowError::Port),
            ("https://u:p@example.com", AllowError::Forbidden),
            ("https://example.com/a?b=1", AllowError::Forbidden),
            ("https://ex*mple.com", AllowError::Wildcard),
            ("https://example.com/a/../b", AllowError::Path),
            ("https://*.*.example.com", AllowError::Wildcard),
        ];
        for (raw, err) in bad {
            assert_eq!(AllowEntry::parse(raw).err(), Some(err), "{raw}");
        }
        assert!(matches!(
            AllowEntry::parse("localhost"),
            Err(AllowError::Host(_))
        ));
        assert!(matches!(
            AllowEntry::parse("*.com."),
            Err(AllowError::Host(_))
        ));
    }

    #[test]
    fn matching_is_by_scheme_host_port_and_path() {
        let l = Allowlist::parse(&[
            "acme.example.org/directory",
            "*.cdn.example.net",
            "tcp://smtp.example.com:587",
            "dns://9.9.9.9",
        ])
        .expect("list");
        assert!(l.permits(Scheme::Https, "acme.example.org", 443, "/directory"));
        assert!(l.permits(
            Scheme::Https,
            "ACME.example.org",
            443,
            "/directory/new-order?x=1"
        ));
        assert!(!l.permits(Scheme::Https, "acme.example.org", 443, "/directory2"));
        assert!(!l.permits(Scheme::Https, "acme.example.org", 443, "/other"));
        assert!(!l.permits(Scheme::Http, "acme.example.org", 80, "/directory"));
        assert!(!l.permits(Scheme::Https, "acme.example.org", 8443, "/directory"));
        assert!(l.permits(Scheme::Https, "cdn.example.net", 443, "/"));
        assert!(l.permits(Scheme::Https, "a.b.cdn.example.net", 443, "/x"));
        assert!(!l.permits(Scheme::Https, "evilcdn.example.net", 443, "/"));
        assert!(!l.permits(Scheme::Https, "cdn.example.net.evil.org", 443, "/"));
        assert!(l.permits(Scheme::Tcp, "smtp.example.com", 587, ""));
        assert!(!l.permits(Scheme::Tcp, "smtp.example.com", 25, ""));
        assert!(l.permits(Scheme::Dns, "9.9.9.9", 53, ""));
        assert!(l.permits(Scheme::Dns, "::ffff:9.9.9.9", 53, ""));
        assert!(!Allowlist::deny_all().permits(Scheme::Https, "acme.example.org", 443, "/"));
    }

    #[test]
    fn ambiguous_paths_never_satisfy_a_prefix_entry() {
        for p in [
            "/a/../b",
            "/a/./b",
            "/a/%2e%2e/b",
            "/a/%2E%2e/b",
            "/a%2fb",
            "/a%5cb",
            "/a//b",
            r"/a\b",
            "/a/%00",
        ] {
            assert!(path_is_ambiguous(p), "{p}");
        }
        for p in ["/a/b", "/a/b.c/", "/a/..b/c", "/a/b%20c", "/"] {
            assert!(!path_is_ambiguous(p), "{p}");
        }
        let e = AllowEntry::parse("http://x.example.org/a").expect("entry");
        assert!(e.matches(Scheme::Http, "x.example.org", 80, "/a/b"));
        assert!(!e.matches(Scheme::Http, "x.example.org", 80, "/a/../b"));
        // an entry without a prefix does not care about the path
        let any = AllowEntry::parse("http://x.example.org").expect("entry");
        assert!(any.matches(Scheme::Http, "x.example.org", 80, "/a/../b"));
    }

    #[test]
    fn list_parsing_reports_every_bad_entry_with_its_index() {
        let err = Allowlist::parse(&[
            "ok.example.com",
            "ftp://x.example.com",
            "",
            "also.ok.example.com",
        ])
        .expect_err("errors");
        assert_eq!(err.iter().map(|(i, _)| *i).collect::<Vec<_>>(), vec![1, 2]);
    }

    proptest! {
        #[test]
        fn entry_parsing_and_matching_never_panic(s in ".{0,200}", host in ".{0,80}", path in ".{0,80}") {
            if let Ok(e) = AllowEntry::parse(&s) {
                let _ = e.matches(Scheme::Https, &host, 443, &path);
                let _ = e.to_string();
            }
        }
    }
}
