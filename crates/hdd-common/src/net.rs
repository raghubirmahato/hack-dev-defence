//! Small, panic-free network value types shared by the profile validator and the egress guard: CIDR blocks, host names
//! and e-mail address syntax. Parsing is strict (no whitespace, no leading zeros, no implicit prefixes) so that two
//! textual spellings of one address cannot be treated differently by two components.

use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::str::FromStr;

/// A CIDR block (`192.0.2.0/24`, `2001:db8::/32`). A bare address is a host route (/32 or /128).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Cidr {
    network: IpAddr,
    prefix: u8,
}

/// Why a CIDR failed to parse.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CidrError {
    /// Empty string.
    Empty,
    /// Contains whitespace.
    Whitespace,
    /// The address part is not a valid IPv4/IPv6 address.
    Address,
    /// The prefix is not a number, has a sign or leading zeros.
    Prefix,
    /// The prefix exceeds 32 (IPv4) or 128 (IPv6).
    PrefixRange,
}

impl fmt::Display for CidrError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            CidrError::Empty => "empty CIDR",
            CidrError::Whitespace => "CIDR contains whitespace",
            CidrError::Address => "not a valid IPv4 or IPv6 address",
            CidrError::Prefix => "prefix length is not a plain decimal number",
            CidrError::PrefixRange => {
                "prefix length is larger than the address family allows (32 for IPv4, 128 for IPv6)"
            }
        })
    }
}

impl std::error::Error for CidrError {}

/// Unwrap an IPv4-mapped IPv6 address (`::ffff:a.b.c.d`) to its IPv4 form; other addresses are returned unchanged.
pub fn canonical_ip(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V6(v6) => v6.to_ipv4_mapped().map_or(IpAddr::V6(v6), IpAddr::V4),
        v4 => v4,
    }
}

fn mask_v4(addr: Ipv4Addr, prefix: u8) -> Ipv4Addr {
    let bits = u32::from(addr);
    let mask = if prefix == 0 {
        0
    } else {
        u32::MAX << (32 - u32::from(prefix.min(32)))
    };
    Ipv4Addr::from(bits & mask)
}

fn mask_v6(addr: Ipv6Addr, prefix: u8) -> Ipv6Addr {
    let bits = u128::from(addr);
    let mask = if prefix == 0 {
        0
    } else {
        u128::MAX << (128 - u32::from(prefix.min(128)))
    };
    Ipv6Addr::from(bits & mask)
}

impl Cidr {
    /// Build from an address and prefix; the host bits are cleared.
    pub fn new(addr: IpAddr, prefix: u8) -> Result<Self, CidrError> {
        let max = if addr.is_ipv4() { 32 } else { 128 };
        if prefix > max {
            return Err(CidrError::PrefixRange);
        }
        let network = match addr {
            IpAddr::V4(a) => IpAddr::V4(mask_v4(a, prefix)),
            IpAddr::V6(a) => IpAddr::V6(mask_v6(a, prefix)),
        };
        Ok(Cidr { network, prefix })
    }

    /// The network address (host bits cleared).
    pub fn network(&self) -> IpAddr {
        self.network
    }

    /// The prefix length.
    pub fn prefix(&self) -> u8 {
        self.prefix
    }

    /// True when `ip` lies inside the block. IPv4-mapped IPv6 addresses are compared as IPv4.
    pub fn contains(&self, ip: IpAddr) -> bool {
        match (self.network, canonical_ip(ip)) {
            (IpAddr::V4(n), IpAddr::V4(a)) => mask_v4(a, self.prefix) == n,
            (IpAddr::V6(n), IpAddr::V6(a)) => mask_v6(a, self.prefix) == n,
            _ => false,
        }
    }
}

impl FromStr for Cidr {
    type Err = CidrError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if s.is_empty() {
            return Err(CidrError::Empty);
        }
        if s.chars().any(char::is_whitespace) {
            return Err(CidrError::Whitespace);
        }
        let (addr_s, prefix_s) = match s.split_once('/') {
            Some((a, p)) => (a, Some(p)),
            None => (s, None),
        };
        let addr: IpAddr = addr_s.parse().map_err(|_| CidrError::Address)?;
        let prefix = match prefix_s {
            None => {
                if addr.is_ipv4() {
                    32
                } else {
                    128
                }
            }
            Some(p) => {
                if p.is_empty()
                    || !p.chars().all(|c| c.is_ascii_digit())
                    || (p.len() > 1 && p.starts_with('0'))
                {
                    return Err(CidrError::Prefix);
                }
                p.parse::<u8>().map_err(|_| CidrError::PrefixRange)?
            }
        };
        Cidr::new(addr, prefix)
    }
}

impl fmt::Display for Cidr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}/{}", self.network, self.prefix)
    }
}

/// Why a host name is rejected.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HostnameError {
    /// Empty.
    Empty,
    /// Longer than 253 characters.
    TooLong,
    /// A label is empty, longer than 63 characters or starts/ends with a hyphen.
    Label,
    /// Contains a character other than letters, digits, hyphen and dot.
    Character,
    /// A single label (no dot); a fully qualified name is required.
    SingleLabel,
    /// The last label is numeric only (looks like an IP address).
    NumericTld,
}

impl fmt::Display for HostnameError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            HostnameError::Empty => "empty host name",
            HostnameError::TooLong => "host name is longer than 253 characters",
            HostnameError::Label => "a label is empty, longer than 63 characters, or starts or ends with a hyphen",
            HostnameError::Character => "host names may contain only ASCII letters, digits, hyphens and dots (use the xn-- form for internationalized names)",
            HostnameError::SingleLabel => "a fully qualified host name with at least two labels is required",
            HostnameError::NumericTld => "the last label must not be numeric only (this looks like an IP address)",
        })
    }
}

impl std::error::Error for HostnameError {}

/// Validate a fully qualified host name (RFC 1123, ASCII, no trailing dot).
pub fn validate_hostname(h: &str) -> Result<(), HostnameError> {
    if h.is_empty() {
        return Err(HostnameError::Empty);
    }
    if h.len() > 253 {
        return Err(HostnameError::TooLong);
    }
    if !h
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '.')
    {
        return Err(HostnameError::Character);
    }
    let labels: Vec<&str> = h.split('.').collect();
    for l in &labels {
        if l.is_empty() || l.len() > 63 || l.starts_with('-') || l.ends_with('-') {
            return Err(HostnameError::Label);
        }
    }
    if labels.len() < 2 {
        return Err(HostnameError::SingleLabel);
    }
    if labels
        .last()
        .is_some_and(|l| l.chars().all(|c| c.is_ascii_digit()))
    {
        return Err(HostnameError::NumericTld);
    }
    Ok(())
}

/// True when `child` is a strict subdomain of `parent` (case-insensitive, both already syntactically valid).
pub fn is_strict_subdomain(child: &str, parent: &str) -> bool {
    let c = child.to_ascii_lowercase();
    let p = parent.to_ascii_lowercase();
    c.len() > p.len() + 1
        && c.ends_with(&p)
        && c.as_bytes().get(c.len() - p.len() - 1) == Some(&b'.')
}

/// Minimal e-mail syntax check: one `@`, a non-empty local part without spaces, and a valid host name after it.
pub fn validate_email(e: &str) -> bool {
    let Some((local, domain)) = e.split_once('@') else {
        return false;
    };
    !local.is_empty()
        && local.len() <= 64
        && !local
            .chars()
            .any(|c| c.is_whitespace() || c == '@' || c.is_control())
        && validate_hostname(domain).is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    #[test]
    fn cidr_parsing_table() {
        let ok = [
            ("192.0.2.0/24", "192.0.2.0/24"),
            ("192.0.2.77/24", "192.0.2.0/24"),
            ("10.1.2.3", "10.1.2.3/32"),
            ("2001:db8::1/32", "2001:db8::/32"),
            ("::1", "::1/128"),
            ("0.0.0.0/0", "0.0.0.0/0"),
        ];
        for (input, canon) in ok {
            assert_eq!(
                input.parse::<Cidr>().map(|c| c.to_string()).as_deref(),
                Ok(canon),
                "{input}"
            );
        }
        let bad: [(&str, CidrError); 9] = [
            ("", CidrError::Empty),
            (" 10.0.0.0/8", CidrError::Whitespace),
            ("10.0.0.0/8 ", CidrError::Whitespace),
            ("10.0.0/8", CidrError::Address),
            ("10.0.0.0/", CidrError::Prefix),
            ("10.0.0.0/08", CidrError::Prefix),
            ("10.0.0.0/+8", CidrError::Prefix),
            ("10.0.0.0/33", CidrError::PrefixRange),
            ("::/129", CidrError::PrefixRange),
        ];
        for (input, err) in bad {
            assert_eq!(input.parse::<Cidr>().err(), Some(err), "{input}");
        }
        assert_eq!("256.1.1.1".parse::<Cidr>().err(), Some(CidrError::Address));
        assert_eq!(
            "010.0.0.1/8".parse::<Cidr>().err(),
            Some(CidrError::Address)
        );
    }

    #[test]
    fn containment_includes_mapped_addresses_and_edges() {
        let c: Cidr = "10.0.0.0/8".parse().expect("cidr");
        assert!(c.contains("10.255.255.255".parse().expect("ip")));
        assert!(!c.contains("11.0.0.0".parse().expect("ip")));
        assert!(c.contains("::ffff:10.1.2.3".parse().expect("ip")));
        assert!(!c.contains("2001:db8::1".parse().expect("ip")));
        let v6: Cidr = "2001:db8::/32".parse().expect("cidr");
        assert!(v6.contains("2001:db8:ffff::1".parse().expect("ip")));
        assert!(!v6.contains("2001:db9::1".parse().expect("ip")));
        let all: Cidr = "0.0.0.0/0".parse().expect("cidr");
        assert!(all.contains("203.0.113.9".parse().expect("ip")));
    }

    #[test]
    fn hostname_table() {
        for ok in [
            "example.com",
            "a-b.example.co.uk",
            "xn--bcher-kva.example",
            "A.B.example.com",
            "1a.example.org",
        ] {
            assert_eq!(validate_hostname(ok), Ok(()), "{ok}");
        }
        let bad = [
            ("", HostnameError::Empty),
            ("localhost", HostnameError::SingleLabel),
            ("-a.example.com", HostnameError::Label),
            ("a-.example.com", HostnameError::Label),
            ("a..example.com", HostnameError::Label),
            ("example.com.", HostnameError::Label),
            ("exa mple.com", HostnameError::Character),
            ("bücher.example", HostnameError::Character),
            ("192.168.1.1", HostnameError::NumericTld),
        ];
        for (input, err) in bad {
            assert_eq!(validate_hostname(input), Err(err), "{input}");
        }
        assert_eq!(
            validate_hostname(&format!("{}.com", "a".repeat(64))),
            Err(HostnameError::Label)
        );
        assert_eq!(
            validate_hostname(&format!("{}.com", ["a"; 130].join("."))),
            Err(HostnameError::TooLong)
        );
    }

    #[test]
    fn subdomain_relation_is_strict_and_label_aligned() {
        assert!(is_strict_subdomain("hddtest.example.com", "example.com"));
        assert!(is_strict_subdomain("A.B.Example.COM", "example.com"));
        assert!(!is_strict_subdomain("example.com", "example.com"));
        assert!(!is_strict_subdomain("badexample.com", "example.com"));
        assert!(!is_strict_subdomain("example.com.evil.net", "example.com"));
    }

    #[test]
    fn email_syntax() {
        assert!(validate_email("ops@example.com"));
        for bad in [
            "",
            "ops",
            "ops@",
            "@example.com",
            "ops@example",
            "o ps@example.com",
            "a@b@example.com",
        ] {
            assert!(!validate_email(bad), "{bad}");
        }
    }

    proptest! {
        #[test]
        fn cidr_parsing_never_panics(s in ".{0,60}") {
            let _ = s.parse::<Cidr>();
        }

        #[test]
        fn hostname_validation_never_panics(s in ".{0,300}") {
            let _ = validate_hostname(&s);
            let _ = is_strict_subdomain(&s, "example.com");
            let _ = validate_email(&s);
        }

        #[test]
        fn display_round_trips_for_valid_cidrs(a in any::<u32>(), p in 0u8..=32) {
            let c = Cidr::new(IpAddr::V4(Ipv4Addr::from(a)), p).expect("valid");
            prop_assert_eq!(c.to_string().parse::<Cidr>(), Ok(c));
            prop_assert!(c.contains(c.network()));
        }

        #[test]
        fn v6_display_round_trips(a in any::<u128>(), p in 0u8..=128) {
            let c = Cidr::new(IpAddr::V6(Ipv6Addr::from(a)), p).expect("valid");
            prop_assert_eq!(c.to_string().parse::<Cidr>(), Ok(c));
        }
    }
}
