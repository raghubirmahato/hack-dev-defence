//! Address policy of the SSRF-guarded client (section 2.9, T-0009 step 3).
//!
//! Only public unicast addresses may be contacted on behalf of a user-supplied URL. The classification table below covers
//! loopback, RFC 1918, CGNAT, link-local (including the cloud metadata address), multicast, unspecified, documentation,
//! IPv6 unique-local, benchmarking and reserved ranges, address-translation prefixes that embed IPv4 (NAT64, 6to4, Teredo)
//! and IPv4-mapped IPv6 (unwrapped first, so `::ffff:127.0.0.1` is loopback). HDD's own platform addresses are rejected for
//! loop prevention. Metadata, link-local, multicast, unspecified and broadcast addresses are never reachable, not even through
//! the explicit private-origin allowlist.

use std::fmt;
use std::net::IpAddr;
use std::sync::OnceLock;

use crate::net::{Cidr, canonical_ip};

/// Class of an IP address for egress decisions.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum IpClass {
    /// Globally routable unicast.
    PublicUnicast,
    /// `127.0.0.0/8`, `::1`.
    Loopback,
    /// RFC 1918.
    Private,
    /// `100.64.0.0/10`.
    CarrierGradeNat,
    /// `169.254.0.0/16`, `fe80::/10` (includes `169.254.169.254`).
    LinkLocal,
    /// Cloud metadata range `fd00:ec2::/32` (IPv6 metadata address).
    Metadata,
    /// `224.0.0.0/4`, `ff00::/8`.
    Multicast,
    /// `0.0.0.0/8`, `::`.
    Unspecified,
    /// `255.255.255.255`.
    Broadcast,
    /// RFC 5737 / RFC 3849 / RFC 9637 documentation ranges.
    Documentation,
    /// `fc00::/7`.
    UniqueLocal,
    /// `198.18.0.0/15`, `2001:2::/48`.
    Benchmark,
    /// Address translation prefixes that embed IPv4 (NAT64, 6to4, Teredo).
    Translation,
    /// Reserved, deprecated or not globally routable.
    Reserved,
}

impl IpClass {
    /// Short label used in logs.
    pub fn label(self) -> &'static str {
        match self {
            IpClass::PublicUnicast => "public_unicast",
            IpClass::Loopback => "loopback",
            IpClass::Private => "private_rfc1918",
            IpClass::CarrierGradeNat => "cgnat",
            IpClass::LinkLocal => "link_local",
            IpClass::Metadata => "metadata",
            IpClass::Multicast => "multicast",
            IpClass::Unspecified => "unspecified",
            IpClass::Broadcast => "broadcast",
            IpClass::Documentation => "documentation",
            IpClass::UniqueLocal => "unique_local",
            IpClass::Benchmark => "benchmark",
            IpClass::Translation => "translation_prefix",
            IpClass::Reserved => "reserved",
        }
    }

    /// Classes that no configuration can make reachable.
    pub fn never_reachable(self) -> bool {
        matches!(
            self,
            IpClass::LinkLocal
                | IpClass::Metadata
                | IpClass::Multicast
                | IpClass::Unspecified
                | IpClass::Broadcast
        )
    }
}

const TABLE: &[(&str, IpClass)] = &[
    // IPv4
    ("0.0.0.0/8", IpClass::Unspecified),
    ("10.0.0.0/8", IpClass::Private),
    ("100.64.0.0/10", IpClass::CarrierGradeNat),
    ("127.0.0.0/8", IpClass::Loopback),
    ("169.254.0.0/16", IpClass::LinkLocal),
    ("172.16.0.0/12", IpClass::Private),
    ("192.0.0.0/24", IpClass::Reserved),
    ("192.0.2.0/24", IpClass::Documentation),
    ("192.88.99.0/24", IpClass::Reserved),
    ("192.168.0.0/16", IpClass::Private),
    ("198.18.0.0/15", IpClass::Benchmark),
    ("198.51.100.0/24", IpClass::Documentation),
    ("203.0.113.0/24", IpClass::Documentation),
    ("224.0.0.0/4", IpClass::Multicast),
    ("240.0.0.0/4", IpClass::Reserved),
    ("255.255.255.255/32", IpClass::Broadcast),
    // cloud metadata and wire-server addresses that sit inside otherwise ordinary ranges
    ("100.100.100.200/32", IpClass::Metadata),
    ("168.63.129.16/32", IpClass::Metadata),
    ("192.0.0.192/32", IpClass::Metadata),
    // IPv6
    ("::/128", IpClass::Unspecified),
    ("::1/128", IpClass::Loopback),
    ("::/96", IpClass::Reserved),
    ("64:ff9b::/96", IpClass::Translation),
    ("64:ff9b:1::/48", IpClass::Translation),
    ("100::/64", IpClass::Reserved),
    ("2001::/32", IpClass::Translation),
    ("2001:2::/48", IpClass::Benchmark),
    ("2001:10::/28", IpClass::Reserved),
    ("2001:db8::/32", IpClass::Documentation),
    ("2002::/16", IpClass::Translation),
    ("3fff::/20", IpClass::Documentation),
    ("fc00::/7", IpClass::UniqueLocal),
    ("fd00:ec2::/32", IpClass::Metadata),
    ("fe80::/10", IpClass::LinkLocal),
    ("fec0::/10", IpClass::Reserved),
    ("ff00::/8", IpClass::Multicast),
];

fn table() -> &'static Vec<(Cidr, IpClass)> {
    static T: OnceLock<Vec<(Cidr, IpClass)>> = OnceLock::new();
    T.get_or_init(|| {
        let mut v: Vec<(Cidr, IpClass)> = TABLE
            .iter()
            .filter_map(|(c, k)| c.parse::<Cidr>().ok().map(|c| (c, *k)))
            .collect();
        // most specific prefix first, so that fd00:ec2::/32 wins over fc00::/7 and ::1 over ::/96
        v.sort_by_key(|(c, _)| std::cmp::Reverse(c.prefix()));
        v
    })
}

/// Number of entries of the classification table that parsed (guards against a typo silently dropping a range).
pub fn table_len() -> usize {
    table().len()
}

/// Number of entries written in the source table.
pub const SOURCE_TABLE_LEN: usize = TABLE.len();

/// Classify an address. IPv4-mapped IPv6 addresses are classified as their IPv4 form.
pub fn classify(ip: IpAddr) -> IpClass {
    let ip = canonical_ip(ip);
    for (cidr, class) in table() {
        if cidr.contains(ip) {
            return *class;
        }
    }
    match ip {
        IpAddr::V4(_) => IpClass::PublicUnicast,
        // outside 2000::/3 nothing is globally routable unicast
        IpAddr::V6(v6) => {
            if v6.segments().first().is_some_and(|s| s & 0xe000 == 0x2000) {
                IpClass::PublicUnicast
            } else {
                IpClass::Reserved
            }
        }
    }
}

/// True for globally routable unicast addresses.
pub fn is_public_unicast(ip: IpAddr) -> bool {
    classify(ip) == IpClass::PublicUnicast
}

/// Why an address or port was refused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SsrfDeny {
    /// The address class is not reachable.
    Class(IpClass),
    /// One of HDD's own platform addresses (loop prevention).
    PlatformAddress,
    /// The port is not on the allowlist.
    Port(u16),
    /// The scheme is not http or https.
    Scheme,
}

impl fmt::Display for SsrfDeny {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SsrfDeny::Class(c) => write!(f, "address class `{}` is not reachable", c.label()),
            SsrfDeny::PlatformAddress => f.write_str("HDD platform address (loop prevention)"),
            SsrfDeny::Port(p) => write!(f, "port {p} is not on the allowlist"),
            SsrfDeny::Scheme => f.write_str("only http and https are allowed"),
        }
    }
}

impl std::error::Error for SsrfDeny {}

/// Origin address policy (section 2.9).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SsrfPolicy {
    allowed_ports: Vec<u16>,
    platform_addrs: Vec<Cidr>,
    private_origin_allowlist: Vec<Cidr>,
}

/// Default port allowlist for origins (configurable per plan).
pub const DEFAULT_PORTS: &[u16] = &[80, 443, 8080, 8443];

impl Default for SsrfPolicy {
    fn default() -> Self {
        SsrfPolicy {
            allowed_ports: DEFAULT_PORTS.to_vec(),
            platform_addrs: Vec::new(),
            private_origin_allowlist: Vec::new(),
        }
    }
}

impl SsrfPolicy {
    /// Replace the port allowlist.
    pub fn with_ports(mut self, ports: &[u16]) -> Self {
        self.allowed_ports = ports.to_vec();
        self
    }

    /// Set HDD's own platform addresses (rejected for loop prevention).
    pub fn with_platform_addrs(mut self, addrs: Vec<Cidr>) -> Self {
        self.platform_addrs = addrs;
        self
    }

    /// Permit explicit private ranges for the operator's own sites. Refused in `saas` mode (`owner_only` is required);
    /// metadata, link-local, multicast, unspecified and broadcast stay unreachable regardless.
    pub fn with_private_origin_allowlist(
        mut self,
        cidrs: Vec<Cidr>,
        mode: crate::profile::types::DeploymentMode,
    ) -> Result<Self, &'static str> {
        if mode != crate::profile::types::DeploymentMode::OwnerOnly && !cidrs.is_empty() {
            return Err(
                "egress.private_origin_allowlist is refused unless deployment_mode is owner_only (section 2.9)",
            );
        }
        self.private_origin_allowlist = cidrs;
        Ok(self)
    }

    /// The port allowlist.
    pub fn ports(&self) -> &[u16] {
        &self.allowed_ports
    }

    /// Check a port.
    pub fn check_port(&self, port: u16) -> Result<(), SsrfDeny> {
        if self.allowed_ports.contains(&port) {
            Ok(())
        } else {
            Err(SsrfDeny::Port(port))
        }
    }

    /// Check a resolved address. Called on every resolution and every connect (DNS-rebinding defense).
    pub fn check_ip(&self, ip: IpAddr) -> Result<(), SsrfDeny> {
        let ip = canonical_ip(ip);
        let class = classify(ip);
        if class.never_reachable() {
            return Err(SsrfDeny::Class(class));
        }
        if self.platform_addrs.iter().any(|c| c.contains(ip)) {
            return Err(SsrfDeny::PlatformAddress);
        }
        if class == IpClass::PublicUnicast {
            return Ok(());
        }
        let exemptable = matches!(
            class,
            IpClass::Private | IpClass::UniqueLocal | IpClass::Loopback
        );
        if exemptable && self.private_origin_allowlist.iter().any(|c| c.contains(ip)) {
            return Ok(());
        }
        Err(SsrfDeny::Class(class))
    }
}

/// IPv4 address embedded in a translation prefix: NAT64 (`64:ff9b::/96`), 6to4 (`2002:a.b.c.d::/48`) and Teredo
/// (`2001:0::/32`, the obfuscated client address in the last 32 bits).
pub fn embedded_v4(ip: IpAddr) -> Option<std::net::Ipv4Addr> {
    let IpAddr::V6(v6) = canonical_ip(ip) else {
        return None;
    };
    let seg = v6.segments();
    let [s0, s1, s2, s3, s4, s5, s6, s7] = seg;
    let join = |hi: u16, lo: u16| std::net::Ipv4Addr::from((u32::from(hi) << 16) | u32::from(lo));
    if (s0, s1, s2, s3, s4, s5) == (0x64, 0xff9b, 0, 0, 0, 0) {
        return Some(join(s6, s7));
    }
    if s0 == 0x2002 {
        return Some(join(s1, s2));
    }
    if (s0, s1) == (0x2001, 0) {
        return Some(join(!s6, !s7));
    }
    None
}

/// Baseline applied to every egress, including allowlisted hosts: addresses nobody legitimately talks to. An IPv4 address
/// hidden inside a translation prefix is judged by the IPv4 address it stands for.
pub fn check_baseline(ip: IpAddr) -> Result<(), SsrfDeny> {
    let class = classify(ip);
    if class.never_reachable() {
        return Err(SsrfDeny::Class(class));
    }
    if class == IpClass::Translation
        && let Some(v4) = embedded_v4(ip)
    {
        let inner = classify(IpAddr::V4(v4));
        if inner.never_reachable() {
            return Err(SsrfDeny::Class(inner));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::profile::types::DeploymentMode;
    use proptest::prelude::*;

    fn ip(s: &str) -> IpAddr {
        s.parse().expect("ip literal in test")
    }

    #[test]
    fn every_table_entry_parses() {
        assert_eq!(table_len(), SOURCE_TABLE_LEN);
    }

    #[test]
    fn classification_table() {
        let cases = [
            ("8.8.8.8", IpClass::PublicUnicast),
            ("93.184.216.34", IpClass::PublicUnicast),
            ("1.1.1.1", IpClass::PublicUnicast),
            ("127.0.0.1", IpClass::Loopback),
            ("127.255.255.254", IpClass::Loopback),
            ("10.1.2.3", IpClass::Private),
            ("172.16.0.1", IpClass::Private),
            ("172.31.255.255", IpClass::Private),
            ("172.32.0.1", IpClass::PublicUnicast),
            ("192.168.1.1", IpClass::Private),
            ("100.64.0.1", IpClass::CarrierGradeNat),
            ("100.127.255.255", IpClass::CarrierGradeNat),
            ("100.128.0.1", IpClass::PublicUnicast),
            ("169.254.169.254", IpClass::LinkLocal),
            ("169.254.0.1", IpClass::LinkLocal),
            ("224.0.0.1", IpClass::Multicast),
            ("239.255.255.255", IpClass::Multicast),
            ("0.0.0.0", IpClass::Unspecified),
            ("0.1.2.3", IpClass::Unspecified),
            ("255.255.255.255", IpClass::Broadcast),
            ("240.0.0.1", IpClass::Reserved),
            ("192.0.2.1", IpClass::Documentation),
            ("198.51.100.7", IpClass::Documentation),
            ("203.0.113.200", IpClass::Documentation),
            ("198.18.0.1", IpClass::Benchmark),
            ("198.19.255.255", IpClass::Benchmark),
            ("::1", IpClass::Loopback),
            ("::", IpClass::Unspecified),
            ("fe80::1", IpClass::LinkLocal),
            ("febf::1", IpClass::LinkLocal),
            ("fc00::1", IpClass::UniqueLocal),
            ("fdff::1", IpClass::UniqueLocal),
            ("fd00:ec2::254", IpClass::Metadata),
            ("ff02::1", IpClass::Multicast),
            ("2001:db8::1", IpClass::Documentation),
            ("2606:4700:4700::1111", IpClass::PublicUnicast),
            ("2a00:1450:4001:81b::200e", IpClass::PublicUnicast),
            ("64:ff9b::7f00:1", IpClass::Translation),
            ("2002:7f00:1::1", IpClass::Translation),
            ("2001:0:4136:e378:8000:63bf:3fff:fdd2", IpClass::Translation),
            ("::10.0.0.1", IpClass::Reserved),
            ("4000::1", IpClass::Reserved),
        ];
        for (text, want) in cases {
            assert_eq!(classify(ip(text)), want, "{text}");
        }
    }

    #[test]
    fn ipv4_mapped_forms_take_the_class_of_the_embedded_address() {
        for (mapped, want) in [
            ("::ffff:127.0.0.1", IpClass::Loopback),
            ("::ffff:7f00:1", IpClass::Loopback),
            ("::ffff:169.254.169.254", IpClass::LinkLocal),
            ("::ffff:a9fe:a9fe", IpClass::LinkLocal),
            ("::ffff:10.0.0.1", IpClass::Private),
            ("::ffff:8.8.8.8", IpClass::PublicUnicast),
            ("0:0:0:0:0:ffff:192.168.0.1", IpClass::Private),
            ("::FFFF:C0A8:1", IpClass::Private),
        ] {
            assert_eq!(classify(ip(mapped)), want, "{mapped}");
        }
    }

    #[test]
    fn default_policy_accepts_only_public_unicast_on_allowed_ports() {
        let p = SsrfPolicy::default();
        assert!(p.check_ip(ip("8.8.8.8")).is_ok());
        assert!(p.check_ip(ip("2606:4700:4700::1111")).is_ok());
        for bad in [
            "127.0.0.1",
            "10.0.0.1",
            "169.254.169.254",
            "::1",
            "fd00:ec2::254",
            "::ffff:127.0.0.1",
            "100.64.1.1",
            "0.0.0.0",
            "192.0.2.1",
        ] {
            assert!(p.check_ip(ip(bad)).is_err(), "{bad}");
        }
        for port in [80, 443, 8080, 8443] {
            assert!(p.check_port(port).is_ok());
        }
        for port in [22, 25, 0, 3306, 6379, 8000, 65535] {
            assert_eq!(p.check_port(port), Err(SsrfDeny::Port(port)));
        }
    }

    #[test]
    fn platform_addresses_are_rejected_for_loop_prevention() {
        let p =
            SsrfPolicy::default().with_platform_addrs(vec!["8.8.8.8/32".parse().expect("cidr")]);
        assert_eq!(p.check_ip(ip("8.8.8.8")), Err(SsrfDeny::PlatformAddress));
        assert_eq!(
            p.check_ip(ip("::ffff:8.8.8.8")),
            Err(SsrfDeny::PlatformAddress)
        );
        assert!(p.check_ip(ip("8.8.4.4")).is_ok());
    }

    #[test]
    fn private_origin_allowlist_exempts_only_private_ranges_and_never_metadata() {
        let allow = vec![
            "10.0.0.0/8".parse().expect("cidr"),
            "169.254.0.0/16".parse().expect("cidr"),
            "127.0.0.0/8".parse().expect("cidr"),
            "fd00:ec2::/32".parse().expect("cidr"),
        ];
        let p = SsrfPolicy::default()
            .with_private_origin_allowlist(allow, DeploymentMode::OwnerOnly)
            .expect("owner_only");
        assert!(p.check_ip(ip("10.9.9.9")).is_ok());
        assert!(p.check_ip(ip("127.0.0.1")).is_ok());
        assert!(p.check_ip(ip("::ffff:10.1.1.1")).is_ok());
        assert_eq!(
            p.check_ip(ip("169.254.169.254")),
            Err(SsrfDeny::Class(IpClass::LinkLocal)),
            "metadata is never reachable"
        );
        assert_eq!(
            p.check_ip(ip("fd00:ec2::254")),
            Err(SsrfDeny::Class(IpClass::Metadata))
        );
        assert!(p.check_ip(ip("192.168.0.1")).is_err(), "not listed");
    }

    #[test]
    fn private_origin_allowlist_is_refused_in_saas_mode() {
        let r = SsrfPolicy::default().with_private_origin_allowlist(
            vec!["10.0.0.0/8".parse().expect("cidr")],
            DeploymentMode::Saas,
        );
        assert!(r.is_err());
        assert!(
            SsrfPolicy::default()
                .with_private_origin_allowlist(vec![], DeploymentMode::Saas)
                .is_ok()
        );
    }

    #[test]
    fn embedded_ipv4_is_extracted_from_translation_prefixes() {
        for (text, want) in [
            ("64:ff9b::a9fe:a9fe", Some("169.254.169.254")),
            ("64:ff9b::7f00:1", Some("127.0.0.1")),
            ("2002:a9fe:a9fe::1", Some("169.254.169.254")),
            // Teredo stores the client address inverted in the last 32 bits: 169.254.169.254 -> 0x5601 0x5601
            (
                "2001:0:4136:e378:8000:63bf:5601:5601",
                Some("169.254.169.254"),
            ),
            ("2606:4700:4700::1111", None),
            ("::ffff:10.0.0.1", None),
        ] {
            let got = embedded_v4(ip(text)).map(|v| v.to_string());
            assert_eq!(got.as_deref(), want, "{text}");
        }
    }

    #[test]
    fn extra_metadata_addresses_in_ordinary_ranges() {
        for addr in ["100.100.100.200", "168.63.129.16", "192.0.0.192"] {
            assert_eq!(classify(ip(addr)), IpClass::Metadata, "{addr}");
            assert!(check_baseline(ip(addr)).is_err(), "{addr}");
            assert!(SsrfPolicy::default().check_ip(ip(addr)).is_err(), "{addr}");
        }
        assert_eq!(classify(ip("100.100.100.201")), IpClass::CarrierGradeNat);
    }

    #[test]
    fn baseline_blocks_metadata_even_for_allowlisted_hosts() {
        assert!(check_baseline(ip("169.254.169.254")).is_err());
        assert!(check_baseline(ip("fd00:ec2::254")).is_err());
        assert!(check_baseline(ip("224.0.0.1")).is_err());
        assert!(
            check_baseline(ip("127.0.0.1")).is_ok(),
            "loopback stays reachable for lab and tests"
        );
        assert!(check_baseline(ip("8.8.8.8")).is_ok());
    }

    /// Different spellings of one IPv6 address (expanded, compressed, upper case, mapped dotted/hex).
    fn v6_spellings(segs: [u16; 8]) -> Vec<String> {
        let expanded = segs
            .iter()
            .map(|s| format!("{s:04x}"))
            .collect::<Vec<_>>()
            .join(":");
        let short = segs
            .iter()
            .map(|s| format!("{s:x}"))
            .collect::<Vec<_>>()
            .join(":");
        vec![
            expanded.clone(),
            expanded.to_uppercase(),
            short,
            std::net::Ipv6Addr::from(segs).to_string(),
        ]
    }

    proptest! {
        #[test]
        fn classification_is_invariant_under_textual_representation(segs in proptest::array::uniform8(any::<u16>())) {
            let addr = std::net::Ipv6Addr::from(segs);
            let want = classify(IpAddr::V6(addr));
            for text in v6_spellings(segs) {
                let parsed: IpAddr = text.parse().expect("every spelling parses");
                prop_assert_eq!(classify(parsed), want, "{}", text);
            }
        }

        #[test]
        fn mapped_ipv4_classifies_like_plain_ipv4(a in any::<u32>()) {
            let v4 = std::net::Ipv4Addr::from(a);
            let mapped = v4.to_ipv6_mapped();
            prop_assert_eq!(classify(IpAddr::V6(mapped)), classify(IpAddr::V4(v4)));
            let dotted: IpAddr = format!("::ffff:{v4}").parse().expect("mapped dotted");
            prop_assert_eq!(classify(dotted), classify(IpAddr::V4(v4)));
        }

        #[test]
        fn policy_never_accepts_a_never_reachable_class_ipv4(a in any::<u32>()) {
            let addr = IpAddr::V4(std::net::Ipv4Addr::from(a));
            let policy = SsrfPolicy::default()
                .with_private_origin_allowlist(vec!["0.0.0.0/0".parse().expect("cidr")], DeploymentMode::OwnerOnly)
                .expect("owner_only");
            if classify(addr).never_reachable() {
                prop_assert!(policy.check_ip(addr).is_err());
                prop_assert!(check_baseline(addr).is_err());
            }
        }

        #[test]
        fn policy_never_accepts_a_never_reachable_class(a in any::<u128>()) {
            let addr = IpAddr::V6(std::net::Ipv6Addr::from(a));
            let policy = SsrfPolicy::default()
                .with_private_origin_allowlist(vec!["::/0".parse().expect("cidr"), "0.0.0.0/0".parse().expect("cidr")], DeploymentMode::OwnerOnly)
                .expect("owner_only");
            if classify(addr).never_reachable() {
                prop_assert!(policy.check_ip(addr).is_err());
            }
        }
    }
}
