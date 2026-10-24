//! `TargetGuard` (T-0009 step 4): attack-shaped traffic may only go to the targets derived from the live profile.
//!
//! * live mode: `test_hostname` and `sandbox_hostname`;
//! * lab mode: the lab host and addresses inside `lab.cidr` (live names are then refused, and in live mode lab addresses are
//!   refused).
//!
//! The guard checks the literal target, and after resolution it also checks that no CNAME in the chain points to a host outside
//! the set (a delegated or hijacked name that now points at a third party), and, when the profile names the platform addresses,
//! that the target resolves only to them. A resolver that cannot report CNAMEs makes a live-mode check fail closed.

use std::collections::BTreeSet;
use std::fmt;
use std::net::IpAddr;

use crate::net::{Cidr, canonical_ip};
use crate::profile::Profile;

use super::resolver::Resolver;
use super::ssrf::{check_baseline, is_public_unicast};

/// Which target set applies.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TargetMode {
    /// The operator's live profile: test and sandbox host names.
    Live,
    /// The closed lab: lab addresses only.
    Lab,
}

/// Why a target was refused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TargetDenied {
    /// The host or address is not in the derived set.
    NotInSet(String),
    /// A CNAME in the chain points outside the set.
    CnameOutside {
        /// The queried target.
        target: String,
        /// The offending canonical name.
        cname: String,
    },
    /// The target resolved to an address outside the allowed addresses.
    AddressOutside {
        /// The queried target.
        target: String,
        /// The offending address.
        addr: IpAddr,
    },
    /// The resolver cannot report CNAME chains, so the check cannot be completed (fail closed).
    CnameBlind,
    /// Resolution failed.
    Resolution(String),
    /// Lab mode was requested but the profile has no usable lab.
    LabNotConfigured,
    /// The target set derived from the profile is empty.
    EmptySet,
    /// A platform address in the profile does not parse (a typo must not silently shrink the check).
    BadPlatformAddress(String),
}

impl fmt::Display for TargetDenied {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            TargetDenied::NotInSet(t) => write!(f, "target `{t}` is not in the set derived from the profile"),
            TargetDenied::CnameOutside { target, cname } => write!(f, "target `{target}` has a CNAME to `{cname}`, which is outside the allowed set"),
            TargetDenied::AddressOutside { target, addr } => write!(f, "target `{target}` resolves to {addr}, which is outside the allowed addresses"),
            TargetDenied::CnameBlind => f.write_str("the resolver cannot report CNAME chains; refusing to treat the target as safe"),
            TargetDenied::Resolution(e) => write!(f, "cannot resolve target: {e}"),
            TargetDenied::LabNotConfigured => f.write_str("lab mode requires lab.enabled with a host and CIDR in the profile"),
            TargetDenied::BadPlatformAddress(a) => write!(f, "platform address `{a}` in the profile is not an IP address or CIDR"),
            TargetDenied::EmptySet => f.write_str("the profile yields no allowed targets (test_hostname / sandbox_hostname are empty)"),
        }
    }
}

impl std::error::Error for TargetDenied {}

/// The target guard.
#[derive(Debug, Clone)]
pub struct TargetGuard {
    mode: TargetMode,
    hosts: BTreeSet<String>,
    cidrs: Vec<Cidr>,
    platform: Vec<Cidr>,
}

impl TargetGuard {
    /// Derive the allowed set from the profile.
    pub fn from_profile(p: &Profile, mode: TargetMode) -> Result<TargetGuard, TargetDenied> {
        let mut hosts = BTreeSet::new();
        let mut cidrs = Vec::new();
        let mut platform = Vec::new();
        match mode {
            TargetMode::Live => {
                for h in [&p.test_hostname, &p.sandbox_hostname] {
                    let h = h.trim().trim_end_matches('.').to_ascii_lowercase();
                    if !h.is_empty() {
                        hosts.insert(h);
                    }
                }
                for ip in p
                    .platform
                    .public_ipv4
                    .iter()
                    .chain(p.platform.public_ipv6.iter())
                {
                    match ip.parse::<Cidr>() {
                        Ok(c) => platform.push(c),
                        // a typo must not silently shrink the check to "anything goes"
                        Err(_) => return Err(TargetDenied::BadPlatformAddress(ip.clone())),
                    }
                }
            }
            TargetMode::Lab => {
                if !p.lab.enabled || p.lab.cidr.trim().is_empty() {
                    return Err(TargetDenied::LabNotConfigured);
                }
                let cidr = p
                    .lab
                    .cidr
                    .trim()
                    .parse::<Cidr>()
                    .map_err(|_| TargetDenied::LabNotConfigured)?;
                cidrs.push(cidr);
                let h = p.lab.host.trim().trim_end_matches('.').to_ascii_lowercase();
                if !h.is_empty() {
                    hosts.insert(h);
                }
            }
        }
        if hosts.is_empty() && cidrs.is_empty() {
            return Err(TargetDenied::EmptySet);
        }
        Ok(TargetGuard {
            mode,
            hosts,
            cidrs,
            platform,
        })
    }

    /// The mode.
    pub fn mode(&self) -> TargetMode {
        self.mode
    }

    /// The allowed host names.
    pub fn hosts(&self) -> impl Iterator<Item = &str> {
        self.hosts.iter().map(String::as_str)
    }

    fn host_allowed(&self, host: &str) -> bool {
        let h = host.trim().trim_end_matches('.').to_ascii_lowercase();
        if let Ok(ip) = h.parse::<IpAddr>() {
            return self.cidrs.iter().any(|c| c.contains(ip))
                || (self.mode == TargetMode::Lab && self.hosts.contains(&ip.to_string()));
        }
        self.hosts.contains(&h)
    }

    /// Check a target host (name or IP literal) without resolving it.
    pub fn check_host(&self, host: &str) -> Result<(), TargetDenied> {
        if self.host_allowed(host) {
            Ok(())
        } else {
            Err(TargetDenied::NotInSet(host.to_owned()))
        }
    }

    /// Check a target and everything it resolves to. Returns the validated addresses.
    pub async fn check_resolved(
        &self,
        host: &str,
        resolver: &dyn Resolver,
    ) -> Result<Vec<IpAddr>, TargetDenied> {
        self.check_host(host)?;
        let h = host.trim().trim_end_matches('.').to_ascii_lowercase();
        if let Ok(ip) = h.parse::<IpAddr>() {
            return Ok(vec![ip]);
        }
        if self.mode == TargetMode::Live && !resolver.sees_cnames() {
            return Err(TargetDenied::CnameBlind);
        }
        let res = resolver
            .resolve(&h)
            .await
            .map_err(|e| TargetDenied::Resolution(e.to_string()))?;
        for c in &res.cnames {
            if !self.host_allowed(c) {
                return Err(TargetDenied::CnameOutside {
                    target: h.clone(),
                    cname: c.clone(),
                });
            }
        }
        if res.addrs.is_empty() {
            return Err(TargetDenied::Resolution("no addresses".into()));
        }
        for ip in &res.addrs {
            let ip = canonical_ip(*ip);
            let ok = check_baseline(ip).is_ok()
                && match self.mode {
                    // with the platform addresses configured they are the only acceptable answers; without them the answer must
                    // at least be a public unicast address (never loopback, private or metadata space)
                    TargetMode::Live => {
                        if self.platform.is_empty() {
                            is_public_unicast(ip)
                        } else {
                            self.platform.iter().any(|c| c.contains(ip))
                        }
                    }
                    TargetMode::Lab => self.cidrs.iter().any(|c| c.contains(ip)),
                };
            if !ok {
                return Err(TargetDenied::AddressOutside {
                    target: h.clone(),
                    addr: ip,
                });
            }
        }
        Ok(res.addrs)
    }
}

#[cfg(test)]
#[allow(
    clippy::field_reassign_with_default,
    reason = "tests build profiles by overriding single fields"
)]
mod tests {
    use super::super::allow::Allowlist;
    use super::super::resolver::testutil::*;
    use super::super::resolver::{Resolver, UdpResolver};
    use super::*;
    use std::collections::BTreeMap;
    use std::net::Ipv4Addr;
    use std::time::Duration;

    fn profile() -> Profile {
        let mut p = Profile::default();
        p.test_hostname = "hddtest.shop-site.org".into();
        p.sandbox_hostname = "hddsbx.shop-site.org".into();
        p.platform.public_ipv4 = vec!["198.51.100.20".into()];
        p
    }

    #[test]
    fn the_set_is_derived_from_the_profile() {
        let g = TargetGuard::from_profile(&profile(), TargetMode::Live).expect("guard");
        assert_eq!(
            g.hosts().collect::<Vec<_>>(),
            vec!["hddsbx.shop-site.org", "hddtest.shop-site.org"]
        );
        assert!(g.check_host("hddtest.shop-site.org").is_ok());
        assert!(g.check_host("HDDSBX.shop-site.org.").is_ok());
        for bad in [
            "shop-site.org",
            "www.shop-site.org",
            "evil.test",
            "hddtest.shop-site.org.evil.net",
            "198.51.100.20",
            "127.0.0.1",
        ] {
            assert_eq!(
                g.check_host(bad),
                Err(TargetDenied::NotInSet(bad.to_owned())),
                "{bad}"
            );
        }
    }

    #[test]
    fn an_empty_profile_yields_no_targets() {
        assert_eq!(
            TargetGuard::from_profile(&Profile::default(), TargetMode::Live).err(),
            Some(TargetDenied::EmptySet)
        );
    }

    #[test]
    fn lab_mode_needs_a_lab_and_refuses_live_names() {
        assert_eq!(
            TargetGuard::from_profile(&profile(), TargetMode::Lab).err(),
            Some(TargetDenied::LabNotConfigured)
        );
        let mut p = profile();
        p.lab.enabled = true;
        p.lab.cidr = "10.99.0.0/24".into();
        p.lab.host = "vulnlab.lab.internal".into();
        let g = TargetGuard::from_profile(&p, TargetMode::Lab).expect("lab guard");
        assert!(g.check_host("10.99.0.7").is_ok());
        assert!(g.check_host("vulnlab.lab.internal").is_ok());
        assert!(g.check_host("10.98.0.7").is_err());
        assert!(
            g.check_host("hddtest.shop-site.org").is_err(),
            "live names are not lab targets"
        );
        let live = TargetGuard::from_profile(&p, TargetMode::Live).expect("live guard");
        assert!(
            live.check_host("10.99.0.7").is_err(),
            "lab addresses are not live targets"
        );
    }

    #[tokio::test]
    async fn a4_a_cname_to_another_host_is_rejected_using_a_real_dns_responder() {
        let mut zone = BTreeMap::new();
        zone.insert(
            "hddtest.shop-site.org".to_owned(),
            vec![Rec::A(Ipv4Addr::new(198, 51, 100, 20))],
        );
        zone.insert(
            "hddsbx.shop-site.org".to_owned(),
            vec![Rec::Cname("tenant-42.third-party.example".to_owned())],
        );
        zone.insert(
            "tenant-42.third-party.example".to_owned(),
            vec![Rec::A(Ipv4Addr::new(203, 0, 113, 9))],
        );
        let dns = spawn_dns(zone).await;
        let allow =
            Allowlist::parse(&[format!("dns://127.0.0.1:{}", dns.port())]).expect("allowlist");
        let r = UdpResolver::new(vec![dns], &allow, Duration::from_secs(2)).expect("resolver");
        let g = TargetGuard::from_profile(&profile(), TargetMode::Live).expect("guard");
        assert_eq!(
            g.check_resolved("hddtest.shop-site.org", &r).await,
            Ok(vec!["198.51.100.20".parse::<IpAddr>().expect("ip")])
        );
        assert_eq!(
            g.check_resolved("hddsbx.shop-site.org", &r).await,
            Err(TargetDenied::CnameOutside {
                target: "hddsbx.shop-site.org".into(),
                cname: "tenant-42.third-party.example".into()
            })
        );
        assert!(
            matches!(
                g.check_resolved("www.shop-site.org", &r).await,
                Err(TargetDenied::NotInSet(_))
            ),
            "not in the set: refused before any query"
        );
    }

    #[tokio::test]
    async fn a_target_that_resolves_outside_the_platform_addresses_is_rejected() {
        let mut zone = BTreeMap::new();
        zone.insert(
            "hddtest.shop-site.org".to_owned(),
            vec![Rec::A(Ipv4Addr::new(203, 0, 113, 77))],
        );
        let dns = spawn_dns(zone).await;
        let allow =
            Allowlist::parse(&[format!("dns://127.0.0.1:{}", dns.port())]).expect("allowlist");
        let r = UdpResolver::new(vec![dns], &allow, Duration::from_secs(2)).expect("resolver");
        let g = TargetGuard::from_profile(&profile(), TargetMode::Live).expect("guard");
        assert!(matches!(
            g.check_resolved("hddtest.shop-site.org", &r).await,
            Err(TargetDenied::AddressOutside { .. })
        ));
    }

    #[tokio::test]
    async fn without_platform_addresses_only_public_unicast_answers_are_accepted() {
        let mut p = profile();
        p.platform.public_ipv4.clear();
        let g = TargetGuard::from_profile(&p, TargetMode::Live).expect("guard");
        for (bad, why) in [
            ("127.0.0.1", "loopback"),
            ("10.0.0.5", "private"),
            ("169.254.169.254", "metadata"),
        ] {
            let r = CnameAware(Scripted::new(&[(
                "hddtest.shop-site.org",
                vec![vec![bad.parse().expect("ip")]],
            )]));
            assert!(
                matches!(
                    g.check_resolved("hddtest.shop-site.org", &r).await,
                    Err(TargetDenied::AddressOutside { .. })
                ),
                "{why}"
            );
        }
        let ok = CnameAware(Scripted::new(&[(
            "hddtest.shop-site.org",
            vec![vec!["93.184.216.34".parse().expect("ip")]],
        )]));
        assert!(g.check_resolved("hddtest.shop-site.org", &ok).await.is_ok());
        let empty = CnameAware(Scripted::new(&[("hddtest.shop-site.org", vec![vec![]])]));
        assert!(
            matches!(
                g.check_resolved("hddtest.shop-site.org", &empty).await,
                Err(TargetDenied::Resolution(_))
            ),
            "an empty answer is not a pass"
        );
    }

    #[test]
    fn a_mistyped_platform_address_is_an_error_not_a_weaker_check() {
        let mut p = profile();
        p.platform.public_ipv4 = vec!["198.51.100.20".into(), "198.51.100.2O".into()];
        assert_eq!(
            TargetGuard::from_profile(&p, TargetMode::Live).err(),
            Some(TargetDenied::BadPlatformAddress("198.51.100.2O".into()))
        );
    }

    /// A scripted resolver that claims to see CNAMEs (the answers carry none).
    struct CnameAware(Scripted);

    impl Resolver for CnameAware {
        fn resolve<'a>(
            &'a self,
            host: &'a str,
        ) -> super::super::resolver::BoxFuture<
            'a,
            std::io::Result<super::super::resolver::Resolution>,
        > {
            self.0.resolve(host)
        }
        fn sees_cnames(&self) -> bool {
            true
        }
    }

    #[tokio::test]
    async fn a_resolver_that_cannot_see_cnames_fails_closed_in_live_mode() {
        let g = TargetGuard::from_profile(&profile(), TargetMode::Live).expect("guard");
        let blind = Scripted::new(&[(
            "hddtest.shop-site.org",
            vec![vec!["198.51.100.20".parse().expect("ip")]],
        )]);
        assert!(!blind.sees_cnames());
        assert_eq!(
            g.check_resolved("hddtest.shop-site.org", &blind).await,
            Err(TargetDenied::CnameBlind)
        );
    }

    #[tokio::test]
    async fn lab_resolution_must_stay_inside_the_lab_cidr() {
        let mut p = profile();
        p.lab.enabled = true;
        p.lab.cidr = "10.99.0.0/24".into();
        p.lab.host = "vulnlab.lab.internal".into();
        let g = TargetGuard::from_profile(&p, TargetMode::Lab).expect("lab guard");
        let inside = Scripted::new(&[(
            "vulnlab.lab.internal",
            vec![vec!["10.99.0.5".parse().expect("ip")]],
        )]);
        assert!(
            g.check_resolved("vulnlab.lab.internal", &inside)
                .await
                .is_ok()
        );
        let outside = Scripted::new(&[(
            "vulnlab.lab.internal",
            vec![vec!["8.8.8.8".parse().expect("ip")]],
        )]);
        assert!(matches!(
            g.check_resolved("vulnlab.lab.internal", &outside).await,
            Err(TargetDenied::AddressOutside { .. })
        ));
    }
}
