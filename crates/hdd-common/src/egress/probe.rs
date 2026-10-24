//! Reachability probes for `hddctl preflight` (T-0006 step 5): a TCP connect (SMTP relay) and a DNS lookup (nameserver names).
//!
//! These are the only network actions of the profile checks, they are explicit, and they go through the same policy as every
//! other outbound call: the destination must be on the allowlist (`tcp://host:port` for a connect, `dns://resolver` for the
//! resolver that answers), addresses pass the baseline (no metadata, link-local, multicast), the kill switch is honored, and
//! each denial is logged.

use std::net::{IpAddr, SocketAddr};
use std::time::Duration;

use super::allow::{Allowlist, Scheme};
use super::client::{Connector, EgressError, TcpConnector};
use super::denylog::DenyLog;
use super::killswitch::KillSwitch;
use super::resolver::{Resolution, Resolver, UdpResolver};
use super::ssrf::check_baseline;

/// The `dns://` resolver endpoints of an allowlist (IP literal entries only), for building a [`UdpResolver`].
pub fn dns_servers(allow: &Allowlist) -> Vec<SocketAddr> {
    allow
        .entries()
        .iter()
        .filter(|e| e.scheme == Scheme::Dns)
        .filter_map(|e| match &e.host {
            super::allow::HostPattern::Ip(ip) => Some(SocketAddr::new(*ip, e.port)),
            _ => None,
        })
        .collect()
}

/// Build the resolver used for probes: the allowlisted `dns://` servers when present, otherwise `None`.
pub fn probe_resolver(allow: &Allowlist, timeout: Duration) -> Option<UdpResolver> {
    let servers = dns_servers(allow);
    if servers.is_empty() {
        None
    } else {
        UdpResolver::new(servers, allow, timeout).ok()
    }
}

/// What a probe needs besides its target.
pub struct ProbeContext<'a> {
    /// The egress allowlist.
    pub allow: &'a Allowlist,
    /// Resolver for host names.
    pub resolver: &'a dyn Resolver,
    /// Connect timeout.
    pub timeout: Duration,
    /// Deny log.
    pub deny: &'a DenyLog,
    /// Kill switch, when the tool has one.
    pub kill: Option<&'a KillSwitch>,
    /// Who is asking (for the deny log).
    pub caller: &'a str,
}

/// Connect to `host:port` and close the connection. The destination must be permitted as `tcp://host:port`.
pub async fn tcp_probe(
    cx: &ProbeContext<'_>,
    host: &str,
    port: u16,
) -> Result<SocketAddr, EgressError> {
    let dest = format!("tcp://{host}:{port}");
    if let Some(k) = cx.kill {
        k.check().map_err(|_| EgressError::Aborted)?;
    }
    if !cx.allow.permits(Scheme::Tcp, host, port, "") {
        cx.deny
            .record(&dest, "not_on_allowlist", cx.caller, "allowlist");
        return Err(EgressError::Denied {
            reason: "not_on_allowlist".into(),
            destination: dest,
        });
    }
    let addrs: Vec<IpAddr> = match host.parse::<IpAddr>() {
        Ok(ip) => vec![ip],
        Err(_) => {
            abortable(cx.kill, async {
                cx.resolver
                    .resolve(host)
                    .await
                    .map_err(|e| EgressError::Resolve(e.to_string()))
            })
            .await?
            .addrs
        }
    };
    if addrs.is_empty() {
        return Err(EgressError::Resolve("no addresses".into()));
    }
    for ip in &addrs {
        if let Err(e) = check_baseline(*ip) {
            let reason = format!(
                "address_class:{}",
                match e {
                    super::ssrf::SsrfDeny::Class(c) => c.label(),
                    _ => "other",
                }
            );
            cx.deny.record(&dest, &reason, cx.caller, "allowlist");
            return Err(EgressError::Denied {
                reason,
                destination: dest,
            });
        }
    }
    let target = SocketAddr::new(
        addrs.first().copied().unwrap_or(IpAddr::from([0, 0, 0, 0])),
        port,
    );
    abortable(cx.kill, async {
        match tokio::time::timeout(cx.timeout, TcpConnector.connect(target)).await {
            Ok(Ok(_stream)) => Ok(target),
            Ok(Err(e)) => Err(EgressError::Connect(e.to_string())),
            Err(_) => Err(EgressError::Timeout("connect")),
        }
    })
    .await
}

/// Resolve `host` with the given resolver (for nameserver names use [`probe_resolver`]).
pub async fn dns_probe(
    resolver: &dyn Resolver,
    host: &str,
    kill: Option<&KillSwitch>,
) -> Result<Resolution, EgressError> {
    if let Some(k) = kill {
        k.check().map_err(|_| EgressError::Aborted)?;
    }
    abortable(kill, async {
        resolver
            .resolve(host)
            .await
            .map_err(|e| EgressError::Resolve(e.to_string()))
    })
    .await
}

/// Run `fut` but stop as soon as the kill switch trips.
async fn abortable<T>(
    kill: Option<&KillSwitch>,
    fut: impl std::future::Future<Output = Result<T, EgressError>>,
) -> Result<T, EgressError> {
    match kill {
        Some(k) => {
            tokio::select! {
                r = fut => r,
                () = k.tripped() => Err(EgressError::Aborted),
            }
        }
        None => fut.await,
    }
}

#[cfg(test)]
mod tests {
    use super::super::resolver::SystemResolver;
    use super::super::resolver::testutil::*;
    use super::*;
    use std::collections::BTreeMap;
    use std::net::Ipv4Addr;
    use tokio::net::TcpListener;

    fn log() -> DenyLog {
        DenyLog::new(Box::new(|_| {}), 100, Duration::from_secs(60))
    }

    fn cx<'a>(
        allow: &'a Allowlist,
        deny: &'a DenyLog,
        kill: Option<&'a KillSwitch>,
        secs: u64,
    ) -> ProbeContext<'a> {
        ProbeContext {
            allow,
            resolver: &SystemResolver,
            timeout: Duration::from_secs(secs),
            deny,
            kill,
            caller: "preflight",
        }
    }

    #[tokio::test]
    async fn tcp_probe_connects_only_to_allowlisted_endpoints() {
        let l = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let port = l.local_addr().expect("addr").port();
        let accept = tokio::spawn(async move { l.accept().await.is_ok() });
        let allow = Allowlist::parse(&[format!("tcp://127.0.0.1:{port}")]).expect("allow");
        let d = log();
        let got = tcp_probe(&cx(&allow, &d, None, 2), "127.0.0.1", port)
            .await
            .expect("connect");
        assert_eq!(got.port(), port);
        assert!(
            accept.await.expect("task"),
            "the listener accepted the probe connection"
        );

        let other = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let other_port = other.local_addr().expect("addr").port();
        let err = tcp_probe(&cx(&allow, &d, None, 1), "127.0.0.1", other_port)
            .await
            .expect_err("denied");
        assert!(matches!(err, EgressError::Denied { .. }));
        assert!(
            tokio::time::timeout(Duration::from_millis(200), other.accept())
                .await
                .is_err(),
            "no connection to the unlisted port"
        );
        assert_eq!(d.total(), 1);
    }

    #[tokio::test]
    async fn tcp_probe_refuses_metadata_even_when_listed_and_honors_the_kill_switch() {
        let allow = Allowlist::parse(&["tcp://169.254.169.254:80"]).expect("allow");
        let d = log();
        let err = tcp_probe(&cx(&allow, &d, None, 1), "169.254.169.254", 80)
            .await
            .expect_err("denied");
        assert!(
            matches!(&err, EgressError::Denied { reason, .. } if reason == "address_class:link_local"),
            "{err}"
        );

        let path = std::env::temp_dir().join(format!("hdd-probe-kill-{}", std::process::id()));
        std::fs::write(&path, b"x").expect("touch");
        let ks = KillSwitch::new(&path, Duration::from_millis(1));
        assert!(ks.poll_now());
        let allow2 = Allowlist::parse(&["tcp://127.0.0.1:9"]).expect("allow");
        assert!(matches!(
            tcp_probe(&cx(&allow2, &d, Some(&ks), 1), "127.0.0.1", 9).await,
            Err(EgressError::Aborted)
        ));
        let _ = std::fs::remove_file(&path);
    }

    #[tokio::test]
    async fn dns_probe_resolves_nameserver_names_through_an_allowlisted_resolver() {
        let mut zone = BTreeMap::new();
        zone.insert(
            "ns1.hdd-ops.dev".to_owned(),
            vec![Rec::A(Ipv4Addr::new(198, 51, 100, 20))],
        );
        let dns = spawn_dns(zone).await;
        let allow = Allowlist::parse(&[format!("dns://127.0.0.1:{}", dns.port())]).expect("allow");
        assert_eq!(dns_servers(&allow), vec![dns]);
        let r = probe_resolver(&allow, Duration::from_secs(2)).expect("resolver");
        let ok = dns_probe(&r, "ns1.hdd-ops.dev", None)
            .await
            .expect("resolves");
        assert_eq!(ok.addrs, vec![IpAddr::from([198, 51, 100, 20])]);
        let missing = dns_probe(&r, "ns9.hdd-ops.dev", None)
            .await
            .expect_err("nxdomain");
        assert!(matches!(missing, EgressError::Resolve(m) if m.contains("NXDOMAIN")));
        assert!(
            probe_resolver(&Allowlist::deny_all(), Duration::from_secs(1)).is_none(),
            "without a dns:// entry there is no resolver, hence UNVERIFIED rather than a lookup through the system"
        );
    }
}
