//! Name resolution for the egress client: a trait (so tests can script rebinding sequences), the system resolver, and a small
//! stub resolver that speaks DNS over UDP to explicitly allowlisted servers and reports CNAME chains (needed by `TargetGuard`).
//!
//! The wire code is bounds-checked everywhere (`get`, never indexing), limits name length and pointer jumps, and ignores
//! answer records whose owner is not on the CNAME chain of the question (a basic defense against spoofed extra records).

use std::future::Future;
use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::pin::Pin;
use std::time::Duration;

use tokio::net::UdpSocket;

use super::allow::{Allowlist, Scheme};

/// A boxed future (the resolver trait is object safe).
pub type BoxFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

/// Result of resolving a name.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Resolution {
    /// Addresses in the order the resolver returned them (deduplicated).
    pub addrs: Vec<IpAddr>,
    /// Canonical-name chain followed from the queried name (lower case, no trailing dot), empty when none or unknown.
    pub cnames: Vec<String>,
}

/// Resolves host names.
pub trait Resolver: Send + Sync {
    /// Resolve `host` (a DNS name, never an IP literal).
    fn resolve<'a>(&'a self, host: &'a str) -> BoxFuture<'a, io::Result<Resolution>>;

    /// True when [`Resolution::cnames`] is filled in. The system resolver cannot see CNAMEs.
    fn sees_cnames(&self) -> bool {
        false
    }
}

/// The operating system's resolver (`getaddrinfo`). Does not report CNAME chains.
#[derive(Debug, Clone, Copy, Default)]
pub struct SystemResolver;

impl Resolver for SystemResolver {
    fn resolve<'a>(&'a self, host: &'a str) -> BoxFuture<'a, io::Result<Resolution>> {
        Box::pin(async move {
            let mut addrs: Vec<IpAddr> = Vec::new();
            // an absolute name (trailing dot) keeps getaddrinfo from applying search-domain suffixes
            let absolute = if host.ends_with('.') {
                host.to_owned()
            } else {
                format!("{host}.")
            };
            for sa in tokio::net::lookup_host((absolute.as_str(), 0)).await? {
                if !addrs.contains(&sa.ip()) {
                    addrs.push(sa.ip());
                }
            }
            Ok(Resolution {
                addrs,
                cnames: Vec::new(),
            })
        })
    }
}

/// A resolver that resolves nothing: for callers that only ever pass IP literals and must fail rather than fall back to the
/// system resolver.
#[derive(Debug, Clone, Copy, Default)]
pub struct NoResolver;

impl Resolver for NoResolver {
    fn resolve<'a>(&'a self, _host: &'a str) -> BoxFuture<'a, io::Result<Resolution>> {
        Box::pin(async move {
            Err(io::Error::new(
                io::ErrorKind::NotFound,
                "no resolver is configured for names",
            ))
        })
    }
}

/// DNS wire format helpers.
pub mod wire {
    use super::*;

    /// Record type A.
    pub const TYPE_A: u16 = 1;
    /// Record type CNAME.
    pub const TYPE_CNAME: u16 = 5;
    /// Record type AAAA.
    pub const TYPE_AAAA: u16 = 28;
    const MAX_NAME: usize = 255;
    const MAX_JUMPS: usize = 16;

    /// Why a response was rejected.
    #[derive(Debug, Clone, PartialEq, Eq)]
    pub enum DnsError {
        /// Shorter than a header or a record claims more bytes than exist.
        Truncated,
        /// Not a response, wrong id, or the question does not match.
        Mismatch,
        /// A compressed name loops or is too long.
        BadName,
    }

    /// Parsed response.
    #[derive(Debug, Clone, PartialEq, Eq, Default)]
    pub struct Parsed {
        /// Response code (0 = no error, 3 = NXDOMAIN).
        pub rcode: u8,
        /// The TC bit.
        pub truncated: bool,
        /// Addresses of the queried type that belong to the question's CNAME chain.
        pub addrs: Vec<IpAddr>,
        /// CNAME chain from the question name.
        pub cnames: Vec<String>,
    }

    /// Build a query for `name` and `qtype` (class IN, recursion desired). `None` when the name cannot be encoded.
    pub fn build_query(id: u16, name: &str, qtype: u16) -> Option<Vec<u8>> {
        let mut out = Vec::with_capacity(32 + name.len());
        out.extend_from_slice(&id.to_be_bytes());
        out.extend_from_slice(&[0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);
        let trimmed = name.trim_end_matches('.');
        if trimmed.is_empty() || trimmed.len() > MAX_NAME - 2 {
            return None;
        }
        for label in trimmed.split('.') {
            let bytes = label.as_bytes();
            if bytes.is_empty()
                || bytes.len() > 63
                || !bytes
                    .iter()
                    .all(|b| b.is_ascii_alphanumeric() || *b == b'-' || *b == b'_')
            {
                return None;
            }
            out.push(u8::try_from(bytes.len()).ok()?);
            out.extend_from_slice(bytes);
        }
        out.push(0);
        out.extend_from_slice(&qtype.to_be_bytes());
        out.extend_from_slice(&1u16.to_be_bytes());
        Some(out)
    }

    fn u16_at(buf: &[u8], at: usize) -> Option<u16> {
        let b = buf.get(at..at.checked_add(2)?)?;
        Some(u16::from_be_bytes([*b.first()?, *b.get(1)?]))
    }

    /// Read a possibly compressed name at `at`; returns the lower-case dotted name and the offset after the name field.
    pub fn read_name(buf: &[u8], at: usize) -> Result<(String, usize), DnsError> {
        let mut name = String::new();
        let mut pos = at;
        let mut next_after: Option<usize> = None;
        let mut jumps = 0;
        loop {
            let len = *buf.get(pos).ok_or(DnsError::Truncated)?;
            match len & 0xC0 {
                0x00 => {
                    if len == 0 {
                        pos += 1;
                        break;
                    }
                    let l = usize::from(len);
                    let label = buf.get(pos + 1..pos + 1 + l).ok_or(DnsError::Truncated)?;
                    if !name.is_empty() {
                        name.push('.');
                    }
                    for b in label {
                        // only host-name characters are accepted: this keeps control sequences out of messages and a literal dot
                        // inside a label (which would be indistinguishable from two labels) out of the name
                        if !(b.is_ascii_alphanumeric() || *b == b'-' || *b == b'_') {
                            return Err(DnsError::BadName);
                        }
                        name.push(char::from(b.to_ascii_lowercase()));
                    }
                    if name.len() > MAX_NAME {
                        return Err(DnsError::BadName);
                    }
                    pos += 1 + l;
                }
                0xC0 => {
                    let second = *buf.get(pos + 1).ok_or(DnsError::Truncated)?;
                    let target = (usize::from(len & 0x3F) << 8) | usize::from(second);
                    if next_after.is_none() {
                        next_after = Some(pos + 2);
                    }
                    jumps += 1;
                    if jumps > MAX_JUMPS {
                        return Err(DnsError::BadName);
                    }
                    pos = target;
                }
                _ => return Err(DnsError::BadName),
            }
        }
        Ok((name, next_after.unwrap_or(pos)))
    }

    /// Parse a response to the query (`id`, `qname`, `qtype`).
    pub fn parse_response(
        buf: &[u8],
        id: u16,
        qname: &str,
        qtype: u16,
    ) -> Result<Parsed, DnsError> {
        if buf.len() < 12 {
            return Err(DnsError::Truncated);
        }
        let flags = u16_at(buf, 2).ok_or(DnsError::Truncated)?;
        if u16_at(buf, 0) != Some(id) || flags & 0x8000 == 0 {
            return Err(DnsError::Mismatch);
        }
        let qd = u16_at(buf, 4).ok_or(DnsError::Truncated)?;
        let an = u16_at(buf, 6).ok_or(DnsError::Truncated)?;
        let mut parsed = Parsed {
            rcode: u8::try_from(flags & 0x000F).unwrap_or(15),
            truncated: flags & 0x0200 != 0,
            ..Parsed::default()
        };
        let mut pos = 12usize;
        let want = qname.trim_end_matches('.').to_ascii_lowercase();
        if qd != 1 {
            return Err(DnsError::Mismatch);
        }
        let (qn, after) = read_name(buf, pos)?;
        let qt = u16_at(buf, after).ok_or(DnsError::Truncated)?;
        if qn != want || qt != qtype {
            return Err(DnsError::Mismatch);
        }
        pos = after + 4;
        if pos > buf.len() {
            return Err(DnsError::Truncated);
        }
        struct Rr {
            owner: String,
            rtype: u16,
            rdata_at: usize,
            rdlen: usize,
        }
        let mut rrs: Vec<Rr> = Vec::new();
        for _ in 0..an.min(64) {
            let (owner, after_name) = read_name(buf, pos)?;
            let rtype = u16_at(buf, after_name).ok_or(DnsError::Truncated)?;
            let rdlen = usize::from(u16_at(buf, after_name + 8).ok_or(DnsError::Truncated)?);
            let rdata_at = after_name + 10;
            if rdata_at + rdlen > buf.len() {
                return Err(DnsError::Truncated);
            }
            rrs.push(Rr {
                owner,
                rtype,
                rdata_at,
                rdlen,
            });
            pos = rdata_at + rdlen;
        }
        let mut chain_names = vec![want];
        for _ in 0..MAX_JUMPS {
            let mut grew = false;
            for rr in rrs.iter().filter(|r| r.rtype == TYPE_CNAME) {
                if chain_names.contains(&rr.owner) {
                    let (target, _) = read_name(buf, rr.rdata_at)?;
                    if !chain_names.contains(&target) {
                        chain_names.push(target.clone());
                        parsed.cnames.push(target);
                        grew = true;
                    }
                }
            }
            if !grew {
                break;
            }
        }
        for rr in &rrs {
            if !chain_names.contains(&rr.owner) {
                continue;
            }
            let data = buf
                .get(rr.rdata_at..rr.rdata_at + rr.rdlen)
                .ok_or(DnsError::Truncated)?;
            if rr.rtype == TYPE_A
                && qtype == TYPE_A
                && let Ok(b) = <[u8; 4]>::try_from(data)
            {
                parsed.addrs.push(IpAddr::V4(Ipv4Addr::from(b)));
            } else if rr.rtype == TYPE_AAAA
                && qtype == TYPE_AAAA
                && let Ok(b) = <[u8; 16]>::try_from(data)
            {
                parsed.addrs.push(IpAddr::V6(Ipv6Addr::from(b)));
            }
        }
        Ok(parsed)
    }
}

/// A stub resolver that asks explicitly listed DNS servers over UDP. Every server must be permitted by a `dns://` entry of the
/// egress allowlist (class `dns_resolution`); the constructor refuses others.
#[derive(Debug, Clone)]
pub struct UdpResolver {
    servers: Vec<SocketAddr>,
    timeout: Duration,
}

impl UdpResolver {
    /// Build a resolver; fails with the first server that the allowlist does not permit.
    pub fn new(
        servers: Vec<SocketAddr>,
        allow: &Allowlist,
        timeout: Duration,
    ) -> Result<Self, SocketAddr> {
        for s in &servers {
            if !allow.permits(Scheme::Dns, &s.ip().to_string(), s.port(), "") {
                return Err(*s);
            }
        }
        Ok(UdpResolver { servers, timeout })
    }

    async fn ask(&self, server: SocketAddr, name: &str, qtype: u16) -> io::Result<wire::Parsed> {
        let mut idb = [0u8; 2];
        getrandom::fill(&mut idb).map_err(|e| io::Error::other(e.to_string()))?;
        let id = u16::from_be_bytes(idb);
        let query = wire::build_query(id, name, qtype)
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "name cannot be encoded"))?;
        let bind: SocketAddr = if server.is_ipv4() {
            SocketAddr::from(([0, 0, 0, 0], 0))
        } else {
            SocketAddr::from(([0u16; 8], 0))
        };
        let sock = UdpSocket::bind(bind).await?;
        sock.connect(server).await?;
        sock.send(&query).await?;
        let mut buf = vec![0u8; 4096];
        let n = tokio::time::timeout(self.timeout, sock.recv(&mut buf))
            .await
            .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "dns timeout"))??;
        let parsed =
            wire::parse_response(buf.get(..n).unwrap_or(&[]), id, name, qtype).map_err(|e| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("bad dns response: {e:?}"),
                )
            })?;
        if parsed.truncated {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "dns response truncated (TCP fallback not implemented)",
            ));
        }
        match parsed.rcode {
            0 => Ok(parsed),
            3 => Err(io::Error::new(io::ErrorKind::NotFound, "NXDOMAIN")),
            c => Err(io::Error::other(format!("dns rcode {c}"))),
        }
    }
}

impl Resolver for UdpResolver {
    fn resolve<'a>(&'a self, host: &'a str) -> BoxFuture<'a, io::Result<Resolution>> {
        Box::pin(async move {
            let mut last_err = io::Error::new(io::ErrorKind::NotFound, "no dns server configured");
            for server in &self.servers {
                let a = self.ask(*server, host, wire::TYPE_A).await;
                let aaaa = self.ask(*server, host, wire::TYPE_AAAA).await;
                match (a, aaaa) {
                    (Err(e), Err(_)) => last_err = e,
                    (a, aaaa) => {
                        let mut out = Resolution::default();
                        for p in [a, aaaa].into_iter().flatten() {
                            for ip in p.addrs {
                                if !out.addrs.contains(&ip) {
                                    out.addrs.push(ip);
                                }
                            }
                            for c in p.cnames {
                                if !out.cnames.contains(&c) {
                                    out.cnames.push(c);
                                }
                            }
                        }
                        return Ok(out);
                    }
                }
            }
            Err(last_err)
        })
    }

    fn sees_cnames(&self) -> bool {
        true
    }
}

#[cfg(test)]
pub(crate) mod testutil {
    //! A real local DNS responder over UDP plus scripted resolvers, for the egress tests.

    use super::*;
    use std::collections::BTreeMap;
    use std::sync::Arc;
    use std::sync::Mutex;

    /// One record the test responder can serve.
    #[derive(Clone, Debug)]
    pub enum Rec {
        A(Ipv4Addr),
        Aaaa(Ipv6Addr),
        Cname(String),
    }

    fn encode_name(name: &str) -> Vec<u8> {
        let mut out = Vec::new();
        for l in name.trim_end_matches('.').split('.') {
            out.push(u8::try_from(l.len()).unwrap_or(0));
            out.extend_from_slice(l.as_bytes());
        }
        out.push(0);
        out
    }

    /// Spawn a UDP responder on 127.0.0.1; returns its address. Unknown names get NXDOMAIN.
    pub async fn spawn_dns(zone: BTreeMap<String, Vec<Rec>>) -> SocketAddr {
        let sock = UdpSocket::bind("127.0.0.1:0").await.expect("bind dns");
        let addr = sock.local_addr().expect("addr");
        tokio::spawn(async move {
            let mut buf = vec![0u8; 1500];
            loop {
                let Ok((n, peer)) = sock.recv_from(&mut buf).await else {
                    return;
                };
                let q = buf.get(..n).unwrap_or(&[]).to_vec();
                let Ok((qname, after)) = wire::read_name(&q, 12) else {
                    continue;
                };
                let qtype = u16::from_be_bytes([
                    q.get(after).copied().unwrap_or(0),
                    q.get(after + 1).copied().unwrap_or(0),
                ]);
                let recs = zone.get(&qname);
                let mut resp = Vec::new();
                resp.extend_from_slice(q.get(0..2).unwrap_or(&[0, 0]));
                let rcode: u8 = if recs.is_some() { 0 } else { 3 };
                resp.extend_from_slice(&[0x81, 0x80 | rcode]);
                resp.extend_from_slice(&[0, 1]);
                let mut answers: Vec<u8> = Vec::new();
                let mut count: u16 = 0;
                let mut owner = qname.clone();
                // follow CNAME chain in the zone, then answer records of the requested type
                for _ in 0..8 {
                    let Some(rs) = zone.get(&owner) else { break };
                    if let Some(Rec::Cname(target)) = rs.iter().find(|r| matches!(r, Rec::Cname(_)))
                    {
                        answers.extend_from_slice(&encode_name(&owner));
                        answers.extend_from_slice(&[0, 5, 0, 1, 0, 0, 0, 60]);
                        let rd = encode_name(target);
                        answers
                            .extend_from_slice(&u16::try_from(rd.len()).unwrap_or(0).to_be_bytes());
                        answers.extend_from_slice(&rd);
                        count += 1;
                        owner = target.clone();
                        continue;
                    }
                    for r in rs {
                        match (r, qtype) {
                            (Rec::A(ip), 1) => {
                                answers.extend_from_slice(&encode_name(&owner));
                                answers.extend_from_slice(&[0, 1, 0, 1, 0, 0, 0, 60, 0, 4]);
                                answers.extend_from_slice(&ip.octets());
                                count += 1;
                            }
                            (Rec::Aaaa(ip), 28) => {
                                answers.extend_from_slice(&encode_name(&owner));
                                answers.extend_from_slice(&[0, 28, 0, 1, 0, 0, 0, 60, 0, 16]);
                                answers.extend_from_slice(&ip.octets());
                                count += 1;
                            }
                            _ => {}
                        }
                    }
                    break;
                }
                resp.extend_from_slice(&count.to_be_bytes());
                resp.extend_from_slice(&[0, 0, 0, 0]);
                resp.extend_from_slice(q.get(12..after + 4).unwrap_or(&[]));
                resp.extend_from_slice(&answers);
                let _ = sock.send_to(&resp, peer).await;
            }
        });
        addr
    }

    /// A resolver that answers from a script: each call to `resolve` pops the next answer for the host (the last answer repeats).
    pub struct Scripted {
        script: Mutex<BTreeMap<String, Vec<Vec<IpAddr>>>>,
        pub calls: Arc<Mutex<Vec<String>>>,
    }

    impl Scripted {
        pub fn new(entries: &[(&str, Vec<Vec<IpAddr>>)]) -> Self {
            Scripted {
                script: Mutex::new(
                    entries
                        .iter()
                        .map(|(h, a)| ((*h).to_owned(), a.clone()))
                        .collect(),
                ),
                calls: Arc::new(Mutex::new(Vec::new())),
            }
        }
    }

    impl Resolver for Scripted {
        fn resolve<'a>(&'a self, host: &'a str) -> BoxFuture<'a, io::Result<Resolution>> {
            Box::pin(async move {
                self.calls
                    .lock()
                    .unwrap_or_else(|p| p.into_inner())
                    .push(host.to_owned());
                let mut script = self.script.lock().unwrap_or_else(|p| p.into_inner());
                let Some(seq) = script.get_mut(host) else {
                    return Err(io::Error::new(io::ErrorKind::NotFound, "unknown host"));
                };
                let addrs = if seq.len() > 1 {
                    seq.remove(0)
                } else {
                    seq.first().cloned().unwrap_or_default()
                };
                Ok(Resolution {
                    addrs,
                    cnames: Vec::new(),
                })
            })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::testutil::*;
    use super::*;
    use proptest::prelude::*;
    use std::collections::BTreeMap;

    fn zone() -> BTreeMap<String, Vec<Rec>> {
        let mut z = BTreeMap::new();
        z.insert(
            "direct.test.example".to_owned(),
            vec![
                Rec::A(Ipv4Addr::new(192, 0, 2, 10)),
                Rec::Aaaa("2001:db8::10".parse().expect("v6")),
            ],
        );
        z.insert(
            "alias.test.example".to_owned(),
            vec![Rec::Cname("hop.test.example".to_owned())],
        );
        z.insert(
            "hop.test.example".to_owned(),
            vec![Rec::Cname("final.third-party.example".to_owned())],
        );
        z.insert(
            "final.third-party.example".to_owned(),
            vec![Rec::A(Ipv4Addr::new(198, 51, 100, 7))],
        );
        z
    }

    #[test]
    fn query_building_validates_names() {
        assert!(wire::build_query(1, "example.com", wire::TYPE_A).is_some());
        assert!(wire::build_query(1, "example.com.", wire::TYPE_AAAA).is_some());
        for bad in ["", ".", "a..b", &"a".repeat(64), "sp ace.com", "ü.com"] {
            assert!(wire::build_query(1, bad, wire::TYPE_A).is_none(), "{bad}");
        }
        let q = wire::build_query(0xabcd, "a.bc", wire::TYPE_A).expect("query");
        assert_eq!(q.get(..2), Some(&[0xab, 0xcd][..]));
        assert_eq!(
            q.get(12..),
            Some(&[1, b'a', 2, b'b', b'c', 0, 0, 1, 0, 1][..])
        );
    }

    #[tokio::test]
    async fn udp_resolver_talks_to_a_real_local_responder_and_reports_the_cname_chain() {
        let dns = spawn_dns(zone()).await;
        let allow =
            Allowlist::parse(&[format!("dns://127.0.0.1:{}", dns.port())]).expect("allowlist");
        let r =
            UdpResolver::new(vec![dns], &allow, Duration::from_secs(2)).expect("allowed server");
        let direct = r.resolve("direct.test.example").await.expect("resolve");
        assert_eq!(direct.addrs.len(), 2);
        assert!(
            direct
                .addrs
                .contains(&"192.0.2.10".parse::<IpAddr>().expect("ip"))
        );
        assert!(direct.cnames.is_empty());
        let alias = r.resolve("alias.test.example").await.expect("resolve");
        assert_eq!(
            alias.cnames,
            vec![
                "hop.test.example".to_owned(),
                "final.third-party.example".to_owned()
            ]
        );
        assert_eq!(
            alias.addrs,
            vec!["198.51.100.7".parse::<IpAddr>().expect("ip")]
        );
        let nx = r
            .resolve("missing.test.example")
            .await
            .expect_err("nxdomain");
        assert_eq!(nx.kind(), io::ErrorKind::NotFound);
        assert!(r.sees_cnames());
    }

    #[tokio::test]
    async fn udp_resolver_refuses_servers_the_allowlist_does_not_permit() {
        let dns = spawn_dns(zone()).await;
        let allow = Allowlist::parse(&["dns://127.0.0.1:1"]).expect("allowlist");
        assert_eq!(
            UdpResolver::new(vec![dns], &allow, Duration::from_secs(1)).err(),
            Some(dns)
        );
        assert!(
            UdpResolver::new(vec![dns], &Allowlist::deny_all(), Duration::from_secs(1)).is_err()
        );
    }

    #[tokio::test]
    async fn a_silent_server_times_out() {
        let sock = UdpSocket::bind("127.0.0.1:0").await.expect("bind");
        let addr = sock.local_addr().expect("addr");
        let allow =
            Allowlist::parse(&[format!("dns://127.0.0.1:{}", addr.port())]).expect("allowlist");
        let r = UdpResolver::new(vec![addr], &allow, Duration::from_millis(150)).expect("allowed");
        let err = r.resolve("direct.test.example").await.expect_err("timeout");
        assert_eq!(err.kind(), io::ErrorKind::TimedOut);
    }

    #[test]
    fn records_for_names_outside_the_chain_are_ignored() {
        // response to "a.test" containing an A record for "evil.test" (a spoofed extra record)
        let mut r = vec![0x12, 0x34, 0x81, 0x80, 0, 1, 0, 1, 0, 0, 0, 0];
        r.extend_from_slice(&[1, b'a', 4, b't', b'e', b's', b't', 0, 0, 1, 0, 1]);
        r.extend_from_slice(&[
            4, b'e', b'v', b'i', b'l', 4, b't', b'e', b's', b't', 0, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4,
            6, 6, 6, 6,
        ]);
        let p = wire::parse_response(&r, 0x1234, "a.test", wire::TYPE_A).expect("parse");
        assert!(p.addrs.is_empty());
    }

    #[test]
    fn mismatches_and_bad_names_are_rejected() {
        let good = {
            let mut r = vec![0x12, 0x34, 0x81, 0x80, 0, 1, 0, 0, 0, 0, 0, 0];
            r.extend_from_slice(&[1, b'a', 4, b't', b'e', b's', b't', 0, 0, 1, 0, 1]);
            r
        };
        assert!(wire::parse_response(&good, 0x1234, "a.test", wire::TYPE_A).is_ok());
        assert_eq!(
            wire::parse_response(&good, 0x9999, "a.test", wire::TYPE_A),
            Err(wire::DnsError::Mismatch),
            "wrong id"
        );
        assert_eq!(
            wire::parse_response(&good, 0x1234, "b.test", wire::TYPE_A),
            Err(wire::DnsError::Mismatch),
            "wrong question"
        );
        assert_eq!(
            wire::parse_response(&good, 0x1234, "a.test", wire::TYPE_AAAA),
            Err(wire::DnsError::Mismatch),
            "wrong type"
        );
        let mut not_response = good.clone();
        not_response[2] = 0x01;
        assert_eq!(
            wire::parse_response(&not_response, 0x1234, "a.test", wire::TYPE_A),
            Err(wire::DnsError::Mismatch)
        );
        assert_eq!(
            wire::parse_response(&good[..8], 0x1234, "a.test", wire::TYPE_A),
            Err(wire::DnsError::Truncated)
        );
        // pointer loop
        let looped = [0xC0, 0x00];
        assert_eq!(wire::read_name(&looped, 0), Err(wire::DnsError::BadName));
        // reserved label type
        assert_eq!(
            wire::read_name(&[0x80, 0x01, 0], 0),
            Err(wire::DnsError::BadName)
        );
    }

    proptest! {
        #[test]
        fn parsing_arbitrary_bytes_never_panics(bytes in proptest::collection::vec(any::<u8>(), 0..600), id in any::<u16>()) {
            let _ = wire::parse_response(&bytes, id, "direct.test.example", wire::TYPE_A);
            let _ = wire::parse_response(&bytes, id, "direct.test.example", wire::TYPE_AAAA);
            let _ = wire::read_name(&bytes, 12);
        }

        #[test]
        fn parsing_mutated_valid_responses_never_panics(flip in 0usize..80, val in any::<u8>()) {
            let mut r = vec![0x12, 0x34, 0x81, 0x80, 0, 1, 0, 2, 0, 0, 0, 0];
            r.extend_from_slice(&[1, b'a', 4, b't', b'e', b's', b't', 0, 0, 1, 0, 1]);
            r.extend_from_slice(&[0xC0, 12, 0, 5, 0, 1, 0, 0, 0, 60, 0, 6, 3, b'x', b'y', b'z', 0xC0, 14]);
            r.extend_from_slice(&[0xC0, 12, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4, 1, 2, 3, 4]);
            if let Some(b) = r.get_mut(flip) { *b = val; }
            let _ = wire::parse_response(&r, 0x1234, "a.test", wire::TYPE_A);
        }
    }
}
