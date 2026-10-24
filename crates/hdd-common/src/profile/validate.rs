//! The pure profile validator (T-0006 step 4). `validate` performs no I/O: network probes belong to `hddctl preflight`.
//!
//! Every rule ends as PASS, FAIL, WARN (advisory), NOT APPLICABLE or UNVERIFIED(reason) (section 0.4) and carries the
//! exact remediation text. Reason codes: `capability_not_supplied`, `human_step_pending`, `environment_unsupported`,
//! `stage_not_reached`.

use std::collections::BTreeSet;
use std::fmt;
use std::net::IpAddr;

use crate::egress::allow::{Allowlist, Scheme};
use crate::net::{Cidr, canonical_ip, is_strict_subdomain, validate_email, validate_hostname};

use super::capability::Capability;
use super::types::{
    AcmeDirectory, AdminExposure, BreachCheck, DdosMode, DeployMode, DnsTopology, LifecycleStage,
    LockdownState, LoopbackIdentity, Profile, RuntimeProfile, SignupMode, SmtpTls, TlsVerifyMode,
    TunnelProvider,
};

/// Reason code of an UNVERIFIED result (section 0.4).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Reason {
    /// The operator has not supplied the capability or data.
    CapabilityNotSupplied,
    /// A human step is pending.
    HumanStepPending,
    /// The environment cannot run the check.
    EnvironmentUnsupported,
    /// A later stage of the build owns the check.
    StageNotReached,
}

impl Reason {
    /// Code as written in reports.
    pub fn code(self) -> &'static str {
        match self {
            Reason::CapabilityNotSupplied => "capability_not_supplied",
            Reason::HumanStepPending => "human_step_pending",
            Reason::EnvironmentUnsupported => "environment_unsupported",
            Reason::StageNotReached => "stage_not_reached",
        }
    }
}

/// Result of one rule.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Status {
    /// The rule holds.
    Pass,
    /// The rule is violated; the profile cannot be used as is.
    Fail,
    /// Advisory: allowed, but the operator should look.
    Warn,
    /// Cannot be decided from the profile alone.
    Unverified(Reason),
    /// Does not apply to this runtime profile.
    NotApplicable,
}

impl fmt::Display for Status {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Status::Pass => f.write_str("PASS"),
            Status::Fail => f.write_str("FAIL"),
            Status::Warn => f.write_str("WARN"),
            Status::Unverified(r) => write!(f, "UNVERIFIED({})", r.code()),
            Status::NotApplicable => f.write_str("N/A"),
        }
    }
}

/// One line of the report.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Finding {
    /// Rule id such as `PROF-REQUIRED`.
    pub rule: &'static str,
    /// Result.
    pub status: Status,
    /// Dotted field path the finding is about (may be empty).
    pub field: String,
    /// What was found.
    pub message: String,
    /// What the operator does about it (empty for PASS).
    pub remediation: String,
}

/// Facts the pure validator cannot discover itself.
#[derive(Debug, Clone, Copy, Default)]
pub struct Context {
    /// The acceptance runner's public IP when known (for example from a previous canary echo).
    pub runner_ip: Option<IpAddr>,
}

/// The validator's result.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Report {
    /// Findings in rule order.
    pub findings: Vec<Finding>,
}

impl Report {
    /// Number of FAIL findings.
    pub fn failures(&self) -> usize {
        self.findings
            .iter()
            .filter(|f| f.status == Status::Fail)
            .count()
    }

    /// True when no rule failed.
    pub fn is_ok(&self) -> bool {
        self.failures() == 0
    }

    /// Findings of a rule.
    pub fn of_rule(&self, rule: &str) -> Vec<&Finding> {
        self.findings.iter().filter(|f| f.rule == rule).collect()
    }
}

/// Catalog of rule ids and what they check (documented in OPERATIONS.md; every finding must use one of these).
pub const RULES: &[(&str, &str)] = &[
    ("PROF-SCHEMA", "schema_version is 5"),
    (
        "PROF-REQUIRED",
        "fields required by the chosen runtime profile are present",
    ),
    (
        "PROF-LOCAL",
        "rules that only apply to runtime.profile: local (section 8.2, 2.11)",
    ),
    ("PROF-HOSTNAME", "host names are syntactically valid"),
    (
        "PROF-TEST-SANDBOX",
        "test_hostname and sandbox_hostname are distinct subdomains of domain",
    ),
    (
        "PROF-PLATFORM-DOMAIN",
        "platform_domain is a registrable apex",
    ),
    ("PROF-CIDR", "every CIDR parses and is not absurdly broad"),
    (
        "PROF-RUNNER-ADMIN",
        "admin_cidrs does not contain the runner IP (section 2.4)",
    ),
    (
        "PROF-EGRESS",
        "egress_allowlist entries parse and cover the hosts the profile configures (section 2.1)",
    ),
    (
        "PROF-ACME",
        "ACME directory defaults to staging; production needs approval",
    ),
    (
        "PROF-SIGNUP",
        "signup policy (open needs operator approval; refused in local)",
    ),
    ("PROF-ORIGIN", "origin URL and TLS verification settings"),
    (
        "PROF-PLATFORM",
        "server addresses, deployment mode and SSH details",
    ),
    ("PROF-DNS", "DNS topology and secondary DNS"),
    (
        "PROF-LIFECYCLE",
        "production requires a verified lockdown and a DDoS statement",
    ),
    ("PROF-SMTP", "SMTP relay settings"),
    (
        "PROF-POLICY",
        "retention, password length and similar floors that may only be tightened",
    ),
    ("PROF-LAB", "closed-lab settings"),
    (
        "PROF-LOAD",
        "load profile approval is recorded, not assumed",
    ),
    (
        "PROF-SECRETS",
        "secret-bearing fields hold environment variable names only",
    ),
    (
        "PROF-PLACEHOLDER",
        "documentation placeholder values are replaced",
    ),
    (
        "PROF-PROBES",
        "reachability probes are run by hddctl preflight, not by this validator",
    ),
    ("PROF-NA-LOCAL", "sections ignored in the local profile"),
];

/// A field the operator must supply: path, how to provide it, required for hosted, required for local.
#[derive(Debug, Clone, Copy)]
pub struct RequiredField {
    /// Dotted path in `hdd.live.yaml`.
    pub path: &'static str,
    /// How the operator provides it.
    pub how: &'static str,
    /// Required when `runtime.profile` is `hosted`.
    pub hosted: bool,
    /// Required when `runtime.profile` is `local`.
    pub local: bool,
}

/// Required fields (section 8, 8.2) with the text that tells the operator what to supply.
pub const REQUIRED_FIELDS: &[RequiredField] = &[
    RequiredField {
        path: "operator_email",
        how: "the address that receives test mail and alerts; it is the only address the agent may mail",
        hosted: true,
        local: true,
    },
    RequiredField {
        path: "platform_domain",
        how: "the apex you own that will host www/app/admin/api/ns/status, for example example.com (registrar access not needed yet)",
        hosted: true,
        local: false,
    },
    RequiredField {
        path: "domain",
        how: "the apex zone you own and want protected first",
        hosted: true,
        local: false,
    },
    RequiredField {
        path: "test_hostname",
        how: "a subdomain of `domain` that mirrors your real site, for example hddtest.<domain> (benign traffic and GET/HEAD attack shapes only)",
        hosted: true,
        local: false,
    },
    RequiredField {
        path: "sandbox_hostname",
        how: "a second subdomain of `domain`, distinct from test_hostname, that forwards only exact canary paths, for example hddsbx.<domain>",
        hosted: true,
        local: false,
    },
    RequiredField {
        path: "surfaces.public_host",
        how: "host for the public site, for example www.<platform_domain>",
        hosted: true,
        local: false,
    },
    RequiredField {
        path: "surfaces.app_host",
        how: "host for the customer app, for example app.<platform_domain>",
        hosted: true,
        local: false,
    },
    RequiredField {
        path: "surfaces.admin_host",
        how: "host for the admin panel, for example admin.<platform_domain>",
        hosted: true,
        local: false,
    },
    RequiredField {
        path: "surfaces.api_host",
        how: "host for the API, for example api.<platform_domain>",
        hosted: true,
        local: false,
    },
    RequiredField {
        path: "surfaces.status_host",
        how: "host for the status page, ideally served from outside this server",
        hosted: true,
        local: false,
    },
    RequiredField {
        path: "origin.url",
        how: "the real origin with scheme, for example https://203.0.113.10",
        hosted: true,
        local: false,
    },
    RequiredField {
        path: "origin.tls_server_name",
        how: "the name the origin certificate is valid for",
        hosted: true,
        local: false,
    },
    RequiredField {
        path: "origin.host_header",
        how: "the Host header the origin expects",
        hosted: true,
        local: false,
    },
    RequiredField {
        path: "platform.public_ipv4",
        how: "the public IPv4 address(es) of the server that will run HDD (at least one IPv4 or IPv6 address)",
        hosted: true,
        local: false,
    },
    RequiredField {
        path: "platform.ns_hostnames",
        how: "the nameserver host names HDD will serve, for example ns1.<platform_domain> and ns2.<platform_domain>",
        hosted: true,
        local: false,
    },
    RequiredField {
        path: "platform.edge_cname_zone",
        how: "zone for <site-id>.edge.<platform_domain> (CNAME modes), for example edge.<platform_domain>",
        hosted: true,
        local: false,
    },
    RequiredField {
        path: "platform.acme_cname_zone",
        how: "zone for DNS-01 delegation targets, for example acme.<platform_domain>",
        hosted: true,
        local: false,
    },
    RequiredField {
        path: "acme.email",
        how: "the account email for the certificate authority",
        hosted: true,
        local: false,
    },
];

fn is_present(p: &Profile, path: &str) -> bool {
    let nonempty = |s: &str| !s.trim().is_empty();
    match path {
        "operator_email" => nonempty(&p.operator_email),
        "platform_domain" => nonempty(&p.platform_domain),
        "domain" => nonempty(&p.domain),
        "test_hostname" => nonempty(&p.test_hostname),
        "sandbox_hostname" => nonempty(&p.sandbox_hostname),
        "surfaces.public_host" => nonempty(&p.surfaces.public_host),
        "surfaces.app_host" => nonempty(&p.surfaces.app_host),
        "surfaces.admin_host" => nonempty(&p.surfaces.admin_host),
        "surfaces.api_host" => nonempty(&p.surfaces.api_host),
        "surfaces.status_host" => nonempty(&p.surfaces.status_host),
        "origin.url" => nonempty(&p.origin.url),
        "origin.tls_server_name" => nonempty(&p.origin.tls_server_name),
        "origin.host_header" => nonempty(&p.origin.host_header),
        "platform.public_ipv4" => {
            !p.platform.public_ipv4.is_empty() || !p.platform.public_ipv6.is_empty()
        }
        "platform.ns_hostnames" => !p.platform.ns_hostnames.is_empty(),
        "platform.edge_cname_zone" => nonempty(&p.platform.edge_cname_zone),
        "platform.acme_cname_zone" => nonempty(&p.platform.acme_cname_zone),
        "acme.email" => nonempty(&p.acme.email),
        _ => true,
    }
}

/// A short preview of a rejected value for messages: the field path already says where it is, and a value that was pasted
/// into the wrong field may be a secret, so it is never repeated in full.
fn preview(s: &str) -> String {
    let n = s.chars().count();
    if n <= 6 {
        s.to_owned()
    } else {
        let head: String = s.chars().take(6).collect();
        format!("{head}…({n} chars)")
    }
}

struct Out {
    findings: Vec<Finding>,
}

impl Out {
    fn push(
        &mut self,
        rule: &'static str,
        status: Status,
        field: &str,
        message: impl Into<String>,
        remediation: impl Into<String>,
    ) {
        self.findings.push(Finding {
            rule,
            status,
            field: field.to_owned(),
            message: message.into(),
            remediation: remediation.into(),
        });
    }
    fn pass(&mut self, rule: &'static str, field: &str, message: impl Into<String>) {
        self.push(rule, Status::Pass, field, message, "");
    }
    fn fail(
        &mut self,
        rule: &'static str,
        field: &str,
        message: impl Into<String>,
        remediation: impl Into<String>,
    ) {
        self.push(rule, Status::Fail, field, message, remediation);
    }
    fn warn(
        &mut self,
        rule: &'static str,
        field: &str,
        message: impl Into<String>,
        remediation: impl Into<String>,
    ) {
        self.push(rule, Status::Warn, field, message, remediation);
    }
    fn unverified(
        &mut self,
        rule: &'static str,
        reason: Reason,
        field: &str,
        message: impl Into<String>,
        remediation: impl Into<String>,
    ) {
        self.push(
            rule,
            Status::Unverified(reason),
            field,
            message,
            remediation,
        );
    }
    fn count(&self, rule: &str, status: Status) -> usize {
        self.findings
            .iter()
            .filter(|f| f.rule == rule && f.status == status)
            .count()
    }
}

/// Documentation placeholder domains and address ranges (RFC 2606, RFC 5737, RFC 3849).
fn is_placeholder_host(h: &str) -> bool {
    let h = h.to_ascii_lowercase();
    ["example.com", "example.net", "example.org"]
        .iter()
        .any(|d| h == *d || h.ends_with(&format!(".{d}")))
        || h.ends_with(".invalid")
        || h.ends_with(".example")
}

fn is_placeholder_ip(ip: IpAddr) -> bool {
    [
        "192.0.2.0/24",
        "198.51.100.0/24",
        "203.0.113.0/24",
        "2001:db8::/32",
    ]
    .iter()
    .filter_map(|c| c.parse::<Cidr>().ok())
    .any(|c| c.contains(ip))
}

/// Two-label public suffixes recognised without the full public suffix list (the full list arrives with T-0154).
const COMMON_SECOND_LEVEL_SUFFIXES: &[&str] = &[
    "co.uk", "org.uk", "ac.uk", "gov.uk", "com.au", "net.au", "org.au", "co.jp", "co.nz", "com.br",
    "co.in", "com.cn", "co.za", "com.mx", "com.tr", "com.sg", "com.np", "co.kr",
];

/// True when `h` is a single label or one of the recognised two-label public suffixes (see the limits note on
/// [`COMMON_SECOND_LEVEL_SUFFIXES`]: the complete public suffix list arrives with T-0154).
fn is_public_suffix(h: &str) -> bool {
    let h = h.to_ascii_lowercase();
    !h.contains('.') || COMMON_SECOND_LEVEL_SUFFIXES.contains(&h.as_str())
}

fn registrable_apex(h: &str) -> Result<(), String> {
    let h = h.to_ascii_lowercase();
    let labels: Vec<&str> = h.split('.').collect();
    if labels.len() < 2 {
        return Err("a single label is a top-level domain, not a registrable domain".into());
    }
    let last_two = labels
        .get(labels.len().saturating_sub(2)..)
        .map(|s| s.join("."))
        .unwrap_or_default();
    let suffix_len = if COMMON_SECOND_LEVEL_SUFFIXES.contains(&last_two.as_str()) {
        2
    } else {
        1
    };
    if labels.len() == suffix_len {
        return Err(format!("`{h}` is a public suffix"));
    }
    if labels.len() > suffix_len + 1 {
        return Err(format!(
            "`{h}` is a subdomain; the registrable apex would be `{}`",
            labels
                .get(labels.len() - suffix_len - 1..)
                .map(|s| s.join("."))
                .unwrap_or_default()
        ));
    }
    Ok(())
}

fn parse_origin_url(u: &str) -> Result<(String, String, Option<u16>), String> {
    let (scheme, rest) = u
        .split_once("://")
        .ok_or("missing scheme (use https:// or http://)")?;
    if scheme != "https" && scheme != "http" {
        return Err(format!("unsupported scheme `{scheme}`"));
    }
    if rest.contains(['@', '?', '#', ' ']) {
        return Err("credentials, query, fragment and spaces are not allowed".into());
    }
    let authority = rest.split('/').next().unwrap_or("");
    let (host, port) = if let Some(stripped) = authority.strip_prefix('[') {
        let end = stripped.find(']').ok_or("unterminated IPv6 literal")?;
        let host = stripped.get(..end).unwrap_or("").to_owned();
        let after = stripped.get(end + 1..).unwrap_or("");
        let port = if after.is_empty() {
            None
        } else {
            Some(
                after
                    .strip_prefix(':')
                    .ok_or("unexpected text after the IPv6 literal")?
                    .to_owned(),
            )
        };
        (host, port)
    } else {
        match authority.rsplit_once(':') {
            Some((h, p)) => (h.to_owned(), Some(p.to_owned())),
            None => (authority.to_owned(), None),
        }
    };
    let port = match port {
        Some(p) => Some(p.parse::<u16>().map_err(|_| "invalid port".to_owned())?),
        None => None,
    };
    if host.is_empty() {
        return Err("empty host".into());
    }
    if host.parse::<IpAddr>().is_err() {
        validate_hostname(&host).map_err(|e| e.to_string())?;
    }
    Ok((scheme.to_owned(), host, port))
}

/// Name spaces reserved for local and documentation use (RFC 6761, RFC 2606, RFC 8375).
fn is_reserved_local_suffix(s: &str) -> bool {
    s == "localhost"
        || [".localhost", ".test", ".internal", ".home.arpa", ".example"]
            .iter()
            .any(|r| s.ends_with(r))
        || ["test", "internal", "home.arpa", "example"].contains(&s)
}

fn locale_ok(l: &str) -> bool {
    let mut parts = l.split('-');
    let first = parts.next().unwrap_or("");
    (2..=3).contains(&first.len())
        && first.chars().all(|c| c.is_ascii_lowercase())
        && parts.all(|p| (2..=8).contains(&p.len()) && p.chars().all(|c| c.is_ascii_alphanumeric()))
}

/// Validate a profile. Pure: no network, no file system.
pub fn validate(p: &Profile, ctx: &Context) -> Report {
    let mut o = Out {
        findings: Vec::new(),
    };
    let local = p.runtime.profile == RuntimeProfile::Local;

    // PROF-SCHEMA
    if p.schema_version == 5 {
        o.pass("PROF-SCHEMA", "schema_version", "schema_version is 5");
    } else {
        o.fail("PROF-SCHEMA", "schema_version", format!("schema_version is {}, this build understands 5 only", p.schema_version), "Set `schema_version: 5` (see hdd.live.example.yaml) after reviewing the changed fields.");
    }

    // PROF-REQUIRED
    let mut missing = 0;
    for r in REQUIRED_FIELDS {
        let needed = if local { r.local } else { r.hosted };
        if needed && !is_present(p, r.path) {
            missing += 1;
            o.fail(
                "PROF-REQUIRED",
                r.path,
                format!("required field `{}` is empty", r.path),
                format!("Set `{}` to {}.", r.path, r.how),
            );
        }
    }
    if missing == 0 {
        o.pass(
            "PROF-REQUIRED",
            "",
            format!(
                "all {} required fields are present",
                REQUIRED_FIELDS
                    .iter()
                    .filter(|r| if local { r.local } else { r.hosted })
                    .count()
            ),
        );
    }

    // PROF-LOCAL
    if local {
        let l = &p.runtime.local;
        let mut bad = false;
        // The capability matrix decides (T-0561 step 3); this only words the refusals it returns.
        for r in p.refusals() {
            bad = true;
            match r.capability {
                Capability::SaasMode => o.fail(
                    "PROF-LOCAL",
                    "deployment_mode",
                    format!(
                        "deployment_mode `saas` is refused when runtime.profile is local ({}: {})",
                        r.code, r.reason
                    ),
                    "Set `deployment_mode: owner_only`, or use `runtime.profile: hosted`.",
                ),
                Capability::OpenSignup => o.fail(
                    "PROF-LOCAL",
                    "signup.mode",
                    format!(
                        "signup mode `open` is refused in the local profile ({}: {})",
                        r.code, r.reason
                    ),
                    "Set `signup.mode: disabled` or `invite_only`.",
                ),
                other => o.fail(
                    "PROF-LOCAL",
                    "runtime",
                    format!(
                        "{} is refused in the local profile ({}: {})",
                        other.label(),
                        r.code,
                        r.reason
                    ),
                    "Use `runtime.profile: hosted` for this capability.",
                ),
            }
        }
        if p.surfaces.admin_exposure == AdminExposure::RoutedWithCidr {
            bad = true;
            o.fail(
                "PROF-LOCAL",
                "surfaces.admin_exposure",
                "admin_exposure is forced to `tunnel_only` (loopback) in the local profile",
                "Set `surfaces.admin_exposure: tunnel_only`.",
            );
        }
        let ports = [
            l.ports.web,
            l.ports.proxy_http,
            l.ports.proxy_https,
            l.ports.dns,
            l.ports.api,
        ];
        let distinct: BTreeSet<u16> = ports.iter().copied().collect();
        if distinct.len() != ports.len() || ports.contains(&0) {
            bad = true;
            o.fail(
                "PROF-LOCAL",
                "runtime.local.ports",
                "local ports must be distinct and non-zero",
                "Give each of web, proxy_http, proxy_https, dns and api its own port above 1023.",
            );
        }
        if ports.iter().any(|&x| x < 1024 && x != 0) {
            o.warn("PROF-LOCAL", "runtime.local.ports", "a port below 1024 needs a privilege that HDD never requests silently (section 2.11)", "Keep the unprivileged defaults unless you already hold the capability to bind low ports.");
        }
        if l.lan_exposure && l.tls == super::types::LocalTls::HttpOnly {
            bad = true;
            o.fail(
                "PROF-LOCAL",
                "runtime.local.tls",
                "tls `http_only` is allowed on loopback only, but lan_exposure is true",
                "Set `runtime.local.tls: local_ca` or `lan_exposure: false`.",
            );
        }
        let suffix = l.local_domain_suffix.trim().to_ascii_lowercase();
        if suffix.is_empty()
            || validate_hostname(&suffix).is_err() && suffix != "localhost"
            || is_public_suffix(&suffix) && suffix != "localhost"
        {
            bad = true;
            o.fail("PROF-LOCAL", "runtime.local.local_domain_suffix", format!("local_domain_suffix `{}` is not a usable local suffix", preview(&suffix)), "Use `hdd.localhost` (browsers resolve *.localhost to loopback) or another suffix under a name you control; a public suffix would make unrelated names look local.");
        } else if !is_reserved_local_suffix(&suffix) {
            bad = true;
            o.fail(
                "PROF-LOCAL",
                "runtime.local.local_domain_suffix",
                format!("`{}` is a real name space: the local certificate authority would be constrained to it and the hosts helper would point it at this computer", preview(&suffix)),
                "Use `hdd.localhost` (or another name ending in `.localhost`, `.test`, `.internal`, `.home.arpa` or `.example`, the suffixes reserved for local and documentation use).",
            );
        } else if suffix != "localhost" && !suffix.ends_with(".localhost") {
            o.warn("PROF-LOCAL", "runtime.local.local_domain_suffix", format!("`{suffix}` does not end in `.localhost`: browsers will not resolve it to loopback by themselves, and the local certificate authority's name constraint covers exactly this suffix"), "Prefer `hdd.localhost`; otherwise plan for `hdd-local hosts apply`.");
        }
        if l.lan_exposure {
            o.warn("PROF-LOCAL", "runtime.local.lan_exposure", "protected-site listeners will bind a LAN address (persistent banner and audit event; the control plane stays on loopback)", "Confirm the acknowledgement string at first run (section 2.11) or set `lan_exposure: false`.");
        }
        if l.loopback_client_identity == LoopbackIdentity::Single {
            o.warn(
                "PROF-LOCAL",
                "runtime.local.loopback_client_identity",
                "`single` is refused while any site is in block mode (C18.5)",
                "Use `ua_keyed` unless you only run monitor mode.",
            );
        }
        if l.tunnel.provider != TunnelProvider::None && l.tunnel.trusted_cidrs.is_empty() {
            o.warn("PROF-LOCAL", "runtime.local.tunnel.trusted_cidrs", "a tunnel is configured but trusted_cidrs is empty, so forwarded client IPs will not be trusted", "List the tunnel's egress CIDRs, or set `tunnel.provider: none`.");
        }
        if !bad {
            o.pass(
                "PROF-LOCAL",
                "runtime",
                "local profile settings are consistent",
            );
        }
    } else {
        o.push(
            "PROF-LOCAL",
            Status::NotApplicable,
            "runtime.local",
            "runtime.profile is hosted; `runtime.local` is not read",
            "",
        );
    }

    // PROF-HOSTNAME
    let mut hostnames: Vec<(String, String)> = Vec::new();
    let mut add = |path: &str, v: &str| {
        if !v.trim().is_empty() {
            hostnames.push((path.to_owned(), v.to_owned()));
        }
    };
    if !local {
        add("platform_domain", &p.platform_domain);
        add("domain", &p.domain);
        add("test_hostname", &p.test_hostname);
        add("sandbox_hostname", &p.sandbox_hostname);
        add("surfaces.public_host", &p.surfaces.public_host);
        add("surfaces.app_host", &p.surfaces.app_host);
        add("surfaces.admin_host", &p.surfaces.admin_host);
        add("surfaces.api_host", &p.surfaces.api_host);
        add("surfaces.status_host", &p.surfaces.status_host);
        add("origin.tls_server_name", &p.origin.tls_server_name);
        add("origin.host_header", &p.origin.host_header);
        add("platform.edge_cname_zone", &p.platform.edge_cname_zone);
        add("platform.acme_cname_zone", &p.platform.acme_cname_zone);
        for (i, h) in p.platform.ns_hostnames.iter().enumerate() {
            add(&format!("platform.ns_hostnames[{i}]"), h);
        }
        for (i, h) in p.dns.public_ns.iter().enumerate() {
            add(&format!("dns.public_ns[{i}]"), h);
        }
    }
    if p.smtp.host.parse::<IpAddr>().is_err() && !p.smtp.host.eq_ignore_ascii_case("localhost") {
        add("smtp.host", &p.smtp.host);
    }
    let checked = hostnames.len();
    for (path, h) in &hostnames {
        if let Err(e) = validate_hostname(h) {
            o.fail("PROF-HOSTNAME", path, format!("`{}` is not a valid host name: {e}", preview(h)), format!("Correct `{path}` to a fully qualified lower-case host name such as www.example.com."));
        }
    }
    if o.count("PROF-HOSTNAME", Status::Fail) == 0 {
        o.pass(
            "PROF-HOSTNAME",
            "",
            format!("{checked} host name(s) are syntactically valid"),
        );
    }

    // PROF-TEST-SANDBOX and PROF-PLATFORM-DOMAIN (hosted)
    if !local {
        let (t, s, d) = (
            p.test_hostname.trim(),
            p.sandbox_hostname.trim(),
            p.domain.trim(),
        );
        let mut bad = false;
        if !t.is_empty() && !s.is_empty() && t.eq_ignore_ascii_case(s) {
            bad = true;
            o.fail("PROF-TEST-SANDBOX", "sandbox_hostname", "test_hostname and sandbox_hostname are the same host", "Use two different subdomains of `domain` (for example hddtest.<domain> and hddsbx.<domain>); the sandbox route forwards only exact canary paths and must not share a name with the test mirror.");
        }
        if !d.is_empty() && is_public_suffix(d) {
            bad = true;
            o.fail("PROF-TEST-SANDBOX", "domain", format!("domain `{}` is a public suffix, not a domain the operator can own", preview(d)), "Set `domain` to the registrable domain you own (for example example.com); otherwise test_hostname and sandbox_hostname would be somebody else's names.");
        }
        if !d.is_empty() {
            for (path, h) in [("test_hostname", t), ("sandbox_hostname", s)] {
                if !h.is_empty() && !is_strict_subdomain(h, d) {
                    bad = true;
                    o.fail("PROF-TEST-SANDBOX", path, format!("`{h}` is not a subdomain of domain `{d}`"), format!("Choose a name below `{d}` (for example hdd{}.{d}) so that the operator owns it and the pilot delegation covers it.", if path == "test_hostname" { "test" } else { "sbx" }));
                }
            }
        }
        if !bad && !t.is_empty() && !s.is_empty() && !d.is_empty() {
            o.pass(
                "PROF-TEST-SANDBOX",
                "",
                "test_hostname and sandbox_hostname are distinct subdomains of domain",
            );
        } else if !bad {
            o.unverified(
                "PROF-TEST-SANDBOX",
                Reason::CapabilityNotSupplied,
                "",
                "cannot compare: domain, test_hostname or sandbox_hostname is empty",
                "Fill the three fields (see PROF-REQUIRED).",
            );
        }
        let pd = p.platform_domain.trim();
        if pd.is_empty() {
            o.unverified(
                "PROF-PLATFORM-DOMAIN",
                Reason::CapabilityNotSupplied,
                "platform_domain",
                "platform_domain is empty",
                "Set platform_domain (see PROF-REQUIRED).",
            );
        } else {
            match registrable_apex(pd) {
                Ok(()) => o.pass("PROF-PLATFORM-DOMAIN", "platform_domain", format!("`{pd}` is a registrable apex (checked against the built-in suffix list; the full public suffix list arrives with T-0154)")),
                Err(why) => o.fail("PROF-PLATFORM-DOMAIN", "platform_domain", format!("platform_domain is not a registrable apex: {why}"), "Use the registrable domain you own, for example example.com."),
            }
        }
    } else {
        o.push(
            "PROF-TEST-SANDBOX",
            Status::NotApplicable,
            "",
            "local profile: the local site and sandbox.<suffix> play these roles (section 2.11)",
            "",
        );
        o.push(
            "PROF-PLATFORM-DOMAIN",
            Status::NotApplicable,
            "platform_domain",
            "local profile: platform_domain defaults to hdd.localhost",
            "",
        );
    }

    // PROF-CIDR
    let mut cidr_fields: Vec<(String, &str)> = Vec::new();
    for (i, c) in p.admin_cidrs.iter().enumerate() {
        cidr_fields.push((format!("admin_cidrs[{i}]"), c));
    }
    for (i, c) in p.ssh_allow_cidrs.iter().enumerate() {
        cidr_fields.push((format!("ssh_allow_cidrs[{i}]"), c));
    }
    for (i, c) in p.upstream_cdn.trusted_cidrs.iter().enumerate() {
        cidr_fields.push((format!("upstream_cdn.trusted_cidrs[{i}]"), c));
    }
    for (i, c) in p.runtime.local.tunnel.trusted_cidrs.iter().enumerate() {
        cidr_fields.push((format!("runtime.local.tunnel.trusted_cidrs[{i}]"), c));
    }
    if !p.lab.cidr.is_empty() {
        cidr_fields.push(("lab.cidr".to_owned(), &p.lab.cidr));
    }
    let n_cidr = cidr_fields.len();
    for (path, c) in &cidr_fields {
        match c.parse::<Cidr>() {
            Err(e) => o.fail(
                "PROF-CIDR",
                path,
                format!("`{}` is not a valid CIDR: {e}", preview(c)),
                "Write it as address/prefix, for example 203.0.113.0/24 or 2001:db8::/32.",
            ),
            Ok(cidr) => {
                let broad = if cidr.network().is_ipv4() {
                    cidr.prefix() < 8
                } else {
                    cidr.prefix() < 32
                };
                if broad && path.starts_with("admin_cidrs") {
                    o.fail(
                        "PROF-CIDR",
                        path,
                        format!("`{c}` would put a huge part of the internet on the never-ban list"),
                        "Narrow it to the operator's own addresses (a /8 or wider IPv4 range, or a range wider than /32 in IPv6, is refused).",
                    );
                } else if broad
                    && (path.starts_with("ssh_allow_cidrs")
                        || path.starts_with("upstream_cdn")
                        || path.contains("trusted_cidrs"))
                {
                    o.warn(
                        "PROF-CIDR",
                        path,
                        format!("`{c}` is extremely broad for an allow / trust list"),
                        "Narrow it to the addresses that really need it.",
                    );
                }
            }
        }
    }
    if o.count("PROF-CIDR", Status::Fail) == 0 {
        o.pass("PROF-CIDR", "", format!("{n_cidr} CIDR value(s) parse"));
    }

    // PROF-RUNNER-ADMIN
    let runner: Option<IpAddr> = ctx
        .runner_ip
        .or_else(|| p.test_runner.public_ip.trim().parse::<IpAddr>().ok());
    let runner_text = p.test_runner.public_ip.trim();
    let runner_is_typo = ctx.runner_ip.is_none()
        && !runner_text.is_empty()
        && !runner_text.eq_ignore_ascii_case("auto")
        && runner.is_none();
    if runner_is_typo {
        o.fail(
            "PROF-RUNNER-ADMIN",
            "test_runner.public_ip",
            format!("test_runner.public_ip `{}` is neither `auto` nor an IP address", preview(runner_text)),
            "Write `auto` (the runner address is discovered through the canary echo) or the runner's public IP address.",
        );
    }
    match runner {
        _ if runner_is_typo => {}
        Some(ip) => {
            let hit = p.admin_cidrs.iter().filter_map(|c| c.parse::<Cidr>().ok()).find(|c| c.contains(ip));
            match hit {
                Some(c) => o.fail(
                    "PROF-RUNNER-ADMIN",
                    "admin_cidrs",
                    format!("admin_cidrs contains the runner IP {} (matched by {c}). The runner must stay bannable and must never be in admin_cidrs or any never-ban list (section 2.4).", canonical_ip(ip)),
                    format!("Remove {c} from admin_cidrs, or run the acceptance runner from another address. If the runner needs SSH, keep its IP in ssh_allow_cidrs instead."),
                ),
                None => o.pass("PROF-RUNNER-ADMIN", "admin_cidrs", format!("runner IP {} is not in admin_cidrs", canonical_ip(ip))),
            }
        }
        None => o.unverified("PROF-RUNNER-ADMIN", Reason::StageNotReached, "test_runner.public_ip", "the runner IP is `auto`: it is discovered through the canary echo at run time", "`hddctl preflight` repeats this check once the runner IP is known (T-0217); until then keep your own workstation address out of admin_cidrs only if it is also the runner."),
    }

    // PROF-EGRESS
    if p.egress_allowlist.is_empty() {
        o.unverified("PROF-EGRESS", Reason::HumanStepPending, "egress_allowlist", "egress_allowlist is empty: every outbound request (CA, resolvers, feeds, SMTP, GeoIP download) is denied and outbound checks cannot run", "Add the destinations you permit (Q-040), for example `acme-staging-v02.api.letsencrypt.org`, `tcp://<smtp host>:587`, `dns://1.1.1.1`, `dns://9.9.9.9`.");
    } else {
        match Allowlist::parse(&p.egress_allowlist) {
            Err(errs) => {
                for (i, e) in errs {
                    o.fail("PROF-EGRESS", &format!("egress_allowlist[{i}]"), format!("entry {i} is not valid: {e}"), "Use `[scheme://]host[:port][/path-prefix]` with scheme https, http, tcp or dns, and `*.suffix` for a suffix match.");
                }
            }
            Ok(list) => {
                let mut uncovered = 0;
                let mut need: Vec<(&str, Scheme, String, u16, String)> = Vec::new();
                if !p.smtp.host.trim().is_empty() {
                    need.push((
                        "smtp.host",
                        Scheme::Tcp,
                        p.smtp.host.trim().to_owned(),
                        p.smtp.port,
                        String::new(),
                    ));
                }
                if p.signup.password_breach_check == BreachCheck::HibpRange {
                    need.push((
                        "signup.password_breach_check",
                        Scheme::Https,
                        "api.pwnedpasswords.com".to_owned(),
                        443,
                        "/range/".to_owned(),
                    ));
                }
                if let Some(rest) = p.geoip.source.trim().strip_prefix("https://") {
                    let host = rest.split(['/', ':']).next().unwrap_or("").to_owned();
                    if !host.is_empty() {
                        need.push(("geoip.source", Scheme::Https, host, 443, "/".to_owned()));
                    }
                }
                for (field, scheme, host, port, path) in &need {
                    if !list.permits(*scheme, host, *port, path) {
                        uncovered += 1;
                        o.fail("PROF-EGRESS", field, format!("egress_allowlist does not cover {}://{host}:{port} used by `{field}`", scheme.as_str()), format!("Add `{}://{host}:{port}` to egress_allowlist (adding an egress destination needs your approval, section 0.5).", scheme.as_str()));
                    }
                }
                if uncovered == 0 {
                    o.pass("PROF-EGRESS", "egress_allowlist", format!("{} entries parse and cover the {} host(s) named elsewhere in the profile", list.entries().len(), need.len()));
                }
                o.unverified("PROF-EGRESS", Reason::CapabilityNotSupplied, "egress_allowlist", "profile v5 has no field that names the CA, resolver or feed hosts, so their coverage cannot be checked mechanically", "Make sure the list includes your CA directory host, at least two public resolvers (dns://) and every feed you enable.");
            }
        }
    }

    // PROF-ACME
    if local {
        o.push(
            "PROF-ACME",
            Status::NotApplicable,
            "acme",
            "ACME is not used in the local profile",
            "",
        );
    } else {
        match p.acme.directory {
            AcmeDirectory::Staging => o.pass("PROF-ACME", "acme.directory", "acme.directory is staging (default)"),
            AcmeDirectory::Production => o.unverified("PROF-ACME", Reason::HumanStepPending, "acme.directory", "production issuance needs the operator's explicit approval after staging passes (section 0.5)", "Keep `acme.directory: staging` until you confirm production issuance in chat."),
        }
        if !p.acme.email.trim().is_empty() && !validate_email(p.acme.email.trim()) {
            o.fail(
                "PROF-ACME",
                "acme.email",
                format!("`{}` is not a valid e-mail address", preview(&p.acme.email)),
                "Use an address you read; the CA sends expiry notices there.",
            );
        }
    }

    // PROF-SIGNUP and operator e-mail
    match p.signup.mode {
        SignupMode::Open if !local => o.unverified("PROF-SIGNUP", Reason::HumanStepPending, "signup.mode", "signup mode `open` needs operator approval in chat before it is enabled on a public installation", "Use `invite_only` until you approve open signup."),
        SignupMode::Open => {}
        SignupMode::Disabled => o.pass("PROF-SIGNUP", "signup.mode", "signup mode is disabled"),
        SignupMode::InviteOnly => o.pass("PROF-SIGNUP", "signup.mode", "signup mode is invite_only"),
    }
    if !p.operator_email.trim().is_empty() && !validate_email(p.operator_email.trim()) {
        o.fail(
            "PROF-SIGNUP",
            "operator_email",
            format!(
                "`{}` is not a valid e-mail address",
                preview(&p.operator_email)
            ),
            "Set the address that receives test mail and alerts.",
        );
    }

    // PROF-ORIGIN (hosted)
    if local {
        o.push(
            "PROF-ORIGIN",
            Status::NotApplicable,
            "origin",
            "domains and origins are added from the UI in the local profile",
            "",
        );
    } else if p.origin.url.trim().is_empty() {
        o.unverified(
            "PROF-ORIGIN",
            Reason::CapabilityNotSupplied,
            "origin.url",
            "origin.url is empty",
            "Set origin.url (see PROF-REQUIRED).",
        );
    } else {
        match parse_origin_url(p.origin.url.trim()) {
            Err(e) => o.fail(
                "PROF-ORIGIN",
                "origin.url",
                format!("origin.url is invalid: {e}"),
                "Write the origin as https://host[:port] (or an IP address).",
            ),
            Ok((scheme, host, _)) => {
                if scheme == "http" {
                    o.warn("PROF-ORIGIN", "origin.url", "plaintext origin: allowed only as an explicit, acknowledged `http_origin` mode and flagged in readiness", "Prefer an https origin with certificate verification.");
                } else {
                    o.pass(
                        "PROF-ORIGIN",
                        "origin.url",
                        format!("origin is https://{host}"),
                    );
                }
            }
        }
        if p.origin.tls_verify.mode != TlsVerifyMode::Webpki
            && p.origin.tls_verify.pin.trim().is_empty()
        {
            o.fail("PROF-ORIGIN", "origin.tls_verify.pin", format!("tls_verify.mode is {} but pin is empty", if p.origin.tls_verify.mode == TlsVerifyMode::PinnedCa { "pinned_ca" } else { "pinned_spki" }), "Provide the CA certificate or SPKI hash to pin, or use `webpki`. Verification can never be disabled.");
        }
    }

    // PROF-PLATFORM (hosted)
    if local {
        o.push(
            "PROF-PLATFORM",
            Status::NotApplicable,
            "platform",
            "platform.* is ignored in the local profile",
            "",
        );
    } else {
        let mut bad = false;
        for (i, ip) in p.platform.public_ipv4.iter().enumerate() {
            match ip.parse::<IpAddr>() {
                Ok(IpAddr::V4(v4)) => {
                    if v4.is_private()
                        || v4.is_loopback()
                        || v4.is_link_local()
                        || v4.is_unspecified()
                    {
                        o.warn(
                            "PROF-PLATFORM",
                            &format!("platform.public_ipv4[{i}]"),
                            format!("{ip} is not a public address"),
                            "Use the server's public address (the one the internet reaches).",
                        );
                    }
                }
                _ => {
                    bad = true;
                    o.fail(
                        "PROF-PLATFORM",
                        &format!("platform.public_ipv4[{i}]"),
                        format!("`{}` is not an IPv4 address", preview(ip)),
                        "Put IPv6 addresses under platform.public_ipv6.",
                    );
                }
            }
        }
        for (i, ip) in p.platform.public_ipv6.iter().enumerate() {
            if !matches!(ip.parse::<IpAddr>(), Ok(IpAddr::V6(_))) {
                bad = true;
                o.fail(
                    "PROF-PLATFORM",
                    &format!("platform.public_ipv6[{i}]"),
                    format!("`{}` is not an IPv6 address", preview(ip)),
                    "Put IPv4 addresses under platform.public_ipv4.",
                );
            }
        }
        if p.platform.deploy_mode == DeployMode::Ssh {
            for (field, empty) in [
                ("platform.ssh.host", p.platform.ssh.host.trim().is_empty()),
                ("platform.ssh.user", p.platform.ssh.user.trim().is_empty()),
                ("platform.ssh.key_path", p.platform.ssh.key_path.is_empty()),
            ] {
                if empty {
                    bad = true;
                    o.fail("PROF-PLATFORM", field, format!("deploy_mode is `ssh` but `{field}` is empty"), format!("Set `{field}` (Q-020, Q-021), or use `deploy_mode: on-vps` when running hddctl on the server itself."));
                }
            }
        }
        if p.platform.uplink_mbps == 0 {
            o.unverified(
                "PROF-PLATFORM",
                Reason::CapabilityNotSupplied,
                "platform.uplink_mbps",
                "uplink is 0 (unknown): shield capacity figures stay UNVERIFIED",
                "Enter the contracted or measured uplink in Mbit/s (Q-002).",
            );
        }
        if !bad {
            o.pass(
                "PROF-PLATFORM",
                "platform",
                "server addresses and deployment settings are consistent",
            );
        }
    }

    // PROF-DNS (hosted)
    if local {
        o.push(
            "PROF-DNS",
            Status::NotApplicable,
            "dns",
            "dns.*, registrar and secondary_dns are ignored in the local profile",
            "",
        );
    } else {
        let mut bad = false;
        if p.dns.topology == DnsTopology::HiddenPrimary && p.dns.public_ns.is_empty() {
            bad = true;
            o.fail("PROF-DNS", "dns.public_ns", "topology is hidden_primary but public_ns is empty", "List the nameserver names the external secondary serves publicly, or use `topology: self_authoritative`.");
        }
        let sd = &p.secondary_dns;
        if sd.provider.trim().is_empty() {
            o.unverified("PROF-DNS", Reason::CapabilityNotSupplied, "secondary_dns", "no secondary DNS configured: the cutover gate, AC-21 and AC-28 stay UNVERIFIED", "Name an external secondary DNS provider and the TSIG key variable (Q-032) before cutover.");
        } else {
            if sd.addresses.is_empty() {
                bad = true;
                o.fail(
                    "PROF-DNS",
                    "secondary_dns.addresses",
                    "a secondary DNS provider is set but no addresses are listed",
                    "List the secondary's IP addresses for zone transfer.",
                );
            }
            if sd.tsig_key_env.is_empty() {
                bad = true;
                o.fail(
                    "PROF-DNS",
                    "secondary_dns.tsig_key_env",
                    "a secondary DNS provider is set but tsig_key_env is empty",
                    "Name the environment variable that holds the TSIG key (never the key itself).",
                );
            }
        }
        if !bad {
            o.pass("PROF-DNS", "dns", "DNS topology settings are consistent");
        }
    }

    // PROF-LIFECYCLE
    if p.lifecycle_stage == LifecycleStage::Production && !local {
        if p.origin.lockdown_state != LockdownState::Applied {
            o.fail("PROF-LIFECYCLE", "origin.lockdown_state", "lifecycle_stage is production but origin lockdown is not `applied` (section 2.7, R-34)", "Apply the origin firewall allowlist and the secret header, verify them, then set `origin.lockdown_state: applied`; or return to `lifecycle_stage: pilot`.");
        }
        if p.upstream_ddos.mode == DdosMode::None {
            o.fail("PROF-LIFECYCLE", "upstream_ddos.mode", "lifecycle_stage is production but upstream_ddos.mode is none: DDoS readiness is NOT READY and the cutover checklist fails", "Describe the upstream mitigation from your contract, or record a risk acceptance (risk_acceptance_volumetric: true after the written confirmation).");
        }
    } else if p.upstream_ddos.mode == DdosMode::None && !local {
        o.warn("PROF-LIFECYCLE", "upstream_ddos.mode", "DDoS readiness reports NOT READY while upstream_ddos.mode is none (acceptable for the pilot only)", "Fill upstream_ddos from your provider contract before cutover (Q-029).");
    }
    if p.upstream_ddos.mode != DdosMode::None {
        if p.upstream_ddos.provider.trim().is_empty() {
            o.fail(
                "PROF-LIFECYCLE",
                "upstream_ddos.provider",
                "an upstream DDoS mode is set but provider is empty",
                "Name the provider from your contract.",
            );
        }
        if p.upstream_ddos.advertised_capacity_gbps <= 0.0 {
            o.unverified(
                "PROF-LIFECYCLE",
                Reason::CapabilityNotSupplied,
                "upstream_ddos.advertised_capacity_gbps",
                "advertised capacity is 0: it is copied from the contract and never assumed",
                "Enter the figure from the provider contract.",
            );
        }
    }
    if o.count("PROF-LIFECYCLE", Status::Fail) == 0
        && o.count("PROF-LIFECYCLE", Status::Warn) == 0
        && o.findings.iter().all(|f| f.rule != "PROF-LIFECYCLE")
    {
        o.pass(
            "PROF-LIFECYCLE",
            "lifecycle_stage",
            "lifecycle settings are consistent",
        );
    }

    // PROF-SMTP
    let smtp = &p.smtp;
    if smtp.host.trim().is_empty() {
        o.unverified("PROF-SMTP", Reason::HumanStepPending, "smtp.host", "no SMTP relay: a local SMTP sink is used and real delivery tests (AC-46) stay UNVERIFIED", "Provide relay host, port, TLS mode and credentials (as env var names) before M3 (Q-011).");
    } else {
        let mut bad = false;
        if smtp.port == 0 {
            bad = true;
            o.fail(
                "PROF-SMTP",
                "smtp.port",
                "smtp.port is 0",
                "Use 587 (STARTTLS) or 465 (implicit TLS).",
            );
        }
        if smtp.tls == SmtpTls::None
            && !matches!(smtp.host.as_str(), "localhost" | "127.0.0.1" | "::1")
        {
            bad = true;
            o.fail(
                "PROF-SMTP",
                "smtp.tls",
                "smtp.tls is `none` for a non-loopback relay",
                "Use `starttls` or `tls`; unencrypted SMTP is allowed only for a local sink.",
            );
        }
        if smtp.username_env.is_empty() != smtp.password_env.is_empty() {
            bad = true;
            o.fail(
                "PROF-SMTP",
                "smtp.username_env",
                "username_env and password_env must be set together",
                "Name both environment variables, or neither for an unauthenticated local relay.",
            );
        }
        if !smtp.from_address.trim().is_empty() && !validate_email(smtp.from_address.trim()) {
            bad = true;
            o.fail(
                "PROF-SMTP",
                "smtp.from_address",
                format!("`{}` is not a valid e-mail address", smtp.from_address),
                "Use the sender address, for example hdd@<platform_domain>.",
            );
        }
        if !bad {
            o.pass("PROF-SMTP", "smtp", "SMTP settings are consistent");
        }
    }

    // PROF-POLICY
    for (field, value) in [
        ("smtp.from_name", p.smtp.from_name.as_str()),
        ("smtp.reply_to", p.smtp.reply_to.as_str()),
        ("smtp.from_address", p.smtp.from_address.as_str()),
        ("branding.product_name", p.branding.product_name.as_str()),
        ("branding.legal_entity", p.branding.legal_entity.as_str()),
        ("branding.support_email", p.branding.support_email.as_str()),
        ("branding.terms_url", p.branding.terms_url.as_str()),
        ("branding.privacy_url", p.branding.privacy_url.as_str()),
        ("operator_email", p.operator_email.as_str()),
        ("acme.email", p.acme.email.as_str()),
    ] {
        if value.chars().any(char::is_control) {
            o.fail("PROF-POLICY", field, "contains a control character (such a value could inject mail headers or log lines)", format!("Remove the line break or control character from `{field}`."));
        }
    }
    let mut policy_bad = false;
    if p.retention.audit_days < 180 {
        policy_bad = true;
        o.fail(
            "PROF-POLICY",
            "retention.audit_days",
            format!(
                "audit retention {} days is below the floor of 180",
                p.retention.audit_days
            ),
            "Set retention.audit_days to 180 or more (default 400).",
        );
    }
    if p.retention.events_days == 0 {
        policy_bad = true;
        o.fail(
            "PROF-POLICY",
            "retention.events_days",
            "event retention is 0 days",
            "Set retention.events_days to at least 1 (default 30).",
        );
    }
    if p.signup.min_password_length < 12 {
        policy_bad = true;
        o.fail("PROF-POLICY", "signup.min_password_length", format!("minimum password length {} is below 12; loosening an Appendix E4 value needs the operator's approval", p.signup.min_password_length), "Set it to 12 or more.");
    }
    if p.locales.is_empty() || !p.locales.iter().all(|l| locale_ok(l)) {
        policy_bad = true;
        o.fail(
            "PROF-POLICY",
            "locales",
            "locales must be a non-empty list of language tags such as `en` or `de-DE`",
            "Set `locales: [en]`.",
        );
    }
    if p.branding.product_name.trim().is_empty() {
        policy_bad = true;
        o.fail(
            "PROF-POLICY",
            "branding.product_name",
            "branding.product_name is empty",
            "Keep the default `Hack Dev Defence` unless you decided a brand (Q-005).",
        );
    }
    if !p.branding.support_email.trim().is_empty()
        && !validate_email(p.branding.support_email.trim())
    {
        policy_bad = true;
        o.fail(
            "PROF-POLICY",
            "branding.support_email",
            format!(
                "`{}` is not a valid e-mail address",
                p.branding.support_email
            ),
            "Fix or clear the address.",
        );
    }
    if !policy_bad {
        o.pass(
            "PROF-POLICY",
            "",
            "retention, password length, locales and branding meet the floors",
        );
    }

    // PROF-LAB
    if p.lab.vulnlab_enabled && !p.lab.enabled {
        o.fail(
            "PROF-LAB",
            "lab.vulnlab_enabled",
            "vulnlab_enabled requires lab.enabled",
            "Enable the lab first, or turn the Vuln-Lab off.",
        );
    } else if p.lab.enabled && (p.lab.host.trim().is_empty() || p.lab.cidr.trim().is_empty()) {
        o.fail("PROF-LAB", "lab.host", "lab is enabled but host or cidr is empty", "Name the closed lab machine and its private CIDR (Q-004); the lab is never the live server.");
    } else if p.lab.enabled {
        let lab_cidr = p.lab.cidr.trim().parse::<Cidr>();
        match lab_cidr {
            Err(_) => {} // reported by PROF-CIDR
            Ok(c) => {
                let class = crate::egress::ssrf::classify(c.network());
                let private = matches!(
                    class,
                    crate::egress::ssrf::IpClass::Private
                        | crate::egress::ssrf::IpClass::UniqueLocal
                        | crate::egress::ssrf::IpClass::Loopback
                );
                let wide = if c.network().is_ipv4() {
                    c.prefix() < 8
                } else {
                    c.prefix() < 16
                };
                let overlaps_platform = p
                    .platform
                    .public_ipv4
                    .iter()
                    .chain(p.platform.public_ipv6.iter())
                    .filter_map(|a| a.parse::<IpAddr>().ok())
                    .any(|a| c.contains(a));
                if !private || wide {
                    o.fail("PROF-LAB", "lab.cidr", format!("lab.cidr {c} is not a private lab range (RFC 1918, unique-local or loopback, at most as wide as a /8): attack-shaped lab traffic must never be able to reach a routable address"), "Use the private CIDR of the closed lab network, for example 10.99.0.0/24.");
                }
                if overlaps_platform {
                    o.fail("PROF-LAB", "lab.cidr", format!("lab.cidr {c} contains one of the platform.public_* addresses: the lab is never the live server"), "Use a range that does not contain the server that runs HDD.");
                }
                if private && !wide && !overlaps_platform {
                    o.pass("PROF-LAB", "lab", "lab host is set and lab.cidr is a private range that excludes the platform addresses");
                }
            }
        }
    } else {
        o.unverified(
            "PROF-LAB",
            Reason::CapabilityNotSupplied,
            "lab",
            "no closed lab: AC-26, AC-29, AC-38 and AC-39 lab portions stay UNVERIFIED",
            "Provide a lab machine (Q-004) if you want those checks.",
        );
    }

    // PROF-LOAD
    if p.load_profile_approved {
        o.unverified("PROF-LOAD", Reason::HumanStepPending, "load_profile_approved", "load_profile_approved is true: the approval must be recorded verbatim with its date in docs/OPERATOR-CONFIRMATIONS.md", "Record the written approval for this run; the flag alone is not evidence.");
    } else {
        o.pass(
            "PROF-LOAD",
            "load_profile_approved",
            "no load run is approved",
        );
    }

    // PROF-SECRETS
    let remote_env = p.runtime.hosting.backups.remote_env.clone();
    let env_fields = [
        &remote_env,
        &p.registrar.api_token_env,
        &p.smtp.username_env,
        &p.smtp.password_env,
        &p.secondary_dns.tsig_key_env,
        &p.alerts.webhook_env,
        &p.alerts.heartbeat_url_env,
        &p.upstream_ddos.mitigation_api.token_env,
    ];
    o.pass("PROF-SECRETS", "", format!("{} secret-bearing fields; {} name an environment variable; values are never read from this file (enforced when the file is parsed)", env_fields.len(), env_fields.iter().filter(|e| !e.is_empty()).count()));

    // PROF-PLACEHOLDER
    let mut placeholders: Vec<String> = Vec::new();
    for (path, h) in &hostnames {
        if is_placeholder_host(h) {
            placeholders.push(path.clone());
        }
    }
    if let Ok((_, host, _)) = parse_origin_url(p.origin.url.trim())
        && (is_placeholder_host(&host) || host.parse::<IpAddr>().is_ok_and(is_placeholder_ip))
    {
        placeholders.push("origin.url".into());
    }
    for (i, ip) in p
        .platform
        .public_ipv4
        .iter()
        .chain(p.platform.public_ipv6.iter())
        .enumerate()
    {
        if ip.parse::<IpAddr>().is_ok_and(is_placeholder_ip) {
            placeholders.push(format!("platform.public_ip[{i}]"));
        }
    }
    if placeholders.is_empty() {
        o.pass(
            "PROF-PLACEHOLDER",
            "",
            "no documentation placeholder values found",
        );
    } else {
        o.warn(
            "PROF-PLACEHOLDER",
            &placeholders.join(", "),
            format!(
                "{} value(s) use documentation placeholders (example.com, TEST-NET addresses)",
                placeholders.len()
            ),
            "Replace them with your real names and addresses before any live use.",
        );
    }

    // PROF-PROBES
    o.unverified("PROF-PROBES", Reason::StageNotReached, "platform.ns_hostnames, smtp.host", "DNS resolution of the nameserver names and a TCP connect to the SMTP relay are reachability probes; they run only in `hddctl preflight` without --profile-only and only through the egress client", "Run `hddctl preflight` (without --profile-only) once egress_allowlist lists a `dns://` resolver and the SMTP relay as `tcp://host:port`.");

    // PROF-NA-LOCAL
    if local {
        for section in [
            "platform",
            "dns",
            "registrar",
            "acme",
            "upstream_ddos",
            "secondary_dns",
        ] {
            o.push(
                "PROF-NA-LOCAL",
                Status::NotApplicable,
                section,
                format!("`{section}` is ignored in the local profile (reported as not applicable)"),
                "",
            );
        }
    }

    Report {
        findings: o.findings,
    }
}

#[cfg(test)]
mod tests;
