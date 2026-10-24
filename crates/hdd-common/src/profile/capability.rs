//! The capability matrix of C18.2 as code (T-0561 step 3, R-31).
//!
//! This is the single place that decides what a runtime profile may do. Every refusal path in the API and the UI asks
//! [`Profile::availability`]; nothing else compares `runtime.profile` to decide a feature (`xtask profile-lint` enforces that
//! outside the crates allowed to know the profile). The answer depends on the runtime profile only: it describes what the
//! profile permits, not what the host can do (that is the build plan, `hdd_common::buildplan`).

use std::fmt::Write as _;

use super::types::{DeploymentMode, LocalDatabase, LocalKv, Profile, RuntimeProfile, SignupMode};

/// `ERR-LOCAL-001`: the action is not available in the local runtime profile.
pub const ERR_LOCAL_UNAVAILABLE: &str = "ERR-LOCAL-001";
/// `ERR-LOCAL-002`: LAN exposure needs the acknowledgement.
pub const ERR_LOCAL_ACK: &str = "ERR-LOCAL-002";
/// `ERR-HOSTING-001`: a hosting requirement is not met.
pub const ERR_HOSTING: &str = "ERR-HOSTING-001";
/// The exact acknowledgement string of local LAN exposure (section 2.11, `HDD_LOCAL_LAN_ACK`).
pub const LAN_ACK: &str = "I-UNDERSTAND-LOCAL-IS-NOT-24x7";

/// Something a profile may or may not do.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Capability {
    /// Authoritative DNS on port 53.
    AuthoritativeDns53,
    /// Kernel enforcement (nftables sets, XDP, host agent).
    KernelEnforcement,
    /// ACME certificate issuance for public names.
    Acme,
    /// `deployment_mode: saas`.
    SaasMode,
    /// `signup.mode: open`.
    OpenSignup,
    /// Full nameserver delegation of a customer zone.
    FullNs,
    /// Protected-site listeners on a LAN address.
    LanExposure,
    /// A private PostgreSQL managed by HDD.
    EmbeddedDatabase,
    /// The in-process `KvStore`, `Bus` and `Limiter`.
    MemoryStore,
}

impl Capability {
    /// Every capability, in table order.
    pub const ALL: [Capability; 9] = [
        Capability::AuthoritativeDns53,
        Capability::KernelEnforcement,
        Capability::Acme,
        Capability::SaasMode,
        Capability::OpenSignup,
        Capability::FullNs,
        Capability::LanExposure,
        Capability::EmbeddedDatabase,
        Capability::MemoryStore,
    ];

    /// Stable machine id.
    pub fn id(self) -> &'static str {
        match self {
            Capability::AuthoritativeDns53 => "authoritative_dns_53",
            Capability::KernelEnforcement => "kernel_enforcement",
            Capability::Acme => "acme",
            Capability::SaasMode => "saas",
            Capability::OpenSignup => "open_signup",
            Capability::FullNs => "full_ns",
            Capability::LanExposure => "lan_exposure",
            Capability::EmbeddedDatabase => "embedded_database",
            Capability::MemoryStore => "memory_store",
        }
    }

    /// Plain-language name.
    pub fn label(self) -> &'static str {
        match self {
            Capability::AuthoritativeDns53 => "authoritative DNS on port 53",
            Capability::KernelEnforcement => "kernel enforcement (nftables, XDP)",
            Capability::Acme => "ACME certificates for public names",
            Capability::SaasMode => "saas deployment mode",
            Capability::OpenSignup => "open signup",
            Capability::FullNs => "full nameserver delegation",
            Capability::LanExposure => "LAN exposure of protected sites",
            Capability::EmbeddedDatabase => "embedded database",
            Capability::MemoryStore => "in-process key-value store",
        }
    }
}

/// What the operator must do for an `allowed_with_ack` capability.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Ack {
    /// Type the exact string [`LAN_ACK`].
    LanExposureString,
    /// The operator's approval, recorded in chat and in the audit log (E8.1).
    OperatorApproval,
    /// Only while a single service process is registered (the startup refusal of T-0562).
    SingleServiceProcess,
}

impl Ack {
    /// What to tell the operator.
    pub fn instruction(self) -> &'static str {
        match self {
            Ack::LanExposureString => "type the acknowledgement string exactly",
            Ack::OperatorApproval => "needs the operator's approval, recorded in the audit log",
            Ack::SingleServiceProcess => "only while one service process is registered",
        }
    }
}

/// The result of asking whether a profile may do something.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Availability {
    /// Allowed.
    Allowed,
    /// Allowed after an acknowledgement.
    AllowedWithAck {
        /// What must be acknowledged.
        ack: Ack,
        /// Error code returned until it is (none when the approval is a process step).
        code: Option<&'static str>,
    },
    /// Not available in this profile.
    Unavailable {
        /// Error code (`ERR-LOCAL-001` for the local profile).
        code: &'static str,
        /// Why, in one sentence a person can act on.
        reason: &'static str,
    },
}

impl Availability {
    /// True unless the capability is unavailable.
    pub fn is_usable(self) -> bool {
        !matches!(self, Availability::Unavailable { .. })
    }
}

/// The matrix of C18.2: runtime profile and capability to availability. Pure and total.
pub fn availability(profile: RuntimeProfile, cap: Capability) -> Availability {
    use Availability::{Allowed, AllowedWithAck, Unavailable};
    match (profile, cap) {
        (RuntimeProfile::Hosted, Capability::OpenSignup) => AllowedWithAck {
            ack: Ack::OperatorApproval,
            code: None,
        },
        (RuntimeProfile::Hosted, Capability::EmbeddedDatabase) => Unavailable {
            code: ERR_HOSTING,
            reason: "hosted installations use an external or host-local PostgreSQL server (hardened, T-0521)",
        },
        (RuntimeProfile::Hosted, Capability::MemoryStore) => AllowedWithAck {
            ack: Ack::SingleServiceProcess,
            code: Some(ERR_HOSTING),
        },
        (RuntimeProfile::Hosted, _) => Allowed,
        (RuntimeProfile::Local, Capability::AuthoritativeDns53) => Unavailable {
            code: ERR_LOCAL_UNAVAILABLE,
            reason: "port 53 needs a privilege that local never takes silently; the local DNS listener uses an unprivileged port",
        },
        (RuntimeProfile::Local, Capability::KernelEnforcement) => Unavailable {
            code: ERR_LOCAL_UNAVAILABLE,
            reason: "no nftables sets or XDP in local; the L7 jail enforces bans",
        },
        (RuntimeProfile::Local, Capability::Acme) => Unavailable {
            code: ERR_LOCAL_UNAVAILABLE,
            reason: "local names are *.localhost and use the name-constrained local certificate authority",
        },
        (RuntimeProfile::Local, Capability::SaasMode) => Unavailable {
            code: ERR_LOCAL_UNAVAILABLE,
            reason: "a service for other people needs the hosted profile (local is not available 24/7)",
        },
        (RuntimeProfile::Local, Capability::OpenSignup) => Unavailable {
            code: ERR_LOCAL_UNAVAILABLE,
            reason: "open signup needs the hosted profile; use disabled or invite_only",
        },
        (RuntimeProfile::Local, Capability::FullNs) => Unavailable {
            code: ERR_LOCAL_UNAVAILABLE,
            reason: "full nameserver delegation needs authoritative DNS on port 53 and a public address",
        },
        (RuntimeProfile::Local, Capability::LanExposure) => AllowedWithAck {
            ack: Ack::LanExposureString,
            code: Some(ERR_LOCAL_ACK),
        },
        (RuntimeProfile::Local, Capability::EmbeddedDatabase | Capability::MemoryStore) => Allowed,
    }
}

/// A refused capability with the error to return.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Refusal {
    /// Which capability.
    pub capability: Capability,
    /// Error code (`ERR-LOCAL-001` in local).
    pub code: &'static str,
    /// Why.
    pub reason: &'static str,
}

impl Profile {
    /// May this profile do `cap`? The only place that answers (R-31).
    pub fn availability(&self, cap: Capability) -> Availability {
        availability(self.runtime.profile, cap)
    }

    /// The whole matrix for this profile, in table order.
    pub fn capabilities(&self) -> Vec<(Capability, Availability)> {
        Capability::ALL
            .iter()
            .map(|&c| (c, self.availability(c)))
            .collect()
    }

    /// The capabilities this profile's own settings ask for.
    pub fn requested(&self) -> Vec<Capability> {
        let mut out = Vec::new();
        if self.deployment_mode == DeploymentMode::Saas {
            out.push(Capability::SaasMode);
        }
        if self.signup.mode == SignupMode::Open {
            out.push(Capability::OpenSignup);
        }
        if self.runtime.profile == RuntimeProfile::Local {
            let l = &self.runtime.local;
            if l.lan_exposure {
                out.push(Capability::LanExposure);
            }
            if l.database == LocalDatabase::Embedded {
                out.push(Capability::EmbeddedDatabase);
            }
            if l.kv == LocalKv::Memory {
                out.push(Capability::MemoryStore);
            }
        }
        out
    }

    /// Requested capabilities that are unavailable, with the error to return. Config load fails on any (A1).
    pub fn refusals(&self) -> Vec<Refusal> {
        self.requested()
            .into_iter()
            .filter_map(|c| match self.availability(c) {
                Availability::Unavailable { code, reason } => Some(Refusal {
                    capability: c,
                    code,
                    reason,
                }),
                _ => None,
            })
            .collect()
    }
}

/// The matrix of a profile as a table for `hddctl preflight` and the docs.
pub fn render(p: &Profile) -> String {
    let mut s = format!(
        "Capability matrix for runtime.profile: {}\n",
        match p.runtime.profile {
            RuntimeProfile::Local => "local",
            RuntimeProfile::Hosted => "hosted",
        }
    );
    for (cap, a) in p.capabilities() {
        let _ = match a {
            Availability::Allowed => writeln!(s, "  allowed          {}", cap.label()),
            Availability::AllowedWithAck { ack, code } => {
                let extra = match ack {
                    Ack::LanExposureString => format!(" `{LAN_ACK}`"),
                    _ => String::new(),
                };
                writeln!(
                    s,
                    "  allowed_with_ack {} ({}{}{})",
                    cap.label(),
                    ack.instruction(),
                    extra,
                    code.map(|c| format!("; {c} until then"))
                        .unwrap_or_default()
                )
            }
            Availability::Unavailable { code, reason } => {
                writeln!(s, "  unavailable      {} ({code}: {reason})", cap.label())
            }
        };
    }
    s
}

#[cfg(test)]
mod tests;
