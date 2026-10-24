//! Runtime settings from the environment (B10, T-0561 step 2): `HDD_RUNTIME_PROFILE`, `HDD_DATA_DIR`, `HDD_KV_BACKEND`,
//! `HDD_HOSTING_PROFILE` and the `HDD_LOCAL_*` family, parsed into types and laid over a [`Profile`].
//!
//! The environment wins over the file (the usual order of the product). Nothing here is a secret, but values are still never
//! echoed in full: an error names the variable and a short preview. Parsing is pure: it reads through a lookup function, so
//! tests need no process environment.

use schemars::JsonSchema;
use serde::Serialize;

use super::capability::LAN_ACK;
use super::types::{
    HostingProfile, LocalDatabase, LocalKv, LocalPorts, LocalTls, LoopbackIdentity, Profile,
    RuntimeProfile,
};

/// Backing store for runtime state (`HDD_KV_BACKEND`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum KvBackend {
    /// In-process `MemoryKv`.
    Memory,
    /// Redis or Valkey.
    Redis,
}

/// The settings that come from the environment, each `None` when the variable is unset.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, JsonSchema)]
pub struct RuntimeEnv {
    /// `HDD_RUNTIME_PROFILE`.
    pub runtime_profile: Option<RuntimeProfile>,
    /// `HDD_DATA_DIR`: an absolute path.
    pub data_dir: Option<String>,
    /// `HDD_LOCAL_DATABASE`.
    pub local_database: Option<LocalDatabase>,
    /// `HDD_KV_BACKEND`.
    pub kv_backend: Option<KvBackend>,
    /// `HDD_LOCAL_PORTS`.
    pub local_ports: Option<LocalPorts>,
    /// `HDD_LOCAL_SUFFIX`.
    pub local_suffix: Option<String>,
    /// `HDD_LOCAL_TLS`.
    pub local_tls: Option<LocalTls>,
    /// `HDD_LOCAL_LAN_EXPOSURE`.
    pub local_lan_exposure: Option<bool>,
    /// True when `HDD_LOCAL_LAN_ACK` equals the acknowledgement string exactly.
    pub local_lan_ack: bool,
    /// `HDD_LOCAL_DOGFOOD`.
    pub local_dogfood: Option<bool>,
    /// `HDD_LOCAL_LOOPBACK_IDENTITY`.
    pub local_loopback_identity: Option<LoopbackIdentity>,
    /// `HDD_HOSTING_PROFILE`.
    pub hosting_profile: Option<HostingProfile>,
}

/// One rejected variable.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EnvError {
    /// The variable name.
    pub var: &'static str,
    /// What is wrong, with the accepted values.
    pub message: String,
}

impl std::fmt::Display for EnvError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}: {}", self.var, self.message)
    }
}

impl std::error::Error for EnvError {}

fn preview(s: &str) -> String {
    let n = s.chars().count();
    if n <= 12 {
        s.chars().filter(|c| !c.is_control()).collect()
    } else {
        let head: String = s.chars().take(12).filter(|c| !c.is_control()).collect();
        format!("{head}…({n} chars)")
    }
}

fn one_of<T: Copy>(var: &'static str, value: &str, table: &[(&str, T)]) -> Result<T, EnvError> {
    table
        .iter()
        .find(|(k, _)| *k == value)
        .map(|(_, v)| *v)
        .ok_or_else(|| EnvError {
            var,
            message: format!(
                "`{}` is not accepted; use one of: {}",
                preview(value),
                table.iter().map(|(k, _)| *k).collect::<Vec<_>>().join(", ")
            ),
        })
}

fn boolean(var: &'static str, value: &str) -> Result<bool, EnvError> {
    one_of(var, value, &[("true", true), ("false", false)])
}

fn parse_ports(value: &str) -> Result<LocalPorts, EnvError> {
    let var = "HDD_LOCAL_PORTS";
    let mut ports = LocalPorts::default();
    let mut seen: Vec<&str> = Vec::new();
    for pair in value.split(',') {
        let (name, port) = pair.split_once('=').ok_or_else(|| EnvError {
            var,
            message: format!(
                "`{}` is not name=port; the default is web=8443,proxy_http=8080,proxy_https=8444,dns=5300,api=8000",
                preview(pair)
            ),
        })?;
        let name = name.trim();
        if seen.contains(&name) {
            return Err(EnvError {
                var,
                message: format!("`{}` is given twice", preview(name)),
            });
        }
        seen.push(name);
        let port: u16 = port.trim().parse().map_err(|_| EnvError {
            var,
            message: format!(
                "`{}` is not a port number (1 to 65535)",
                preview(port.trim())
            ),
        })?;
        if port == 0 {
            return Err(EnvError {
                var,
                message: "port 0 is not allowed".into(),
            });
        }
        match name {
            "web" => ports.web = port,
            "proxy_http" => ports.proxy_http = port,
            "proxy_https" => ports.proxy_https = port,
            "dns" => ports.dns = port,
            "api" => ports.api = port,
            other => {
                return Err(EnvError {
                    var,
                    message: format!(
                        "unknown service `{}`; use web, proxy_http, proxy_https, dns, api",
                        preview(other)
                    ),
                });
            }
        }
    }
    Ok(ports)
}

/// Absolute on the platform this runs on (`/x` is not absolute on Windows, `C:\\x` is not absolute on Unix).
fn is_absolute(path: &str) -> bool {
    std::path::Path::new(path).is_absolute()
}

impl RuntimeEnv {
    /// Parse the variables through `get`. Every bad variable is reported, not just the first.
    pub fn from_lookup(get: &dyn Fn(&str) -> Option<String>) -> Result<RuntimeEnv, Vec<EnvError>> {
        let mut env = RuntimeEnv::default();
        let mut errors = Vec::new();
        let take = |var: &'static str| get(var).filter(|v| !v.is_empty());
        macro_rules! field {
            ($var:literal, $slot:expr, $parse:expr) => {
                if let Some(v) = take($var) {
                    match $parse(&v) {
                        Ok(x) => $slot = Some(x),
                        Err(e) => errors.push(e),
                    }
                }
            };
        }
        field!(
            "HDD_RUNTIME_PROFILE",
            env.runtime_profile,
            |v: &str| one_of(
                "HDD_RUNTIME_PROFILE",
                v,
                &[
                    ("hosted", RuntimeProfile::Hosted),
                    ("local", RuntimeProfile::Local)
                ]
            )
        );
        field!("HDD_DATA_DIR", env.data_dir, |v: &str| {
            if v.chars().any(char::is_control) {
                Err(EnvError {
                    var: "HDD_DATA_DIR",
                    message: "contains control characters".into(),
                })
            } else if !is_absolute(v) {
                Err(EnvError {
                    var: "HDD_DATA_DIR",
                    message: "must be an absolute path (a relative path would depend on the working directory)".into(),
                })
            } else {
                Ok(v.to_owned())
            }
        });
        field!("HDD_LOCAL_DATABASE", env.local_database, |v: &str| one_of(
            "HDD_LOCAL_DATABASE",
            v,
            &[
                ("embedded", LocalDatabase::Embedded),
                ("external", LocalDatabase::External),
                ("compose", LocalDatabase::Compose)
            ]
        ));
        field!("HDD_KV_BACKEND", env.kv_backend, |v: &str| one_of(
            "HDD_KV_BACKEND",
            v,
            &[("memory", KvBackend::Memory), ("redis", KvBackend::Redis)]
        ));
        field!("HDD_LOCAL_PORTS", env.local_ports, parse_ports);
        field!("HDD_LOCAL_SUFFIX", env.local_suffix, |v: &str| {
            let s = v.trim().to_ascii_lowercase();
            if s.is_empty() || s.chars().any(|c| c.is_control() || c.is_whitespace()) {
                Err(EnvError {
                    var: "HDD_LOCAL_SUFFIX",
                    message: "must be a host name suffix such as hdd.localhost".into(),
                })
            } else {
                Ok(s)
            }
        });
        field!("HDD_LOCAL_TLS", env.local_tls, |v: &str| one_of(
            "HDD_LOCAL_TLS",
            v,
            &[
                ("local_ca", LocalTls::LocalCa),
                ("http_only", LocalTls::HttpOnly)
            ]
        ));
        field!(
            "HDD_LOCAL_LAN_EXPOSURE",
            env.local_lan_exposure,
            |v: &str| boolean("HDD_LOCAL_LAN_EXPOSURE", v)
        );
        field!("HDD_LOCAL_DOGFOOD", env.local_dogfood, |v: &str| boolean(
            "HDD_LOCAL_DOGFOOD",
            v
        ));
        field!(
            "HDD_LOCAL_LOOPBACK_IDENTITY",
            env.local_loopback_identity,
            |v: &str| one_of(
                "HDD_LOCAL_LOOPBACK_IDENTITY",
                v,
                &[
                    ("ua_keyed", LoopbackIdentity::UaKeyed),
                    ("single", LoopbackIdentity::Single)
                ]
            )
        );
        field!(
            "HDD_HOSTING_PROFILE",
            env.hosting_profile,
            |v: &str| one_of(
                "HDD_HOSTING_PROFILE",
                v,
                &[
                    ("H1", HostingProfile::H1),
                    ("H2", HostingProfile::H2),
                    ("H3", HostingProfile::H3),
                    ("H4", HostingProfile::H4),
                    ("H5", HostingProfile::H5)
                ]
            )
        );
        if let Some(ack) = take("HDD_LOCAL_LAN_ACK") {
            if ack == LAN_ACK {
                env.local_lan_ack = true;
            } else {
                errors.push(EnvError {
                    var: "HDD_LOCAL_LAN_ACK",
                    message: format!("must equal `{LAN_ACK}` exactly (ERR-LOCAL-002)"),
                });
            }
        }
        if errors.is_empty() {
            Ok(env)
        } else {
            Err(errors)
        }
    }

    /// Read the process environment.
    pub fn from_process_env() -> Result<RuntimeEnv, Vec<EnvError>> {
        RuntimeEnv::from_lookup(&|k| std::env::var(k).ok())
    }

    /// Lay these settings over `profile`. The `HDD_LOCAL_*` settings change `runtime.local` only (they are read only in the
    /// local profile); `HDD_HOSTING_PROFILE` changes `runtime.hosting` only.
    pub fn apply(&self, profile: &mut Profile) {
        if let Some(p) = self.runtime_profile {
            profile.runtime.profile = p;
        }
        let l = &mut profile.runtime.local;
        if let Some(d) = &self.data_dir {
            l.data_dir.clone_from(d);
        }
        if let Some(d) = self.local_database {
            l.database = d;
        }
        if let Some(k) = self.kv_backend {
            l.kv = match k {
                KvBackend::Memory => LocalKv::Memory,
                KvBackend::Redis => LocalKv::Redis,
            };
        }
        if let Some(p) = &self.local_ports {
            l.ports = p.clone();
        }
        if let Some(s) = &self.local_suffix {
            l.local_domain_suffix.clone_from(s);
        }
        if let Some(t) = self.local_tls {
            l.tls = t;
        }
        if let Some(x) = self.local_lan_exposure {
            l.lan_exposure = x;
        }
        if let Some(x) = self.local_dogfood {
            l.dogfood = x;
        }
        if let Some(i) = self.local_loopback_identity {
            l.loopback_client_identity = i;
        }
        if let Some(h) = self.hosting_profile {
            profile.runtime.hosting.profile = h;
        }
    }

    /// [`apply`](Self::apply), then enforce what the combination requires: LAN exposure of the local profile needs the exact
    /// acknowledgement in `HDD_LOCAL_LAN_ACK` (`ERR-LOCAL-002`). The acknowledgement is deliberately not a profile field: it has
    /// to be given at the moment of starting.
    pub fn apply_checked(&self, profile: &mut Profile) -> Result<(), Vec<EnvError>> {
        self.apply(profile);
        if profile.runtime.profile == RuntimeProfile::Local
            && profile.runtime.local.lan_exposure
            && !self.local_lan_ack
        {
            return Err(vec![EnvError {
                var: "HDD_LOCAL_LAN_ACK",
                message: format!(
                    "LAN exposure of the local profile needs HDD_LOCAL_LAN_ACK={LAN_ACK} (ERR-LOCAL-002)"
                ),
            }]);
        }
        Ok(())
    }

    /// The store the runtime state lives in, after the environment and the profile are combined.
    pub fn effective_kv(&self, profile: &Profile) -> KvBackend {
        if let Some(k) = self.kv_backend {
            return k;
        }
        match profile.runtime.profile {
            RuntimeProfile::Local => match profile.runtime.local.kv {
                LocalKv::Memory => KvBackend::Memory,
                LocalKv::Redis => KvBackend::Redis,
            },
            RuntimeProfile::Hosted => KvBackend::Redis,
        }
    }
}

/// JSON Schema of the environment settings, pretty-printed with a trailing newline.
pub fn schema_json() -> String {
    let schema = schemars::schema_for!(RuntimeEnv);
    let mut s = serde_json::to_string_pretty(&schema).unwrap_or_default();
    s.push('\n');
    s
}

#[cfg(test)]
mod tests;
