//! The proxy configuration: strict YAML loaded with `serde-saphyr` (`deny_unknown_fields` everywhere), then
//! validated field by field with operator-readable errors. Secrets are never values in this file: `admin_token_env`
//! and `origin_secret_env` hold environment-variable *names*, resolved through [`Validated::resolve_secrets`] with an
//! injectable lookup closure so tests never mutate the process environment (edition 2024 makes `set_var` unsafe, and
//! `unsafe_code` is forbidden in this crate).
//!
//! The reference shape is the lead-owned `demo/hdd-dev.yaml` (COLLAB.md HK1 brief).

use std::collections::{BTreeMap, HashSet};
use std::fmt;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};

use hdd_waf_core::{CustomRule, FieldKind, SiteSettings, Stack, Strictness};
use serde::{Deserialize, Serialize};

use crate::api::{self, ConnectionMethod, Mode};
use crate::util::{Cidr, Origin};

/// The largest configuration file accepted (defence against a truncated or hostile file).
const MAX_CONFIG_BYTES: usize = 1024 * 1024;
/// The largest regex program compiled for a per-site custom rule.
const MAX_RULE_REGEX_BYTES: usize = 1024 * 1024;
/// The ladder used when a site enables bans without listing TTL steps.
const DEFAULT_TTL_LADDER: &[u64] = &[60, 600, 3600];
/// The environment-variable name prefix the wizard uses for an origin secret of a site created through the API.
const ORIGIN_SECRET_ENV_PREFIX: &str = "HDD_ORIGIN_SECRET_";

/// A configuration or validation error with an operator-readable message (never contains a secret value).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConfigError {
    /// The human message.
    pub message: String,
}

impl ConfigError {
    /// Build an error from a message.
    #[must_use]
    fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }
}

impl fmt::Display for ConfigError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.message)
    }
}

impl std::error::Error for ConfigError {}

/// One operator field hint: force the detector field kind of a named field.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct FieldHintConfig {
    /// The field name to match (whole token, case-insensitive).
    pub field: String,
    /// The kind to force.
    pub kind: FieldKind,
}

/// The per-site ban policy.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct BanConfig {
    /// Whether a block verdict bans the client IP.
    pub enabled: bool,
    /// The progressive TTL ladder in seconds (first offence, second, ...); the last step repeats.
    pub ttl_ladder_seconds: Vec<u64>,
}

impl Default for BanConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            ttl_ladder_seconds: DEFAULT_TTL_LADDER.to_vec(),
        }
    }
}

/// One configured site.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SiteConfig {
    /// The public host name the proxy routes on.
    pub host: String,
    /// The origin base URL (`http://` or `https://`).
    pub origin: String,
    /// The site's stack hint; picks the remediation code example in a finding (Addendum 6). Defaults to `other`.
    #[serde(default)]
    pub stack: Stack,
    /// The protection mode (`off`, `monitor`, `block`); defaults to `monitor`.
    #[serde(default)]
    pub mode: Mode,
    /// The detector strictness; defaults to `balanced`.
    #[serde(default)]
    pub strictness: Strictness,
    /// Operator field hints, applied before the detector name heuristic.
    #[serde(default)]
    pub field_hints: Vec<FieldHintConfig>,
    /// Operator custom rules (validated when the configuration loads).
    #[serde(default)]
    pub extra_rules: Vec<CustomRule>,
    /// The ban policy.
    #[serde(default)]
    pub ban: BanConfig,
    /// Whether the incoming `Host` is preserved (`true`) or replaced by the origin authority (`false`).
    #[serde(default = "default_preserve_host")]
    pub preserve_host: bool,
    /// The upstream `Host` override (serverless origins, Addendum 5).
    #[serde(default)]
    pub upstream_host: Option<String>,
    /// The header name injected upstream to prove the origin is locked down.
    #[serde(default)]
    pub origin_secret_header: Option<String>,
    /// The environment variable holding the origin secret value (never the value itself).
    #[serde(default)]
    pub origin_secret_env: Option<String>,
    /// The public HTTPS URL used by the verify-protection probes.
    #[serde(default)]
    pub public_url: Option<String>,
    /// Recorded result of the last successful origin lockdown check.
    #[serde(default)]
    pub lockdown_verified: bool,
}

/// The default for [`SiteConfig::preserve_host`].
fn default_preserve_host() -> bool {
    true
}

/// The default proxy listener address.
fn default_listen() -> String {
    api::DEFAULT_PROXY_LISTEN.to_owned()
}

/// The default admin listener address.
fn default_admin_listen() -> String {
    api::DEFAULT_ADMIN_LISTEN.to_owned()
}

/// The defaults of the optional AI explanation block (Addendum 6 item 3).
fn default_ai_provider() -> String {
    "deepseek".to_owned()
}
fn default_ai_base_url() -> String {
    "https://api.deepseek.com".to_owned()
}
fn default_ai_model() -> String {
    "deepseek-flash".to_owned()
}
fn default_ai_key_env() -> String {
    "DEEPSEEK_API_KEY".to_owned()
}
fn default_ai_timeout() -> u32 {
    20
}
fn default_ai_calls() -> u32 {
    30
}

/// The optional AI explanation configuration (Addendum 6 item 3).
///
/// The API key is **never** in this file: `api_key_env` names the environment variable the runtime reads at call time.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AiConfig {
    /// The provider name; only `deepseek` is supported.
    #[serde(default = "default_ai_provider")]
    pub provider: String,
    /// The API base URL (http(s)); the egress allowlist is exactly this host/port.
    #[serde(default = "default_ai_base_url")]
    pub base_url: String,
    /// The model name.
    #[serde(default = "default_ai_model")]
    pub model: String,
    /// The name of the environment variable holding the API key (never the key itself).
    #[serde(default = "default_ai_key_env")]
    pub api_key_env: String,
    /// The request timeout in seconds.
    #[serde(default = "default_ai_timeout")]
    pub timeout_s: u32,
    /// The maximum number of model calls per rolling hour.
    #[serde(default = "default_ai_calls")]
    pub max_calls_per_hour: u32,
}

impl Default for AiConfig {
    fn default() -> Self {
        Self {
            provider: default_ai_provider(),
            base_url: default_ai_base_url(),
            model: default_ai_model(),
            api_key_env: default_ai_key_env(),
            timeout_s: default_ai_timeout(),
            max_calls_per_hour: default_ai_calls(),
        }
    }
}

/// The configuration file.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    /// The proxy listener address (default `127.0.0.1:8080`).
    #[serde(default = "default_listen")]
    pub listen: String,
    /// The admin listener address (default `127.0.0.1:9090`).
    #[serde(default = "default_admin_listen")]
    pub admin_listen: String,
    /// The CIDR blocks whose `X-Forwarded-For` is trusted (the TLS terminator in front; empty by default).
    #[serde(default)]
    pub trusted_proxies: Vec<String>,
    /// The owner-only directory holding the account store and the event log.
    pub data_dir: PathBuf,
    /// The JSONL event log path.
    pub log_path: PathBuf,
    /// The name of the environment variable holding the admin bootstrap token (no default token).
    pub admin_token_env: String,
    /// Explicit acknowledgement that a **non-loopback** `admin_listen` exposes the admin surface to the network.
    ///
    /// Default `false`: binding the admin listener to a non-loopback address is refused with an actionable error
    /// (review R1-9). When set to `true` the listener starts and a warning is logged at start-up.
    #[serde(default)]
    pub admin_non_loopback_ack: bool,
    /// The optional AI explanation block (Addendum 6 item 3); absent means AI explanations are off.
    #[serde(default)]
    pub ai: Option<AiConfig>,
    /// The configured sites.
    #[serde(default)]
    pub sites: Vec<SiteConfig>,
}

/// A site that passed validation: the raw configuration plus the derived runtime values.
#[derive(Debug, Clone)]
pub struct ValidatedSite {
    /// The configuration with the normalised host name.
    pub config: SiteConfig,
    /// The normalised host name.
    pub host: String,
    /// The parsed origin.
    pub origin: Origin,
    /// The site's stack hint (Addendum 6 remediation code example).
    pub stack: Stack,
    /// The detector settings snapshot.
    pub settings: SiteSettings,
    /// Whether bans are enabled for this site.
    pub ban_enabled: bool,
    /// The progressive TTL ladder.
    pub ladder: Vec<u64>,
}

/// The validated configuration.
#[derive(Debug, Clone)]
pub struct Validated {
    /// The proxy listener address.
    pub listen: SocketAddr,
    /// The admin listener address.
    pub admin_listen: SocketAddr,
    /// The trusted proxy CIDR blocks.
    pub trusted_proxies: Vec<Cidr>,
    /// The owner-only data directory.
    pub data_dir: PathBuf,
    /// The JSONL event log path.
    pub log_path: PathBuf,
    /// The name of the admin bootstrap token environment variable.
    pub admin_token_env: String,
    /// Whether the operator explicitly acknowledged a non-loopback admin listener (review R1-9).
    pub admin_non_loopback_ack: bool,
    /// The normalised AI explanation configuration, when configured (Addendum 6 item 3).
    pub ai: Option<AiConfig>,
    /// The validated sites.
    pub sites: Vec<ValidatedSite>,
}

/// The secret values resolved at start-up; they never appear in a log line or an API response.
#[derive(Clone)]
pub struct ResolvedSecrets {
    /// The admin bootstrap/break-glass token from the configured environment variable.
    pub admin_token: String,
    /// The per-site origin secret values, keyed by normalised host name.
    pub origin_secrets: BTreeMap<String, String>,
}

impl fmt::Debug for ResolvedSecrets {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ResolvedSecrets")
            .field("admin_token", &"<redacted>")
            .field(
                "origin_secrets",
                &self.origin_secrets.keys().collect::<Vec<_>>(),
            )
            .finish()
    }
}

impl Config {
    /// Parse configuration YAML text strictly.
    ///
    /// # Errors
    /// Returns [`ConfigError`] when the YAML is malformed, too large, contains unknown keys or duplicate keys.
    pub fn parse_str(text: &str) -> Result<Self, ConfigError> {
        if text.len() > MAX_CONFIG_BYTES {
            return Err(ConfigError::new(format!(
                "configuration file is larger than {MAX_CONFIG_BYTES} bytes"
            )));
        }
        let options = yaml_options();
        serde_saphyr::from_str_with_options::<Self>(text, options).map_err(|error| {
            ConfigError::new(format!(
                "configuration YAML is invalid (unknown keys are rejected): {error}"
            ))
        })
    }

    /// Load the configuration file and parse it strictly.
    ///
    /// # Errors
    /// Returns [`ConfigError`] when the file cannot be read or parsed.
    pub fn load(path: &Path) -> Result<Self, ConfigError> {
        let text = std::fs::read_to_string(path).map_err(|error| {
            ConfigError::new(format!(
                "cannot read configuration file `{}`: {error}",
                path.display()
            ))
        })?;
        Self::parse_str(&text).map_err(|error| {
            ConfigError::new(format!(
                "configuration file `{}`: {}",
                path.display(),
                error.message
            ))
        })
    }

    /// Validate every field and derive the runtime values.
    ///
    /// # Errors
    /// Returns the first violation with a message that names the offending field and the expected shape.
    pub fn validate(&self) -> Result<Validated, ConfigError> {
        let listen = parse_listen("listen", &self.listen)?;
        let admin_listen = parse_listen("admin_listen", &self.admin_listen)?;
        // Two `:0` binds are legal: the operating system hands out distinct ephemeral ports. Any other duplicate
        // address would make the second bind fail, so it is rejected here with an actionable message.
        if listen == admin_listen && listen.port() != 0 {
            return Err(ConfigError::new(format!(
                "`listen` and `admin_listen` are both {listen}; the proxy and the admin listener need separate addresses"
            )));
        }
        // R1-9: the admin surface is loopback-only unless the operator explicitly accepts the exposure.
        if !admin_listen.ip().is_loopback() && !self.admin_non_loopback_ack {
            return Err(ConfigError::new(format!(
                "`admin_listen` {admin_listen} is not a loopback address, so the admin surface and its login would be \
                 exposed to the network; keep it on loopback (for example 127.0.0.1:9090) or set \
                 `admin_non_loopback_ack: true` to accept the risk explicitly (a warning is logged at start)"
            )));
        }
        let mut trusted_proxies = Vec::with_capacity(self.trusted_proxies.len());
        for (index, entry) in self.trusted_proxies.iter().enumerate() {
            trusted_proxies.push(Cidr::parse(entry).map_err(|message| {
                ConfigError::new(format!("trusted_proxies[{index}]: {message}"))
            })?);
        }
        validate_env_name("admin_token_env", &self.admin_token_env)?;
        if self.data_dir.as_os_str().is_empty() {
            return Err(ConfigError::new("`data_dir` must not be empty"));
        }
        if self.log_path.as_os_str().is_empty() {
            return Err(ConfigError::new("`log_path` must not be empty"));
        }
        // An empty site list is valid: HDD then forwards nothing and the panel shows the honest empty state until a site
        // is added (so a fresh install, or one where every site was removed, still starts).
        let mut hosts = HashSet::with_capacity(self.sites.len());
        let mut sites = Vec::with_capacity(self.sites.len());
        for (index, site) in self.sites.iter().enumerate() {
            let validated = validate_site(site)
                .map_err(|error| ConfigError::new(format!("sites[{index}]: {}", error.message)))?;
            if !hosts.insert(validated.host.clone()) {
                return Err(ConfigError::new(format!(
                    "sites[{index}]: duplicate host `{}`; each host may be configured once",
                    validated.host
                )));
            }
            sites.push(validated);
        }
        Ok(Validated {
            listen,
            admin_listen,
            trusted_proxies,
            data_dir: self.data_dir.clone(),
            log_path: self.log_path.clone(),
            admin_token_env: self.admin_token_env.clone(),
            admin_non_loopback_ack: self.admin_non_loopback_ack,
            ai: validate_ai(self.ai.as_ref())?,
            sites,
        })
    }
}

impl Validated {
    /// Validate one additional site (used when the add-site wizard creates a site at runtime).
    ///
    /// # Errors
    /// Returns the first violation of the same rules [`Config::validate`] applies to file sites.
    pub fn validate_one(&self, config: SiteConfig) -> Result<ValidatedSite, ConfigError> {
        validate_site(&config)
    }

    /// Resolve the secret values through an environment lookup.
    ///
    /// The admin listener refuses to start when the bootstrap token variable is missing (R-03: no default secret);
    /// a site whose `origin_secret_header` is set needs its `origin_secret_env` value for the same reason.
    ///
    /// # Errors
    /// Returns [`ConfigError`] naming the missing environment variable.
    pub fn resolve_secrets(
        &self,
        get_env: impl Fn(&str) -> Option<String>,
    ) -> Result<ResolvedSecrets, ConfigError> {
        let admin_token = get_env(&self.admin_token_env)
            .filter(|value| !value.trim().is_empty())
            .ok_or_else(|| {
                ConfigError::new(format!(
                    "the admin bootstrap token environment variable `{}` is not set or is empty; \
                     the admin listener refuses to start (R-03: there is no default secret)",
                    self.admin_token_env
                ))
            })?;
        let mut origin_secrets = BTreeMap::new();
        for site in &self.sites {
            if let Some(env_name) = site.config.origin_secret_env.as_deref() {
                let value = get_env(env_name)
                    .filter(|value| !value.trim().is_empty())
                    .ok_or_else(|| {
                        ConfigError::new(format!(
                            "site `{}` injects `{}` upstream but its origin secret environment variable \
                             `{env_name}` is not set or is empty",
                            site.host,
                            site.config
                                .origin_secret_header
                                .as_deref()
                                .unwrap_or("<unset header>")
                        ))
                    })?;
                origin_secrets.insert(site.host.clone(), value);
            }
        }
        Ok(ResolvedSecrets {
            admin_token,
            origin_secrets,
        })
    }
}

/// Parse a listener address with an operator-readable error.
fn parse_listen(field: &str, value: &str) -> Result<SocketAddr, ConfigError> {
    value.trim().parse::<SocketAddr>().map_err(|_| {
        ConfigError::new(format!(
            "`{field}` value `{value}` is not a socket address; write `127.0.0.1:8080`"
        ))
    })
}

/// Validate an environment-variable name.
fn validate_env_name(field: &str, name: &str) -> Result<(), ConfigError> {
    let mut chars = name.chars();
    let Some(first) = chars.next() else {
        return Err(ConfigError::new(format!(
            "`{field}` must name an environment variable (it must not be empty)"
        )));
    };
    if !(first.is_ascii_alphabetic() || first == '_')
        || !chars.all(|c| c.is_ascii_alphanumeric() || c == '_')
    {
        return Err(ConfigError::new(format!(
            "`{field}` value `{name}` is not an environment-variable name (letters, digits and `_` only)"
        )));
    }
    Ok(())
}

/// Validate one site and derive its runtime values.
fn validate_site(config: &SiteConfig) -> Result<ValidatedSite, ConfigError> {
    let host = validate_host(&config.host)?;
    let origin = Origin::parse(&config.origin)
        .map_err(|message| ConfigError::new(format!("origin: {message}")))?;
    if let Some(upstream) = config.upstream_host.as_deref()
        && crate::util::parse_authority(upstream).is_none()
    {
        return Err(ConfigError::new(format!(
            "upstream_host `{upstream}` is not a host name (`app.vercel.app` or `app.vercel.app:443`)"
        )));
    }
    let secret_env = match (
        config.origin_secret_header.as_deref(),
        config.origin_secret_env.as_deref(),
    ) {
        (Some(header), Some(env_name)) => {
            validate_header_name(header)?;
            validate_env_name("origin_secret_env", env_name)?;
            Some(env_name.to_owned())
        }
        (Some(header), None) => {
            validate_header_name(header)?;
            Some(default_origin_secret_env(&host))
        }
        (None, Some(_)) => {
            return Err(ConfigError::new(
                "`origin_secret_env` is set but `origin_secret_header` is missing; set both or neither",
            ));
        }
        (None, None) => None,
    };
    if let Some(public_url) = config.public_url.as_deref() {
        Origin::parse(public_url).map_err(|message| {
            ConfigError::new(format!(
                "public_url: {message} (it must be the public http(s) URL of the site)"
            ))
        })?;
    }
    validate_field_hints(&config.field_hints)?;
    let mut rule_ids = HashSet::with_capacity(config.extra_rules.len());
    for rule in &config.extra_rules {
        validate_custom_rule(rule)?;
        if !rule_ids.insert(rule.id.clone()) {
            return Err(ConfigError::new(format!(
                "duplicate custom rule id `{}`; each rule id must be unique per site",
                rule.id
            )));
        }
    }
    let ladder = if config.ban.ttl_ladder_seconds.is_empty() {
        DEFAULT_TTL_LADDER.to_vec()
    } else {
        config.ban.ttl_ladder_seconds.clone()
    };
    if config.ban.enabled && ladder.contains(&0) {
        return Err(ConfigError::new(
            "ban.ttl_ladder_seconds must not contain a zero TTL",
        ));
    }
    let mut normalized = config.clone();
    normalized.host.clone_from(&host);
    normalized.origin_secret_env = secret_env;
    let settings = SiteSettings {
        strictness: normalized.strictness,
        field_hints: normalized
            .field_hints
            .iter()
            .map(|hint| (hint.field.clone(), hint.kind))
            .collect(),
        extra_rules: normalized.extra_rules.clone(),
    };
    Ok(ValidatedSite {
        config: normalized,
        host,
        stack: config.stack,
        origin,
        settings,
        ban_enabled: config.ban.enabled,
        ladder,
    })
}

/// Validate and normalise the optional AI explanation block (Addendum 6 item 3).
///
/// Only the DeepSeek provider is supported; the base URL must be an `http(s)` URL (the egress allowlist is its host);
/// the timeout is 1..=60 s and the rate limit 1..=600 calls/hour. The API key is never read here.
fn validate_ai(ai: Option<&AiConfig>) -> Result<Option<AiConfig>, ConfigError> {
    let Some(ai) = ai else {
        return Ok(None);
    };
    if ai.provider != "deepseek" {
        return Err(ConfigError::new(format!(
            "`ai.provider` value `{}` is not supported; only `deepseek` is available",
            ai.provider
        )));
    }
    let base = Origin::parse(&ai.base_url).map_err(|message| {
        ConfigError::new(format!(
            "ai.base_url: {message} (it must be the http(s) API base URL)"
        ))
    })?;
    if !(1..=60).contains(&ai.timeout_s) {
        return Err(ConfigError::new(format!(
            "`ai.timeout_s` value {} is out of range; use 1..=60 seconds",
            ai.timeout_s
        )));
    }
    if !(1..=600).contains(&ai.max_calls_per_hour) {
        return Err(ConfigError::new(format!(
            "`ai.max_calls_per_hour` value {} is out of range; use 1..=600",
            ai.max_calls_per_hour
        )));
    }
    validate_env_name("ai.api_key_env", &ai.api_key_env)?;
    let mut normalized = ai.clone();
    normalized.base_url = base.url();
    Ok(Some(normalized))
}

/// Validate and normalise a site host name (also used by the add-site endpoint).
///
/// # Errors
/// Returns [`ConfigError`] when the host is not a routable host name.
pub fn validate_host(value: &str) -> Result<String, ConfigError> {
    if value.contains("://") || value.contains('/') {
        return Err(ConfigError::new(format!(
            "host `{value}` must be a bare host name without a scheme or path (`example.com` or `127.0.0.1`)"
        )));
    }
    crate::util::normalize_host(value).ok_or_else(|| {
        ConfigError::new(format!(
            "host `{value}` is not a valid host name (letters, digits, dots and hyphens, or an IP address)"
        ))
    })
}

/// Validate an HTTP header name (a token per RFC 9110).
///
/// # Errors
/// Returns [`ConfigError`] when the name contains characters a header name cannot contain.
pub fn validate_header_name(name: &str) -> Result<(), ConfigError> {
    if name.is_empty()
        || !name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.'))
    {
        return Err(ConfigError::new(format!(
            "origin_secret_header `{name}` is not a valid HTTP header name"
        )));
    }
    Ok(())
}

/// Validate the operator field hints.
fn validate_field_hints(hints: &[FieldHintConfig]) -> Result<(), ConfigError> {
    let mut seen = HashSet::with_capacity(hints.len());
    for hint in hints {
        if hint.field.trim().is_empty() || hint.field.len() > 256 {
            return Err(ConfigError::new(
                "field_hints: every hint needs a non-empty `field` (at most 256 characters)",
            ));
        }
        if !seen.insert(hint.field.to_ascii_lowercase()) {
            return Err(ConfigError::new(format!(
                "field_hints: duplicate hint for field `{}`; the first match wins, so list it once",
                hint.field
            )));
        }
    }
    Ok(())
}

/// Validate a custom rule (unique id, exactly one matcher, linear-time regex).
///
/// # Errors
/// Returns a message naming the invalid part of the rule.
pub fn validate_custom_rule(rule: &CustomRule) -> Result<(), ConfigError> {
    if rule.id.trim().is_empty() || rule.id.len() > 64 {
        return Err(ConfigError::new(
            "custom rule `id` must be 1 to 64 characters",
        ));
    }
    if !rule
        .id
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.'))
    {
        return Err(ConfigError::new(format!(
            "custom rule id `{}` may only contain letters, digits, `-`, `_` and `.`",
            rule.id
        )));
    }
    if rule.description.trim().is_empty() {
        return Err(ConfigError::new(format!(
            "custom rule `{}` needs a non-empty description shown in the dashboard",
            rule.id
        )));
    }
    match (rule.contains.as_deref(), rule.regex.as_deref()) {
        (Some(contains), None) => {
            if contains.is_empty() {
                return Err(ConfigError::new(format!(
                    "custom rule `{}`: `contains` must not be empty",
                    rule.id
                )));
            }
        }
        (None, Some(pattern)) => {
            if pattern.is_empty() {
                return Err(ConfigError::new(format!(
                    "custom rule `{}`: `regex` must not be empty",
                    rule.id
                )));
            }
            regex::RegexBuilder::new(pattern)
                .size_limit(MAX_RULE_REGEX_BYTES)
                .build()
                .map_err(|error| {
                    ConfigError::new(format!(
                        "custom rule `{}`: regex `{pattern}` does not compile: {error}",
                        rule.id
                    ))
                })?;
        }
        (Some(_), Some(_)) => {
            return Err(ConfigError::new(format!(
                "custom rule `{}` has both `contains` and `regex`; set exactly one matcher",
                rule.id
            )));
        }
        (None, None) => {
            return Err(ConfigError::new(format!(
                "custom rule `{}` has neither `contains` nor `regex`; set exactly one matcher",
                rule.id
            )));
        }
    }
    Ok(())
}

/// The environment variable name the add-site wizard expects for a serverless origin secret.
///
/// The name is derived from the host (`HDD_ORIGIN_SECRET_APP_EXAMPLE_COM`); the value itself must be set by the
/// operator in the process environment (R-03: no secret is ever accepted over the API or written to a file).
#[must_use]
pub fn default_origin_secret_env(host: &str) -> String {
    let mut out = String::with_capacity(ORIGIN_SECRET_ENV_PREFIX.len() + host.len());
    out.push_str(ORIGIN_SECRET_ENV_PREFIX);
    for c in host.chars() {
        if c.is_ascii_alphanumeric() {
            out.push(c.to_ascii_uppercase());
        } else {
            out.push('_');
        }
    }
    out
}

/// Build a [`SiteConfig`] from an add-site request (the wizard creates sites with sane defaults).
#[must_use]
pub fn site_config_from_create(request: &api::SiteCreateRequest) -> SiteConfig {
    let origin_secret_env = request
        .origin_secret_header
        .as_ref()
        .map(|_| default_origin_secret_env(&request.host));
    // A front-door site keeps visitors on its main address, so the verify-protection probes must use that address and
    // never the second address that only HDD uses as the origin (Addendum 7 item 3).
    let public_url = (request.connection == ConnectionMethod::VercelFrontDoor)
        .then(|| format!("https://{}", request.host.trim().to_ascii_lowercase()));
    SiteConfig {
        host: request.host.clone(),
        origin: request.origin.clone(),
        stack: Stack::default(),
        mode: request.mode,
        strictness: Strictness::default(),
        field_hints: Vec::new(),
        extra_rules: Vec::new(),
        ban: BanConfig::default(),
        preserve_host: true,
        upstream_host: request.upstream_host.clone(),
        origin_secret_header: request.origin_secret_header.clone(),
        origin_secret_env,
        public_url,
        lockdown_verified: false,
    }
}

/// Validate the origin of a front-door site: it must be a second address of the same Vercel project (Addendum 7).
///
/// The public host is the address visitors keep using. When the origin is that same address, visitors reach the app
/// without passing through HDD, so the front door would be a bypass and the site could never be honestly presented as
/// protected (R-34). The origin must be a second production domain of the same project (or another address of it),
/// added under Vercel, then the project, then Domains.
///
/// # Errors
/// Returns [`ConfigError`] when the origin is not an `http(s)` URL or its host equals the public host.
pub fn validate_front_door_origin(host: &str, origin: &str) -> Result<(), ConfigError> {
    let parsed =
        Origin::parse(origin).map_err(|message| ConfigError::new(format!("origin: {message}")))?;
    if parsed.host.eq_ignore_ascii_case(host.trim()) {
        return Err(ConfigError::new(format!(
            "the front door needs a SECOND address of the same Vercel project: the origin `{origin}` is the public \
             host `{host}`, so visitors would reach the app without passing through HDD. In Vercel open your project, \
             then Domains, add or keep a second production domain for the same project, and use that as the origin."
        )));
    }
    Ok(())
}

/// Whether a connection method map key names a known method.
#[must_use]
pub fn connection_method_from_key(key: &str) -> Option<ConnectionMethod> {
    match key {
        "dns" => Some(ConnectionMethod::Dns),
        "cloudflare" => Some(ConnectionMethod::Cloudflare),
        "nginx" => Some(ConnectionMethod::Nginx),
        "vercel" => Some(ConnectionMethod::Vercel),
        "vercel_front_door" => Some(ConnectionMethod::VercelFrontDoor),
        _ => None,
    }
}

/// Load a JSON list of sites persisted by the add-site wizard (atomic replaces of the file).
///
/// # Errors
/// Returns [`ConfigError`] when the file exists but is not a valid site list.
pub fn load_site_list(path: &Path) -> Result<Vec<SiteConfig>, ConfigError> {
    if !path.exists() {
        return Ok(Vec::new());
    }
    let text = std::fs::read_to_string(path).map_err(|error| {
        ConfigError::new(format!(
            "cannot read the persisted site list `{}`: {error}",
            path.display()
        ))
    })?;
    if text.len() > MAX_CONFIG_BYTES {
        return Err(ConfigError::new(format!(
            "the persisted site list `{}` is larger than {MAX_CONFIG_BYTES} bytes",
            path.display()
        )));
    }
    serde_json::from_str::<Vec<SiteConfig>>(&text).map_err(|error| {
        ConfigError::new(format!(
            "the persisted site list `{}` is not valid JSON: {error}",
            path.display()
        ))
    })
}

/// Persist the add-site wizard sites atomically (write a temporary file, then rename).
///
/// # Errors
/// Returns [`ConfigError`] when the directory or file cannot be written.
pub fn save_site_list(path: &Path, sites: &[SiteConfig]) -> Result<(), ConfigError> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(|error| {
            ConfigError::new(format!(
                "cannot create the data directory `{}`: {error}",
                parent.display()
            ))
        })?;
    }
    let text = serde_json::to_string_pretty(sites).map_err(|error| {
        ConfigError::new(format!("cannot serialize the persisted site list: {error}"))
    })?;
    let temporary = path.with_extension("json.tmp");
    std::fs::write(&temporary, text).map_err(|error| {
        ConfigError::new(format!(
            "cannot write the persisted site list `{}`: {error}",
            temporary.display()
        ))
    })?;
    std::fs::rename(&temporary, path).map_err(|error| {
        ConfigError::new(format!(
            "cannot replace the persisted site list `{}`: {error}",
            path.display()
        ))
    })
}

/// The `serde-saphyr` options: bounded, no anchors/aliases/merge keys, duplicate keys rejected, strict booleans.
fn yaml_options() -> serde_saphyr::Options {
    use serde_saphyr::{DuplicateKeyPolicy, MergeKeyPolicy};
    let mut budget = serde_saphyr::Budget::default();
    budget.max_aliases = 0;
    budget.max_anchors = 0;
    budget.max_depth = 16;
    budget.flow_nesting_limit = 16;
    budget.max_events = 20_000;
    budget.max_nodes = 10_000;
    budget.max_documents = 1;
    budget.max_merge_keys = 0;
    budget.max_total_scalar_bytes = MAX_CONFIG_BYTES;
    let mut options = serde_saphyr::Options::default();
    options.budget = Some(budget);
    options.duplicate_keys = DuplicateKeyPolicy::Error;
    options.merge_keys = MergeKeyPolicy::Error;
    options.strict_booleans = true;
    options
}

/// Hosts of configuration-file sites the operator removed in the panel (`removed-sites.json`); empty when the file is absent.
///
/// # Errors
/// Returns [`ConfigError`] when the file exists but cannot be read or is not a JSON array of strings.
pub fn load_removed_hosts(path: &Path) -> Result<Vec<String>, ConfigError> {
    if !path.exists() {
        return Ok(Vec::new());
    }
    let text = std::fs::read_to_string(path).map_err(|error| {
        ConfigError::new(format!(
            "cannot read the removed-site list `{}`: {error}",
            path.display()
        ))
    })?;
    if text.len() > MAX_CONFIG_BYTES {
        return Err(ConfigError::new(format!(
            "the removed-site list `{}` is larger than {MAX_CONFIG_BYTES} bytes",
            path.display()
        )));
    }
    serde_json::from_str::<Vec<String>>(&text).map_err(|error| {
        ConfigError::new(format!(
            "the removed-site list `{}` is not a JSON array of host names: {error}",
            path.display()
        ))
    })
}

/// Record that a configuration-file site was removed, so it stays removed after a restart.
///
/// # Errors
/// Returns [`ConfigError`] when the list cannot be read or written.
pub fn append_removed_host(path: &Path, host: &str) -> Result<(), ConfigError> {
    let mut hosts = load_removed_hosts(path)?;
    if !hosts
        .iter()
        .any(|existing| existing.eq_ignore_ascii_case(host))
    {
        hosts.push(host.to_ascii_lowercase());
    }
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(|error| {
            ConfigError::new(format!(
                "cannot create the data directory `{}`: {error}",
                parent.display()
            ))
        })?;
    }
    let text = serde_json::to_string_pretty(&hosts).map_err(|error| {
        ConfigError::new(format!("cannot serialize the removed-site list: {error}"))
    })?;
    let temporary = path.with_extension("json.tmp");
    std::fs::write(&temporary, text).map_err(|error| {
        ConfigError::new(format!(
            "cannot write the removed-site list `{}`: {error}",
            temporary.display()
        ))
    })?;
    std::fs::rename(&temporary, path).map_err(|error| {
        ConfigError::new(format!(
            "cannot replace the removed-site list `{}`: {error}",
            path.display()
        ))
    })
}

/// The header name HDD uses for a generated origin secret.
pub const DEFAULT_ORIGIN_SECRET_HEADER: &str = "X-HDD-Origin-Secret";

/// The owner-only file that holds the generated origin secret for `host` (inside the data directory).
#[must_use]
pub fn origin_secret_path(data_dir: &Path, host: &str) -> PathBuf {
    let name: String = host
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() {
                c.to_ascii_lowercase()
            } else {
                '_'
            }
        })
        .collect();
    data_dir
        .join("origin-secrets")
        .join(format!("{name}.secret"))
}

/// A fresh random origin secret: 32 bytes from the operating system, hex encoded.
///
/// # Errors
/// Returns [`ConfigError`] when the operating system random source is unavailable.
pub fn generate_origin_secret() -> Result<String, ConfigError> {
    let mut bytes = [0_u8; 32];
    getrandom::fill(&mut bytes)
        .map_err(|error| ConfigError::new(format!("cannot generate a random secret: {error}")))?;
    let mut out = String::with_capacity(64);
    for byte in bytes {
        out.push_str(&format!("{byte:02x}"));
    }
    Ok(out)
}

/// Write a generated origin secret to its owner-only file (never to the YAML, R-03).
///
/// # Errors
/// Returns [`ConfigError`] when the file cannot be written.
pub fn write_origin_secret(path: &Path, value: &str) -> Result<(), ConfigError> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(|error| {
            ConfigError::new(format!(
                "cannot create the secret directory `{}`: {error}",
                parent.display()
            ))
        })?;
    }
    std::fs::write(path, value).map_err(|error| {
        ConfigError::new(format!(
            "cannot write the origin secret file `{}`: {error}",
            path.display()
        ))
    })?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).map_err(
            |error| {
                ConfigError::new(format!(
                    "cannot restrict the origin secret file `{}`: {error}",
                    path.display()
                ))
            },
        )?;
    }
    Ok(())
}

/// Read a generated origin secret, when its file exists and is not empty.
#[must_use]
pub fn read_origin_secret(path: &Path) -> Option<String> {
    let text = std::fs::read_to_string(path).ok()?;
    let trimmed = text.trim();
    if trimmed.is_empty() {
        None
    } else {
        Some(trimmed.to_owned())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn minimal_yaml() -> String {
        r#"
data_dir: "test-data"
log_path: "test-data/events.jsonl"
admin_token_env: TEST_ADMIN_TOKEN
sites:
  - host: "demo.test"
    origin: "http://127.0.0.1:8081"
    mode: block
"#
        .to_owned()
    }

    #[test]
    fn defaults_are_documented_values() {
        let config = Config::parse_str(&minimal_yaml()).expect("minimal config parses");
        assert_eq!(config.listen, api::DEFAULT_PROXY_LISTEN);
        assert_eq!(config.admin_listen, api::DEFAULT_ADMIN_LISTEN);
        let validated = config.validate().expect("minimal config validates");
        assert_eq!(validated.sites.len(), 1);
        let site = validated.sites.first().expect("one site");
        assert_eq!(site.host, "demo.test");
        assert!(site.ban_enabled);
        assert_eq!(site.ladder, vec![60, 600, 3600]);
        assert!(!site.origin.https);
        assert_eq!(site.origin.port, 8081);
    }

    #[test]
    fn unknown_keys_are_rejected() {
        let yaml = minimal_yaml().replace("mode: block", "mode: block\n    nonsense: true");
        let error = Config::parse_str(&yaml).expect_err("unknown key is rejected");
        assert!(
            error.message.contains("nonsense"),
            "message: {}",
            error.message
        );
    }

    #[test]
    fn bad_origin_scheme_is_rejected_with_a_clear_error() {
        let yaml = minimal_yaml().replace("http://127.0.0.1:8081", "ftp://127.0.0.1:8081");
        let config = Config::parse_str(&yaml).expect("yaml still parses");
        let error = config.validate().expect_err("ftp origin is rejected");
        assert!(error.message.contains("ftp"), "message: {}", error.message);
    }

    #[test]
    fn missing_admin_token_environment_variable_refuses_to_start() {
        let validated = Config::parse_str(&minimal_yaml())
            .expect("parses")
            .validate()
            .expect("validates");
        let error = validated
            .resolve_secrets(|_| None)
            .expect_err("missing admin token is an error");
        assert!(
            error.message.contains("TEST_ADMIN_TOKEN"),
            "message: {}",
            error.message
        );
        let secrets = validated
            .resolve_secrets(|name| (name == "TEST_ADMIN_TOKEN").then(|| "bootstrap".to_owned()))
            .expect("token resolves");
        assert_eq!(secrets.admin_token, "bootstrap");
    }

    #[test]
    fn duplicate_hosts_and_same_listener_are_rejected() {
        let yaml = minimal_yaml()
            + "  - host: \"demo.test\"\n    origin: \"http://127.0.0.1:8082\"\n    mode: monitor\n";
        let config = Config::parse_str(&yaml).expect("parses");
        assert!(config.validate().is_err());
        let mut same_listener = Config::parse_str(&minimal_yaml()).expect("parses");
        same_listener.admin_listen = "127.0.0.1:9999".to_owned();
        same_listener.listen = "127.0.0.1:9999".to_owned();
        assert!(same_listener.validate().is_err());
    }

    #[test]
    fn custom_rules_are_validated() {
        let valid = CustomRule {
            id: "C-1".to_owned(),
            vector: None,
            contains: Some("union select".to_owned()),
            regex: None,
            action: hdd_waf_core::Action::Block,
            description: "demo day rule".to_owned(),
        };
        assert!(validate_custom_rule(&valid).is_ok());
        let both = CustomRule {
            regex: Some("un.*select".to_owned()),
            ..valid.clone()
        };
        assert!(validate_custom_rule(&both).is_err());
        let broken = CustomRule {
            id: "C-2".to_owned(),
            regex: Some("(unclosed".to_owned()),
            contains: None,
            ..valid
        };
        assert!(validate_custom_rule(&broken).is_err());
    }

    #[test]
    fn origin_secret_env_defaults_from_host_and_must_be_present() {
        let yaml = minimal_yaml().replace(
            "mode: block",
            "mode: block\n    origin_secret_header: X-Origin-Secret",
        );
        let validated = Config::parse_str(&yaml)
            .expect("parses")
            .validate()
            .expect("validates");
        let site = validated.sites.first().expect("one site");
        assert_eq!(
            site.config.origin_secret_env.as_deref(),
            Some("HDD_ORIGIN_SECRET_DEMO_TEST")
        );
        let error = validated
            .resolve_secrets(|name| (name == "TEST_ADMIN_TOKEN").then(|| "bootstrap".to_owned()))
            .expect_err("origin secret env missing");
        assert!(error.message.contains("HDD_ORIGIN_SECRET_DEMO_TEST"));
        let secrets = validated
            .resolve_secrets(|name| match name {
                "TEST_ADMIN_TOKEN" => Some("bootstrap".to_owned()),
                "HDD_ORIGIN_SECRET_DEMO_TEST" => Some("origin-secret".to_owned()),
                _ => None,
            })
            .expect("both secrets resolve");
        assert_eq!(
            secrets.origin_secrets.get("demo.test").map(String::as_str),
            Some("origin-secret")
        );
    }

    #[test]
    fn non_loopback_admin_listener_requires_the_explicit_ack() {
        let mut config = Config::parse_str(&minimal_yaml()).expect("minimal config parses");
        config.admin_listen = "0.0.0.0:9090".to_owned();
        let error = config
            .validate()
            .expect_err("a non-loopback admin listener is refused by default");
        assert!(
            error.message.contains("admin_non_loopback_ack"),
            "message: {}",
            error.message
        );
        config.admin_non_loopback_ack = true;
        let validated = config.validate().expect("the explicit ack allows it");
        assert!(validated.admin_non_loopback_ack);
        assert!(!validated.admin_listen.ip().is_loopback());
        let loopback = Config::parse_str(&minimal_yaml()).expect("minimal config parses");
        let validated = loopback.validate().expect("loopback is always fine");
        assert!(validated.admin_listen.ip().is_loopback());
        assert!(!validated.admin_non_loopback_ack);
    }

    #[test]
    fn environment_variable_names_are_validated() {
        assert!(validate_env_name("admin_token_env", "HDD_ADMIN_TOKEN").is_ok());
        assert!(validate_env_name("admin_token_env", "1BAD").is_err());
        assert!(validate_env_name("admin_token_env", "BAD-NAME").is_err());
        assert!(validate_env_name("admin_token_env", "").is_err());
    }

    #[test]
    fn front_door_origin_must_be_a_second_address_of_the_same_project() {
        let host = "hdd-demo-shop.vercel.app";
        // The public host itself is refused: visitors would reach the app without passing through HDD.
        let error = validate_front_door_origin(host, "https://hdd-demo-shop.vercel.app")
            .expect_err("the public host cannot be the front-door origin");
        let message = error.message.to_lowercase();
        assert!(
            message.contains("second address"),
            "message: {}",
            error.message
        );
        assert!(
            message.contains("same vercel project"),
            "message: {}",
            error.message
        );
        assert!(
            validate_front_door_origin(host, "https://HDD-DEMO-SHOP.vercel.app").is_err(),
            "the address comparison is case-insensitive"
        );
        // A second address of the same project is accepted, and so is any other host the operator maps.
        assert!(
            validate_front_door_origin(host, "https://hdd-demo-shop-git-main-team.vercel.app")
                .is_ok()
        );
        assert!(validate_front_door_origin(host, "https://hdd-demo-shop-2.vercel.app").is_ok());
        assert!(validate_front_door_origin(host, "https://shop.example.com").is_ok());
        // A malformed origin is still refused by the shared origin parser.
        assert!(validate_front_door_origin(host, "not-a-url").is_err());
    }

    #[test]
    fn a_front_door_site_records_the_main_address_as_its_public_url() {
        let request = api::SiteCreateRequest {
            host: "hdd-demo-shop.vercel.app".to_owned(),
            origin: "https://hdd-demo-shop-2.vercel.app".to_owned(),
            mode: Mode::Monitor,
            connection: ConnectionMethod::VercelFrontDoor,
            upstream_host: Some("hdd-demo-shop-2.vercel.app".to_owned()),
            origin_secret_header: Some("x-hdd-origin-secret".to_owned()),
            generate_origin_secret: true,
        };
        let config = site_config_from_create(&request);
        assert_eq!(
            config.public_url.as_deref(),
            Some("https://hdd-demo-shop.vercel.app"),
            "verify probes must use the public host, not the second address"
        );
        // The default Vercel path is unchanged: no public_url, the verify protection keeps its fallback.
        let plain = site_config_from_create(&api::SiteCreateRequest {
            connection: ConnectionMethod::Vercel,
            ..request
        });
        assert_eq!(plain.public_url, None);
    }

    #[test]
    fn the_front_door_connection_key_is_recognised() {
        assert_eq!(
            connection_method_from_key("vercel_front_door"),
            Some(ConnectionMethod::VercelFrontDoor)
        );
        assert_eq!(
            connection_method_from_key("vercel"),
            Some(ConnectionMethod::Vercel)
        );
    }
}
