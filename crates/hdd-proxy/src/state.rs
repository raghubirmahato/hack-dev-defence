//! The runtime state shared by both listeners: the site table (config-derived plus wizard-created sites), the event
//! ring/JSONL log, the ban store, the counters, the configuration revision and the authenticator seam.
//!
//! The authenticator seam ([`AdminAuth`]) is what lets the admin integration tests run without the accounts module
//! while the production binary wires teammate D's real [`crate::accounts::AccountStore`] (see [`crate::auth`]).
//! Nothing in the data path can panic: poisoned locks are recovered through [`crate::util::lock`].

use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU8, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, RwLock};
use std::time::{Duration, Instant};

use hdd_waf_core::{SiteSettings, Stack, Strictness};

use crate::ai::AiRuntime;
use crate::api::{
    self, ApiRequest, ApiResponse, BanView, Counters, EventView, FieldHintView, HealthView, Mode,
    Principal, Protection, SiteView,
};
use crate::ban::BanStore;
use crate::blockpage::Page;
use crate::config::{self, ConfigError, ResolvedSecrets, SiteConfig, Validated, ValidatedSite};
use crate::events::EventStore;
use crate::findings::{FindingsStore, stack_name};
use crate::forward::{Forwarder, Upstream};
use crate::util::{self, Cidr};

/// The global request counters (all sites, since start).
#[derive(Debug, Default)]
pub struct GlobalCounters {
    /// Requests seen on the proxy listener for a configured site.
    pub requests: AtomicU64,
    /// Requests refused by the proxy (block verdicts and early bans).
    pub blocked: AtomicU64,
    /// Requests recorded as `would_block` in monitor mode.
    pub would_block: AtomicU64,
}

/// One configured site at runtime: immutable route/origin configuration plus the mutable mode, detector settings,
/// lockdown state and counters.
pub struct SiteRuntime {
    /// The normalised configuration (host, origin string, ban policy, secret header names).
    config: SiteConfig,
    /// The parsed origin.
    origin: util::Origin,
    /// The site's stack hint, used for finding remediation examples (Addendum 6).
    stack: Stack,
    /// The protection mode.
    mode: AtomicU8,
    /// The detector settings (strictness, field hints, extra rules).
    settings: Mutex<SiteSettings>,
    /// Whether the origin secret value is available (the value itself lives in `secret_value`, never in a view).
    secret_value: Option<String>,
    /// The per-site request counter.
    requests: AtomicU64,
    /// The per-site blocked counter.
    blocked: AtomicU64,
    /// Whether the origin lockdown check passed (R-34: a site is not "protected" without it).
    lockdown_verified: std::sync::atomic::AtomicBool,
}

impl SiteRuntime {
    /// Build the runtime site from a validated file site and its resolved origin secret.
    #[must_use]
    pub fn new(validated: &ValidatedSite, secret_value: Option<String>) -> Self {
        Self {
            config: validated.config.clone(),
            origin: validated.origin.clone(),
            stack: validated.stack,
            mode: AtomicU8::new(mode_code(validated.config.mode)),
            settings: Mutex::new(validated.settings.clone()),
            secret_value,
            requests: AtomicU64::new(0),
            blocked: AtomicU64::new(0),
            lockdown_verified: std::sync::atomic::AtomicBool::new(
                validated.config.lockdown_verified,
            ),
        }
    }

    /// The normalised host name.
    #[must_use]
    pub fn host(&self) -> &str {
        &self.config.host
    }

    /// The parsed origin.
    #[must_use]
    pub fn origin(&self) -> &util::Origin {
        &self.origin
    }

    /// The upstream connection target.
    #[must_use]
    pub fn upstream(&self) -> Upstream {
        Upstream::from_origin(&self.origin)
    }

    /// The origin URL as configured (shown on the Sites screen).
    #[must_use]
    pub fn origin_display(&self) -> &str {
        &self.config.origin
    }

    /// The site's stack hint (picks a finding's remediation code example; Addendum 6).
    #[must_use]
    pub fn stack(&self) -> Stack {
        self.stack
    }

    /// The current protection mode.
    #[must_use]
    pub fn mode(&self) -> Mode {
        match self.mode.load(Ordering::Relaxed) {
            0 => Mode::Off,
            2 => Mode::Block,
            _ => Mode::Monitor,
        }
    }

    /// Set the protection mode.
    pub fn set_mode(&self, mode: Mode) {
        self.mode.store(mode_code(mode), Ordering::Relaxed);
    }

    /// A snapshot of the detector settings.
    #[must_use]
    pub fn settings_snapshot(&self) -> SiteSettings {
        util::lock(&self.settings).clone()
    }

    /// The current strictness.
    #[must_use]
    pub fn strictness(&self) -> Strictness {
        util::lock(&self.settings).strictness
    }

    /// Set the strictness, returning the previous one for the audit line.
    pub fn set_strictness(&self, strictness: Strictness) -> Strictness {
        let mut settings = util::lock(&self.settings);
        let previous = settings.strictness;
        settings.strictness = strictness;
        previous
    }

    /// Add a custom rule, returning `false` when the id already exists.
    pub fn add_rule(&self, rule: hdd_waf_core::CustomRule) -> bool {
        let mut settings = util::lock(&self.settings);
        if settings
            .extra_rules
            .iter()
            .any(|existing| existing.id == rule.id)
        {
            return false;
        }
        settings.extra_rules.push(rule);
        true
    }

    /// Remove a custom rule by id, returning whether it existed.
    pub fn remove_rule(&self, id: &str) -> bool {
        let mut settings = util::lock(&self.settings);
        let before = settings.extra_rules.len();
        settings.extra_rules.retain(|rule| rule.id != id);
        settings.extra_rules.len() != before
    }

    /// The custom rules, for the sites API and the audit detail.
    #[must_use]
    pub fn rules(&self) -> Vec<hdd_waf_core::CustomRule> {
        util::lock(&self.settings).extra_rules.clone()
    }

    /// The operator field hints, for the sites API.
    #[must_use]
    pub fn field_hints(&self) -> Vec<FieldHintView> {
        util::lock(&self.settings)
            .field_hints
            .iter()
            .map(|(field, kind)| FieldHintView {
                field: field.clone(),
                kind: *kind,
            })
            .collect()
    }

    /// Whether bans are enabled for this site.
    #[must_use]
    pub fn ban_enabled(&self) -> bool {
        self.config.ban.enabled
    }

    /// The progressive TTL ladder.
    #[must_use]
    pub fn ladder(&self) -> &[u64] {
        &self.config.ban.ttl_ladder_seconds
    }

    /// The origin secret header name, when configured.
    #[must_use]
    pub fn origin_secret_header(&self) -> Option<&str> {
        self.config.origin_secret_header.as_deref()
    }

    /// The origin secret value, when resolved at start-up (never returned by an API).
    #[must_use]
    pub fn origin_secret_value(&self) -> Option<&str> {
        self.secret_value.as_deref()
    }

    /// Whether an origin secret value is available.
    #[must_use]
    pub fn origin_secret_configured(&self) -> bool {
        self.secret_value.is_some()
    }

    /// The public URL used by the verify probes, when configured.
    #[must_use]
    pub fn public_url(&self) -> Option<&str> {
        self.config.public_url.as_deref()
    }

    /// Whether the incoming `Host` is preserved upstream.
    #[must_use]
    pub fn preserve_host(&self) -> bool {
        self.config.preserve_host
    }

    /// The upstream `Host` override, when configured.
    #[must_use]
    pub fn upstream_host(&self) -> Option<&str> {
        self.config.upstream_host.as_deref()
    }

    /// Whether the origin lockdown check passed.
    #[must_use]
    pub fn lockdown_verified(&self) -> bool {
        self.lockdown_verified.load(Ordering::Relaxed)
    }

    /// Record the origin lockdown check result.
    pub fn set_lockdown_verified(&self, verified: bool) {
        self.lockdown_verified.store(verified, Ordering::Relaxed);
    }

    /// Count one request seen for this site and return the new total.
    pub fn note_request(&self) -> u64 {
        self.requests.fetch_add(1, Ordering::Relaxed) + 1
    }

    /// Count one refused request for this site.
    pub fn note_blocked(&self) {
        self.blocked.fetch_add(1, Ordering::Relaxed);
    }

    /// The number of requests seen for this site since start.
    #[must_use]
    pub fn request_count(&self) -> u64 {
        self.requests.load(Ordering::Relaxed)
    }

    /// The number of blocked requests for this site since start.
    #[must_use]
    pub fn blocked_count(&self) -> u64 {
        self.blocked.load(Ordering::Relaxed)
    }

    /// The effective, honest protection state (R-34: block mode without a verified lockdown is not "protected").
    #[must_use]
    pub fn protection(&self) -> Protection {
        match self.mode() {
            Mode::Off => Protection::Off,
            Mode::Monitor => Protection::Monitoring,
            Mode::Block => {
                if self.lockdown_verified() {
                    Protection::BlockingLocked
                } else {
                    Protection::BlockingUnverified
                }
            }
        }
    }

    /// The API view of this site.
    #[must_use]
    pub fn view(&self) -> SiteView {
        SiteView {
            host: self.config.host.clone(),
            origin: self.config.origin.clone(),
            stack: stack_name(self.stack).to_owned(),
            mode: self.mode(),
            strictness: self.strictness(),
            protection: self.protection(),
            ban_enabled: self.config.ban.enabled,
            ttl_ladder_seconds: self.config.ban.ttl_ladder_seconds.clone(),
            field_hints: self.field_hints(),
            rules: self.rules(),
            upstream_host: self.config.upstream_host.clone(),
            origin_secret_header: self.config.origin_secret_header.clone(),
            origin_secret_configured: self.origin_secret_configured(),
            lockdown_verified: self.lockdown_verified(),
            requests: self.request_count(),
            blocked: self.blocked_count(),
        }
    }

    /// A configuration snapshot with the runtime changes applied (persisted by the add-site wizard).
    #[must_use]
    pub fn config_snapshot(&self) -> SiteConfig {
        let settings = util::lock(&self.settings);
        let mut config = self.config.clone();
        config.mode = self.mode();
        config.strictness = settings.strictness;
        config.field_hints = settings
            .field_hints
            .iter()
            .map(|(field, kind)| config::FieldHintConfig {
                field: field.clone(),
                kind: *kind,
            })
            .collect();
        config.extra_rules = settings.extra_rules.clone();
        config.lockdown_verified = self.lockdown_verified();
        config
    }
}

/// Map a mode to its storage code.
fn mode_code(mode: Mode) -> u8 {
    match mode {
        Mode::Off => 0,
        Mode::Monitor => 1,
        Mode::Block => 2,
    }
}

/// The authenticator seam: the production implementation is [`crate::auth::AccountAuth`] over D's `AccountStore`;
/// the admin integration tests implement it directly with a fixed bearer token, which keeps the core tests
/// independent of the accounts module without weakening the production path.
pub trait AdminAuth: Send + Sync + 'static {
    /// Authenticate an admin request (session cookie or bearer API token).
    fn authenticate(&self, request: &ApiRequest) -> Option<Principal>;
    /// Whether the first-run setup wizard is still required (no owner account exists).
    fn setup_required(&self) -> bool;
    /// Dispatch the accounts routes; `None` means "not an accounts path".
    fn handle_accounts(
        &self,
        request: &ApiRequest,
        principal: Option<&Principal>,
        client_ip: &str,
        loopback: bool,
    ) -> Option<ApiResponse>;
}

/// The shared runtime state.
pub struct AppState {
    /// When the process started.
    started: Instant,
    /// The binary version reported by `/healthz`.
    version: &'static str,
    /// The configured sites, in configuration order.
    sites: RwLock<Vec<Arc<SiteRuntime>>>,
    /// The trusted proxy CIDR blocks.
    pub trusted_proxies: Vec<Cidr>,
    /// The event ring and JSONL log.
    pub events: EventStore,
    /// The ban store.
    pub bans: BanStore,
    /// The global counters.
    pub counters: GlobalCounters,
    /// The configuration revision (incremented by every admin mutation).
    config_revision: AtomicU64,
    /// The authenticator seam.
    pub auth: Arc<dyn AdminAuth>,
    /// The number of handler panics caught and contained (R-09).
    caught_panics: AtomicU64,
    /// The origin forwarder.
    pub forwarder: Forwarder,
    /// The owner-only data directory (`sites.json` lives here).
    data_dir: PathBuf,
    /// The bound proxy listener address (set after binding; used by the verify probes).
    proxy_addr: RwLock<Option<SocketAddr>>,
    /// The bound admin listener address (set after binding).
    admin_addr: RwLock<Option<SocketAddr>>,
    /// The sites created through the add-site wizard (persisted to `sites.json`).
    dynamic_sites: Mutex<Vec<Arc<SiteRuntime>>>,
    /// The number of connections currently being served (review R1-7 concurrent-connection cap).
    active_connections: AtomicU64,
    /// The in-memory findings engine (Addendum 6 item 1).
    pub findings: Arc<FindingsStore>,
    /// The optional AI explanation runtime (Addendum 6 item 3); disabled without the API key.
    pub ai: Arc<AiRuntime>,
}

/// The maximum number of connections served concurrently.
///
/// Overflow connections are refused with an opaque 503 page and closed immediately (review R1-7). The cap is well
/// above the demo's needs and keeps a connection flood (or a slowloris herd) from exhausting file descriptors.
pub const MAX_CONNECTIONS: u64 = 256;

/// A reserved connection slot; dropping it releases the concurrent-connection counter.
pub struct ConnectionGuard {
    /// The state whose counter is decremented.
    state: Arc<AppState>,
}

impl Drop for ConnectionGuard {
    fn drop(&mut self) {
        self.state
            .active_connections
            .fetch_sub(1, Ordering::Relaxed);
    }
}

impl AppState {
    /// Build the runtime state with the production AI runtime (key read from the environment at call time).
    ///
    /// # Errors
    /// Returns a [`ConfigError`] when a directory or log file cannot be created, a persisted site is invalid, or a
    /// persisted site collides with a configured one.
    pub fn new(
        validated: &Validated,
        secrets: &ResolvedSecrets,
        auth: Arc<dyn AdminAuth>,
    ) -> Result<Arc<Self>, ConfigError> {
        let ai = Arc::new(AiRuntime::new(
            validated,
            Arc::new(|name: &str| std::env::var(name).ok()),
        ));
        Self::new_with_ai(validated, secrets, auth, ai)
    }

    /// Build the runtime state with an explicit AI runtime (the test seam for the enabled-AI paths).
    ///
    /// # Errors
    /// Returns a [`ConfigError`] when a directory or log file cannot be created, a persisted site is invalid, or a
    /// persisted site collides with a configured one.
    pub fn new_with_ai(
        validated: &Validated,
        secrets: &ResolvedSecrets,
        auth: Arc<dyn AdminAuth>,
        ai: Arc<AiRuntime>,
    ) -> Result<Arc<Self>, ConfigError> {
        std::fs::create_dir_all(&validated.data_dir).map_err(|error| ConfigError {
            message: format!(
                "cannot create the data directory `{}`: {error}",
                validated.data_dir.display()
            ),
        })?;
        let events =
            EventStore::open(&validated.log_path).map_err(|message| ConfigError { message })?;
        let mut sites: Vec<Arc<SiteRuntime>> = Vec::with_capacity(validated.sites.len());
        for site in &validated.sites {
            let secret = secrets.origin_secrets.get(&site.host).cloned();
            sites.push(Arc::new(SiteRuntime::new(site, secret)));
        }
        // Sites the operator removed in the panel stay removed even though the configuration file still lists them.
        let removed = config::load_removed_hosts(&validated.data_dir.join("removed-sites.json"))?;
        sites.retain(|site| {
            !removed
                .iter()
                .any(|host| host.eq_ignore_ascii_case(site.host()))
        });
        let state = Arc::new(Self {
            started: Instant::now(),
            version: env!("CARGO_PKG_VERSION"),
            sites: RwLock::new(sites),
            trusted_proxies: validated.trusted_proxies.clone(),
            events,
            bans: BanStore::new(),
            counters: GlobalCounters::default(),
            config_revision: AtomicU64::new(1),
            auth,
            caught_panics: AtomicU64::new(0),
            forwarder: Forwarder::new(),
            data_dir: validated.data_dir.clone(),
            proxy_addr: RwLock::new(None),
            admin_addr: RwLock::new(None),
            dynamic_sites: Mutex::new(Vec::new()),
            active_connections: AtomicU64::new(0),
            findings: Arc::new(FindingsStore::new()),
            ai,
        });
        state.load_persisted_sites()?;
        Ok(state)
    }

    /// Load `sites.json` from the data directory (wizard-created sites survive a restart).
    fn load_persisted_sites(&self) -> Result<(), ConfigError> {
        let path = self.data_dir.join("sites.json");
        let persisted = config::load_site_list(&path)?;
        for site_config in persisted {
            let validated = self
                .validated_site_placeholder()
                .validate_one(site_config)
                .map_err(|error| ConfigError {
                    message: format!(
                        "persisted site in `{}` is invalid: {}",
                        path.display(),
                        error.message
                    ),
                })?;
            let secret_env = validated.config.origin_secret_env.clone();
            let secret_value = match secret_env {
                Some(env_name) => {
                    let value = std::env::var(&env_name)
                        .ok()
                        .filter(|v| !v.trim().is_empty())
                        .or_else(|| {
                            config::read_origin_secret(&config::origin_secret_path(
                                &self.data_dir,
                                &validated.host,
                            ))
                        });
                    if value.is_none() {
                        return Err(ConfigError {
                            message: format!(
                                "persisted site `{}` needs its origin secret environment variable `{env_name}` \
                                 to be set",
                                validated.host
                            ),
                        });
                    }
                    value
                }
                None => None,
            };
            let runtime = Arc::new(SiteRuntime::new(&validated, secret_value));
            {
                let mut sites = match self.sites.write() {
                    Ok(guard) => guard,
                    Err(poisoned) => poisoned.into_inner(),
                };
                if sites
                    .iter()
                    .any(|existing| existing.host() == runtime.host())
                {
                    return Err(ConfigError {
                        message: format!(
                            "persisted site `{}` collides with a site configured in the YAML file",
                            runtime.host()
                        ),
                    });
                }
                sites.push(Arc::clone(&runtime));
            }
            let mut dynamic = util::lock(&self.dynamic_sites);
            dynamic.push(runtime);
        }
        Ok(())
    }

    /// A validation context that applies the per-site rules without the configured site list (host uniqueness is
    /// checked by [`AppState::add_site`] against the live table instead).
    fn validated_site_placeholder(&self) -> Validated {
        Validated {
            listen: SocketAddr::from(([127, 0, 0, 1], 0)),
            admin_listen: SocketAddr::from(([127, 0, 0, 1], 0)),
            trusted_proxies: self.trusted_proxies.clone(),
            data_dir: self.data_dir.clone(),
            log_path: self.data_dir.join("events.jsonl"),
            admin_token_env: String::new(),
            admin_non_loopback_ack: false,
            ai: None,
            sites: Vec::new(),
        }
    }

    /// Validate one additional site (used by the add-site wizard) against the same per-site rules as the file config.
    ///
    /// # Errors
    /// Returns the first violation with an operator-readable message.
    pub fn validate_site(&self, config: SiteConfig) -> Result<ValidatedSite, ConfigError> {
        self.validated_site_placeholder().validate_one(config)
    }

    /// Persist the wizard-created sites only when there are any (mutations of file-configured sites need no file).
    ///
    /// # Errors
    /// Returns [`ConfigError`] when the persisted list cannot be written.
    pub fn persist_dynamic_sites_if_any(&self) -> Result<(), ConfigError> {
        if util::lock(&self.dynamic_sites).is_empty() {
            return Ok(());
        }
        self.persist_dynamic_sites()
    }

    /// Look up a site by its normalised host name.
    #[must_use]
    pub fn site(&self, host: &str) -> Option<Arc<SiteRuntime>> {
        let sites = match self.sites.read() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        };
        sites
            .iter()
            .find(|site| site.host().eq_ignore_ascii_case(host))
            .cloned()
    }

    /// All sites in configuration order.
    #[must_use]
    pub fn sites(&self) -> Vec<Arc<SiteRuntime>> {
        match self.sites.read() {
            Ok(guard) => guard.clone(),
            Err(poisoned) => poisoned.into_inner().clone(),
        }
    }

    /// The configured host names (newest configuration order).
    #[must_use]
    pub fn hosts(&self) -> Vec<String> {
        self.sites()
            .iter()
            .map(|site| site.host().to_owned())
            .collect()
    }

    /// The site views for the Sites screen and the proxy dashboard cards.
    #[must_use]
    pub fn site_views(&self) -> Vec<SiteView> {
        self.sites().iter().map(|site| site.view()).collect()
    }

    /// The live counters (counters come from the retained events plus the active ban store).
    #[must_use]
    pub fn counters(&self) -> Counters {
        self.events.counters(self.bans.active_count())
    }

    /// The current configuration revision.
    #[must_use]
    pub fn revision(&self) -> u64 {
        self.config_revision.load(Ordering::Relaxed)
    }

    /// Increment the configuration revision and return the new value.
    pub fn bump_revision(&self) -> u64 {
        self.config_revision.fetch_add(1, Ordering::Relaxed) + 1
    }

    /// The binary version.
    #[must_use]
    pub fn version(&self) -> &'static str {
        self.version
    }

    /// Seconds since start.
    #[must_use]
    pub fn uptime_seconds(&self) -> u64 {
        self.started.elapsed().as_secs()
    }

    /// The `/healthz` view.
    #[must_use]
    pub fn health(&self) -> HealthView {
        HealthView {
            status: "ok".to_owned(),
            version: self.version.to_owned(),
            uptime_seconds: self.uptime_seconds(),
            sites: self.sites().len(),
            accounts_ready: !self.auth.setup_required(),
        }
    }

    /// Register the bound listener addresses (called by the server after binding).
    pub fn set_listener_addrs(&self, proxy: SocketAddr, admin: SocketAddr) {
        if let Ok(mut slot) = self.proxy_addr.write() {
            *slot = Some(proxy);
        }
        if let Ok(mut slot) = self.admin_addr.write() {
            *slot = Some(admin);
        }
    }

    /// The bound proxy listener address, when the server has started.
    #[must_use]
    pub fn proxy_addr(&self) -> Option<SocketAddr> {
        match self.proxy_addr.read() {
            Ok(guard) => *guard,
            Err(poisoned) => *poisoned.into_inner(),
        }
    }

    /// The bound admin listener address, when the server has started.
    #[must_use]
    pub fn admin_addr(&self) -> Option<SocketAddr> {
        match self.admin_addr.read() {
            Ok(guard) => *guard,
            Err(poisoned) => *poisoned.into_inner(),
        }
    }

    /// The base URL of the proxy listener (the verify fallback target when a site has no `public_url`).
    #[must_use]
    pub fn proxy_base_url(&self) -> String {
        match self.proxy_addr() {
            Some(address) => format!("http://{address}"),
            None => format!("http://{}", api::DEFAULT_PROXY_LISTEN),
        }
    }

    /// Count one caught handler panic (R-09: caught and alerted, never reachable from the network).
    pub fn note_caught_panic(&self) {
        self.caught_panics.fetch_add(1, Ordering::Relaxed);
    }

    /// How many handler panics were caught since start.
    #[must_use]
    pub fn caught_panics(&self) -> u64 {
        self.caught_panics.load(Ordering::Relaxed)
    }

    /// Add a site created by the add-site wizard and persist the dynamic site list.
    ///
    /// # Errors
    /// Returns [`ConfigError`] when the host already exists or the persisted list cannot be written.
    pub fn add_site(&self, runtime: Arc<SiteRuntime>) -> Result<(), ConfigError> {
        {
            let mut sites = match self.sites.write() {
                Ok(guard) => guard,
                Err(poisoned) => poisoned.into_inner(),
            };
            if sites
                .iter()
                .any(|existing| existing.host() == runtime.host())
            {
                return Err(ConfigError {
                    message: format!("a site for host `{}` already exists", runtime.host()),
                });
            }
            sites.push(Arc::clone(&runtime));
        }
        {
            let mut dynamic = util::lock(&self.dynamic_sites);
            dynamic.push(runtime);
        }
        self.bump_revision();
        self.persist_dynamic_sites()
    }

    /// Remove a site from the live table and remember the decision across restarts.
    ///
    /// A wizard-created site is dropped from `sites.json`. A site from the configuration file cannot be edited by the
    /// process, so its host is recorded in `removed-sites.json` and skipped at the next start. Events and bans stay.
    ///
    /// # Errors
    /// Returns [`ConfigError`] when no such site exists or the decision cannot be written.
    pub fn remove_site(&self, host: &str) -> Result<(), ConfigError> {
        let removed_host = {
            let mut sites = match self.sites.write() {
                Ok(guard) => guard,
                Err(poisoned) => poisoned.into_inner(),
            };
            let Some(index) = sites
                .iter()
                .position(|site| site.host().eq_ignore_ascii_case(host))
            else {
                return Err(ConfigError {
                    message: format!("no site is configured for host `{host}`"),
                });
            };
            sites.remove(index).host().to_owned()
        };
        let was_dynamic = {
            let mut dynamic = util::lock(&self.dynamic_sites);
            let before = dynamic.len();
            dynamic.retain(|site| !site.host().eq_ignore_ascii_case(host));
            dynamic.len() != before
        };
        self.bump_revision();
        // A generated origin secret belongs to the site: remove its file with the site.
        let _ = std::fs::remove_file(config::origin_secret_path(&self.data_dir, &removed_host));
        if was_dynamic {
            self.persist_dynamic_sites()
        } else {
            config::append_removed_host(&self.data_dir.join("removed-sites.json"), &removed_host)
        }
    }

    /// Persist the wizard-created sites atomically (mode/strictness/rule changes included).
    ///
    /// # Errors
    /// Returns [`ConfigError`] when the file cannot be written.
    pub fn persist_dynamic_sites(&self) -> Result<(), ConfigError> {
        let snapshots: Vec<SiteConfig> = {
            let dynamic = util::lock(&self.dynamic_sites);
            dynamic.iter().map(|site| site.config_snapshot()).collect()
        };
        let path = self.data_dir.join("sites.json");
        config::save_site_list(&path, &snapshots)
    }

    /// Record one request event: append it to the event log/ring and, for a blocked *detector* event, fold it into the
    /// findings engine (Addendum 6 item 1). `would_block`/`allow`, early-ban refusals and body-cap refusals stay in the
    /// event log only: they are not a newly detected attack shape.
    pub fn record_event(&self, event: EventView) -> u64 {
        if event.action == "block"
            && event.rule_id.is_some()
            && let Some(site) = self.site(&event.site)
        {
            let _ = self.findings.record(&event, site.stack());
        }
        self.events.record(event)
    }

    /// The page for an unexpected handler panic (R-09: a panic becomes an error page, never a crash).
    #[must_use]
    pub fn panic_page(&self, ray_id: &str, json: bool) -> Page {
        self.note_caught_panic();
        crate::blockpage::internal_error(ray_id, json)
    }

    /// The duration the process has been running, used by the About screen through `/healthz`.
    #[must_use]
    pub fn started(&self) -> Instant {
        self.started
    }

    /// The owner-only data directory.
    #[must_use]
    pub fn data_dir(&self) -> &Path {
        &self.data_dir
    }

    /// The active bans, soonest expiry first.
    #[must_use]
    pub fn bans(&self) -> Vec<BanView> {
        self.bans.list()
    }

    /// Reserve one concurrent-connection slot, or return `None` when [`MAX_CONNECTIONS`] is reached (review R1-7).
    #[must_use]
    pub fn try_connection(self: &Arc<Self>) -> Option<ConnectionGuard> {
        let active = self.active_connections.fetch_add(1, Ordering::Relaxed) + 1;
        if active > MAX_CONNECTIONS {
            self.active_connections.fetch_sub(1, Ordering::Relaxed);
            return None;
        }
        Some(ConnectionGuard {
            state: Arc::clone(self),
        })
    }

    /// The number of connections currently being served (diagnostics and tests).
    #[must_use]
    pub fn active_connections(&self) -> u64 {
        self.active_connections.load(Ordering::Relaxed)
    }
}

/// Build an event view for one proxy decision (the caller supplies every explainable field).
#[allow(clippy::too_many_arguments)]
#[must_use]
pub fn event_view(
    state: &AppState,
    site: &SiteRuntime,
    ray_id: &str,
    client_ip: std::net::IpAddr,
    method: &str,
    path: &str,
    action: &str,
    verdict: &hdd_waf_core::Verdict,
    event_mode: Mode,
    evidence_override: Option<&str>,
) -> EventView {
    let evidence = evidence_override.map_or_else(
        || util::truncate_utf8(&verdict.evidence, hdd_waf_core::MAX_EVIDENCE_BYTES).to_owned(),
        |text| util::truncate_utf8(text, hdd_waf_core::MAX_EVIDENCE_BYTES).to_owned(),
    );
    EventView {
        seq: 0,
        time: util::rfc3339_now(),
        ray_id: ray_id.to_owned(),
        site: site.host().to_owned(),
        client_ip: client_ip.to_string(),
        method: method.to_owned(),
        path: util::truncate_utf8(path, 2_048).to_owned(),
        action: action.to_owned(),
        category: verdict.category.map(str::to_owned),
        subtype: verdict.subtype.map(str::to_owned),
        rule_id: verdict.rule_id.map(str::to_owned),
        vector: verdict.vector.map(util::vector_name).map(str::to_owned),
        field: verdict.field.clone(),
        field_kind: verdict
            .field_kind
            .map(util::field_kind_name)
            .map(str::to_owned),
        evidence,
        mode: event_mode.as_str().to_owned(),
        config_revision: state.revision(),
    }
}

/// The duration of one ladder step (helper for the audit detail).
#[must_use]
pub fn ladder_step_duration(seconds: u64) -> Duration {
    Duration::from_secs(seconds)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::api::Mode;

    fn sample_site() -> SiteRuntime {
        let config = SiteConfig {
            host: "demo.test".to_owned(),
            origin: "http://127.0.0.1:8081".to_owned(),
            stack: Stack::default(),
            mode: Mode::Block,
            strictness: Strictness::Balanced,
            field_hints: vec![config::FieldHintConfig {
                field: "username".to_owned(),
                kind: hdd_waf_core::FieldKind::Username,
            }],
            extra_rules: Vec::new(),
            ban: config::BanConfig::default(),
            preserve_host: true,
            upstream_host: None,
            origin_secret_header: None,
            origin_secret_env: None,
            public_url: None,
            lockdown_verified: false,
        };
        let validated = crate::config::Config::parse_str(
            "listen: \"127.0.0.1:0\"\nadmin_listen: \"127.0.0.1:0\"\ndata_dir: \"target/test-state\"\n\
             log_path: \"target/test-state/events.jsonl\"\nadmin_token_env: TOKEN\n\
             sites:\n  - host: \"demo.test\"\n    origin: \"http://127.0.0.1:8081\"\n    mode: block\n",
        )
        .and_then(|parsed| parsed.validate())
        .expect("sample config validates");
        let site = validated.sites.first().expect("one site");
        let mut runtime = SiteRuntime::new(site, None);
        runtime.config = config;
        runtime
    }

    #[test]
    fn mode_switching_and_protection_state_are_honest() {
        let site = sample_site();
        assert_eq!(site.mode(), Mode::Block);
        assert_eq!(site.protection(), Protection::BlockingUnverified);
        site.set_lockdown_verified(true);
        assert_eq!(site.protection(), Protection::BlockingLocked);
        site.set_mode(Mode::Monitor);
        assert_eq!(site.protection(), Protection::Monitoring);
        site.set_mode(Mode::Off);
        assert_eq!(site.protection(), Protection::Off);
    }

    #[test]
    fn site_views_report_configured_secret_without_its_value() {
        let mut site = sample_site();
        site.config.origin_secret_header = Some("X-Origin-Secret".to_owned());
        site.secret_value = Some("never-shown".to_owned());
        let view = site.view();
        assert_eq!(
            view.origin_secret_header.as_deref(),
            Some("X-Origin-Secret")
        );
        assert!(view.origin_secret_configured);
        let json = serde_json::to_string(&view).expect("view serializes");
        assert!(!json.contains("never-shown"));
    }

    #[test]
    fn rules_can_be_added_once_and_removed() {
        let site = sample_site();
        let rule = hdd_waf_core::CustomRule {
            id: "C-1".to_owned(),
            vector: None,
            contains: Some("union select".to_owned()),
            regex: None,
            action: hdd_waf_core::Action::Block,
            description: "operator rule".to_owned(),
        };
        assert!(site.add_rule(rule.clone()));
        assert!(!site.add_rule(rule.clone()));
        assert_eq!(site.rules().len(), 1);
        assert!(site.remove_rule("C-1"));
        assert!(!site.remove_rule("C-1"));
    }
}
