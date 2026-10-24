//! The Live Target Profile v5 (`hdd.live.yaml`), mirroring section 8 of the specification field for field.
//!
//! Every struct rejects unknown keys. Secrets never appear here: fields that refer to a secret hold the *name* of an
//! environment variable ([`EnvVarName`]) or a path whose printed form is reduced to its file name ([`SecretPath`]).
//! Doc comments become `description` entries of the generated JSON Schema (`docs/profile.schema.json`).

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use super::secrets::{EnvVarName, SecretPath};

/// Whether production traffic crosses HDD (section 2.7).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema, Default)]
#[serde(rename_all = "snake_case")]
pub enum LifecycleStage {
    /// Only the pilot subzones are delegated; destructive checks are allowed with warning.
    #[default]
    Pilot,
    /// The apex is delegated; the runner refuses destructive checks without a per-run approval.
    Production,
}

/// Who the installation serves.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema, Default)]
#[serde(rename_all = "snake_case")]
pub enum DeploymentMode {
    /// The operator's own domains only.
    #[default]
    OwnerOnly,
    /// A service for other people (refused when `runtime.profile` is `local`).
    Saas,
}

/// Runtime profile (R-31).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema, Default)]
#[serde(rename_all = "snake_case")]
pub enum RuntimeProfile {
    /// A server running 24/7.
    #[default]
    Hosted,
    /// A personal computer; protection exists only while HDD runs (section 2.11).
    Local,
}

/// Database used by the local profile.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema, Default)]
#[serde(rename_all = "snake_case")]
pub enum LocalDatabase {
    /// A private PostgreSQL managed by `hdd-local`.
    #[default]
    Embedded,
    /// An external server given by `HDD_DATABASE_URL`.
    External,
    /// Docker Compose services.
    Compose,
}

/// Key-value store used by the local profile.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema, Default)]
#[serde(rename_all = "snake_case")]
pub enum LocalKv {
    /// In-process stores.
    #[default]
    Memory,
    /// Redis or Valkey.
    Redis,
}

/// TLS mode of the local profile.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema, Default)]
#[serde(rename_all = "snake_case")]
pub enum LocalTls {
    /// A name-constrained local certificate authority (needs the operator's consent to install).
    #[default]
    LocalCa,
    /// Plain HTTP on loopback only.
    HttpOnly,
}

/// How loopback clients are told apart (C18.5).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema, Default)]
#[serde(rename_all = "snake_case")]
pub enum LoopbackIdentity {
    /// Keyed by the user agent.
    #[default]
    UaKeyed,
    /// One identity for every loopback client (refused while any site is in `block` mode).
    Single,
}

/// Operator-run tunnel provider.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema, Default)]
#[serde(rename_all = "snake_case")]
pub enum TunnelProvider {
    /// No tunnel; nothing is exposed beyond this computer.
    #[default]
    None,
    /// `cloudflared`.
    Cloudflared,
    /// `ngrok`.
    Ngrok,
    /// WireGuard.
    Wireguard,
    /// Another operator-run tunnel.
    Other,
}

/// Hosting profile (C18.10).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema, Default)]
pub enum HostingProfile {
    /// Single VPS.
    #[default]
    H1,
    /// Two servers or providers.
    H2,
    /// Third hosting profile (see C18.10).
    H3,
    /// Fourth hosting profile (see C18.10).
    H4,
    /// Fifth hosting profile (see C18.10).
    H5,
}

/// Backup target.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema, Default)]
#[serde(rename_all = "snake_case")]
pub enum BackupTarget {
    /// A local directory.
    #[default]
    Local,
    /// SFTP.
    Sftp,
    /// S3-compatible storage.
    S3,
}

/// Admin surface exposure.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema, Default)]
#[serde(rename_all = "snake_case")]
pub enum AdminExposure {
    /// Reachable only through an SSH or WireGuard tunnel.
    #[default]
    TunnelOnly,
    /// Routed, restricted by `admin_cidrs` and MFA.
    RoutedWithCidr,
}

/// Origin TLS verification mode. Verification can never be disabled.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema, Default)]
#[serde(rename_all = "snake_case")]
pub enum TlsVerifyMode {
    /// Web PKI roots.
    #[default]
    Webpki,
    /// A pinned CA (needs `pin`).
    PinnedCa,
    /// A pinned SPKI hash (needs `pin`).
    PinnedSpki,
}

/// Origin lockdown state, set by the operator.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema, Default)]
#[serde(rename_all = "snake_case")]
pub enum LockdownState {
    /// The origin firewall and secret header are not applied yet.
    #[default]
    Pending,
    /// Applied by the operator.
    Applied,
}

/// How HDD is deployed to the server.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema, Default)]
pub enum DeployMode {
    /// HDD runs on the machine that executes `hddctl`.
    #[default]
    #[serde(rename = "on-vps")]
    OnVps,
    /// `hddctl` deploys over SSH (needs `platform.ssh`).
    #[serde(rename = "ssh")]
    Ssh,
}

/// DNS topology.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema, Default)]
#[serde(rename_all = "snake_case")]
pub enum DnsTopology {
    /// HDD serves the zone itself.
    #[default]
    SelfAuthoritative,
    /// An external secondary serves the zone publicly (needs `dns.public_ns`).
    HiddenPrimary,
}

/// How the existing DNS zone is obtained.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema, Default)]
#[serde(rename_all = "snake_case")]
pub enum ExportMethod {
    /// A zone file.
    #[default]
    Zonefile,
    /// Zone transfer.
    Axfr,
    /// Provider API.
    Api,
    /// Entered by hand.
    Manual,
}

/// How the acceptance runner reaches the control plane.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema, Default)]
pub enum ControlPlaneAccess {
    /// SSH tunnel.
    #[default]
    #[serde(rename = "ssh-tunnel")]
    SshTunnel,
    /// WireGuard.
    #[serde(rename = "wireguard")]
    Wireguard,
}

/// ACME directory.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema, Default)]
#[serde(rename_all = "snake_case")]
pub enum AcmeDirectory {
    /// The CA's staging directory (default).
    #[default]
    Staging,
    /// The CA's production directory (needs the operator's approval).
    Production,
}

/// Signup mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema, Default)]
#[serde(rename_all = "snake_case")]
pub enum SignupMode {
    /// No signup.
    Disabled,
    /// Invitations only.
    #[default]
    InviteOnly,
    /// Open signup (needs the operator's approval in chat; refused in `local`).
    Open,
}

/// Email verification policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema, Default)]
#[serde(rename_all = "snake_case")]
pub enum EmailVerification {
    /// Always required.
    #[default]
    Required,
}

/// Disposable-address policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema, Default)]
#[serde(rename_all = "snake_case")]
pub enum DisposablePolicy {
    /// Reject.
    Block,
    /// Extra friction.
    #[default]
    Challenge,
    /// Allow.
    Allow,
}

/// Password breach check mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema, Default)]
#[serde(rename_all = "snake_case")]
pub enum BreachCheck {
    /// An offline list.
    #[default]
    OfflineList,
    /// The k-anonymity range API (needs an egress entry).
    HibpRange,
    /// Off.
    Off,
}

/// SMTP transport security.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema, Default)]
#[serde(rename_all = "snake_case")]
pub enum SmtpTls {
    /// STARTTLS.
    #[default]
    Starttls,
    /// Implicit TLS.
    Tls,
    /// No TLS (only for a local sink).
    None,
}

/// Plan mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema, Default)]
#[serde(rename_all = "snake_case")]
pub enum PlansMode {
    /// No quotas.
    #[default]
    Unlimited,
    /// Quotas editable in the admin panel.
    Tiered,
}

/// Kind of the protected site (drives honeypot defaults).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema, Default)]
#[serde(rename_all = "snake_case")]
pub enum SitePlatform {
    /// WordPress.
    Wordpress,
    /// Static site.
    Static,
    /// Custom application.
    #[default]
    Custom,
    /// Something else.
    Other,
}

/// Upstream DDoS mitigation mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema, Default)]
#[serde(rename_all = "snake_case")]
pub enum DdosMode {
    /// Always-on scrubbing.
    AlwaysOn,
    /// On demand.
    OnDemand,
    /// None (pilot only; DDoS readiness is then NOT READY).
    #[default]
    None,
}

/// Vulnerability feed mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema, Default)]
#[serde(rename_all = "snake_case")]
pub enum FeedMode {
    /// Online feeds.
    #[default]
    Online,
    /// File import.
    Offline,
}

/// Unprivileged default ports of the local profile.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields, default)]
pub struct LocalPorts {
    /// Product web surfaces.
    pub web: u16,
    /// Protected-site HTTP listener.
    pub proxy_http: u16,
    /// Protected-site HTTPS listener.
    pub proxy_https: u16,
    /// DNS listener.
    pub dns: u16,
    /// Control-plane API.
    pub api: u16,
}

impl Default for LocalPorts {
    fn default() -> Self {
        LocalPorts {
            web: 8443,
            proxy_http: 8080,
            proxy_https: 8444,
            dns: 5300,
            api: 8000,
        }
    }
}

/// Operator-run tunnel.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema, Default)]
#[serde(deny_unknown_fields, default)]
pub struct Tunnel {
    /// Tunnel provider.
    pub provider: TunnelProvider,
    /// CIDRs whose `X-Forwarded-For` is trusted.
    pub trusted_cidrs: Vec<String>,
}

/// Settings read only when `runtime.profile` is `local`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields, default)]
pub struct LocalRuntime {
    /// Data directory; empty means the per-OS user data directory.
    pub data_dir: String,
    /// Database kind.
    pub database: LocalDatabase,
    /// Key-value store kind.
    pub kv: LocalKv,
    /// Listener ports.
    pub ports: LocalPorts,
    /// Suffix of local site names (browsers resolve `*.localhost` to loopback).
    pub local_domain_suffix: String,
    /// TLS mode.
    pub tls: LocalTls,
    /// Bind protected-site listeners to the LAN (needs the acknowledgement of section 2.11).
    pub lan_exposure: bool,
    /// Loopback client identity mode.
    pub loopback_client_identity: LoopbackIdentity,
    /// Accept `X-HDD-Test-Client` on loopback (self-test and acceptance runs).
    pub test_client_header: bool,
    /// Route the product surfaces through the HDD proxy like hosted.
    pub dogfood: bool,
    /// Operator-run tunnel.
    pub tunnel: Tunnel,
}

impl Default for LocalRuntime {
    fn default() -> Self {
        LocalRuntime {
            data_dir: String::new(),
            database: LocalDatabase::default(),
            kv: LocalKv::default(),
            ports: LocalPorts::default(),
            local_domain_suffix: "hdd.localhost".into(),
            tls: LocalTls::default(),
            lan_exposure: false,
            loopback_client_identity: LoopbackIdentity::default(),
            test_client_header: false,
            dogfood: false,
            tunnel: Tunnel::default(),
        }
    }
}

/// Backup settings of the hosted profile.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields, default)]
pub struct Backups {
    /// Cron schedule.
    pub schedule: String,
    /// Backup destination.
    pub target: BackupTarget,
    /// Name of the environment variable that holds the remote credentials (never the credentials).
    pub remote_env: EnvVarName,
}

impl Default for Backups {
    fn default() -> Self {
        Backups {
            schedule: "0 3 * * *".into(),
            target: BackupTarget::Local,
            remote_env: EnvVarName::empty(),
        }
    }
}

/// Settings read only when `runtime.profile` is `hosted`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields, default)]
pub struct Hosting {
    /// Hosting profile H1 to H5.
    pub profile: HostingProfile,
    /// Run the watchdog.
    pub watchdog: bool,
    /// Backups.
    pub backups: Backups,
    /// Keep a last-known-good snapshot.
    pub last_known_good_snapshot: bool,
}

impl Default for Hosting {
    fn default() -> Self {
        Hosting {
            profile: HostingProfile::default(),
            watchdog: true,
            backups: Backups::default(),
            last_known_good_snapshot: true,
        }
    }
}

/// Runtime selection (R-31, section 8.2).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema, Default)]
#[serde(deny_unknown_fields, default)]
pub struct Runtime {
    /// `hosted` or `local`.
    pub profile: RuntimeProfile,
    /// Local-profile settings.
    pub local: LocalRuntime,
    /// Hosted-profile settings.
    pub hosting: Hosting,
}

/// Hostnames of the product surfaces.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema, Default)]
#[serde(deny_unknown_fields, default)]
pub struct Surfaces {
    /// Public site host.
    pub public_host: String,
    /// Customer app host.
    pub app_host: String,
    /// Admin host.
    pub admin_host: String,
    /// API host.
    pub api_host: String,
    /// Status page host (ideally served from outside this server).
    pub status_host: String,
    /// Admin exposure.
    pub admin_exposure: AdminExposure,
}

/// Origin TLS verification.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema, Default)]
#[serde(deny_unknown_fields, default)]
pub struct TlsVerify {
    /// Verification mode.
    pub mode: TlsVerifyMode,
    /// Pin value for the pinned modes (a certificate or key hash, not a secret).
    pub pin: String,
}

/// Canary files on the origin.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields, default)]
pub struct Canary {
    /// Base path of the canary files.
    pub base_path: String,
    /// Use the `hdd-canary` agent on the origin.
    pub use_hdd_canary_agent: bool,
}

impl Default for Canary {
    fn default() -> Self {
        Canary {
            base_path: "/__hdd_canary/".into(),
            use_hdd_canary_agent: true,
        }
    }
}

/// The operator's real site host.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema, Default)]
#[serde(deny_unknown_fields, default)]
pub struct Origin {
    /// Origin URL including the scheme.
    pub url: String,
    /// TLS server name to verify.
    pub tls_server_name: String,
    /// `Host` header to send.
    pub host_header: String,
    /// TLS verification.
    pub tls_verify: TlsVerify,
    /// Lockdown state.
    pub lockdown_state: LockdownState,
    /// Canary settings.
    pub canary: Canary,
}

/// SSH access for deployment.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema, Default)]
#[serde(deny_unknown_fields, default)]
pub struct Ssh {
    /// Host.
    pub host: String,
    /// User.
    pub user: String,
    /// Path of the private key file (printed as its file name only).
    pub key_path: SecretPath,
}

/// Minimum server resources.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields, default)]
pub struct MinResources {
    /// Virtual CPUs.
    pub vcpu: u32,
    /// RAM in MiB.
    pub ram_mb: u32,
    /// Disk in GiB.
    pub disk_gb: u32,
}

impl Default for MinResources {
    fn default() -> Self {
        MinResources {
            vcpu: 2,
            ram_mb: 4096,
            disk_gb: 40,
        }
    }
}

/// The server(s) running HDD.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema, Default)]
#[serde(deny_unknown_fields, default)]
pub struct Platform {
    /// Public IPv4 addresses.
    pub public_ipv4: Vec<String>,
    /// Public IPv6 addresses.
    pub public_ipv6: Vec<String>,
    /// Nameserver host names.
    pub ns_hostnames: Vec<String>,
    /// Zone for `<site-id>.edge.<platform_domain>` (CNAME modes).
    pub edge_cname_zone: String,
    /// DNS-01 delegation zone `<zone-id>.acme.<platform_domain>`.
    pub acme_cname_zone: String,
    /// Contracted or measured uplink in Mbit/s; 0 means unknown (capacity then UNVERIFIED).
    pub uplink_mbps: u32,
    /// Deployment mode.
    pub deploy_mode: DeployMode,
    /// SSH access for `deploy_mode: ssh`.
    pub ssh: Ssh,
    /// Minimum resources.
    pub min_resources: MinResources,
}

/// DNS settings.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema, Default)]
#[serde(deny_unknown_fields, default)]
pub struct Dns {
    /// Topology.
    pub topology: DnsTopology,
    /// Public nameserver names served by the external secondary (hidden primary).
    pub public_ns: Vec<String>,
}

/// Registrar access.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema, Default)]
#[serde(deny_unknown_fields, default)]
pub struct Registrar {
    /// Provider name.
    pub provider: String,
    /// Environment variable NAME holding the API token (never the token).
    pub api_token_env: EnvVarName,
}

/// Where the current DNS zone comes from.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema, Default)]
#[serde(deny_unknown_fields, default)]
pub struct ExistingDns {
    /// Current provider.
    pub provider: String,
    /// Export method.
    pub export_method: ExportMethod,
    /// Zone file path (for `zonefile`).
    pub zonefile_path: String,
}

/// Acceptance runner.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields, default)]
pub struct TestRunner {
    /// Runner public IP, or `auto` (discovered through the canary echo; bannable by design).
    pub public_ip: String,
    /// Control-plane access method.
    pub control_plane_access: ControlPlaneAccess,
}

impl Default for TestRunner {
    fn default() -> Self {
        TestRunner {
            public_ip: "auto".into(),
            control_plane_access: ControlPlaneAccess::default(),
        }
    }
}

/// ACME settings.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema, Default)]
#[serde(deny_unknown_fields, default)]
pub struct Acme {
    /// Account email.
    pub email: String,
    /// Directory; staging first.
    pub directory: AcmeDirectory,
}

/// Signup policy.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields, default)]
pub struct Signup {
    /// Mode.
    pub mode: SignupMode,
    /// Email verification (always required).
    pub email_verification: EmailVerification,
    /// Allowed email domains; empty means any (subject to policy).
    pub allowed_email_domains: Vec<String>,
    /// Disposable-address policy.
    pub disposable_email_policy: DisposablePolicy,
    /// Password breach check.
    pub password_breach_check: BreachCheck,
    /// Minimum password length.
    pub min_password_length: u32,
    /// Roles for which MFA enrollment is forced.
    pub require_mfa_for: Vec<String>,
}

impl Default for Signup {
    fn default() -> Self {
        Signup {
            mode: SignupMode::default(),
            email_verification: EmailVerification::default(),
            allowed_email_domains: Vec::new(),
            disposable_email_policy: DisposablePolicy::default(),
            password_breach_check: BreachCheck::default(),
            min_password_length: 12,
            require_mfa_for: vec!["platform_admin".into()],
        }
    }
}

/// SMTP relay.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields, default)]
pub struct Smtp {
    /// Relay host; empty means a local SMTP sink only.
    pub host: String,
    /// Port.
    pub port: u16,
    /// Transport security.
    pub tls: SmtpTls,
    /// Environment variable NAME holding the username.
    pub username_env: EnvVarName,
    /// Environment variable NAME holding the password.
    pub password_env: EnvVarName,
    /// Sender address.
    pub from_address: String,
    /// Sender display name.
    pub from_name: String,
    /// Reply-to address.
    pub reply_to: String,
}

impl Default for Smtp {
    fn default() -> Self {
        Smtp {
            host: String::new(),
            port: 587,
            tls: SmtpTls::default(),
            username_env: EnvVarName::empty(),
            password_env: EnvVarName::empty(),
            from_address: String::new(),
            from_name: "Hack Dev Defence".into(),
            reply_to: String::new(),
        }
    }
}

/// Branding.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields, default)]
pub struct Branding {
    /// Product name.
    pub product_name: String,
    /// Logo file path.
    pub logo_path: String,
    /// Legal entity.
    pub legal_entity: String,
    /// Support email.
    pub support_email: String,
    /// Terms URL.
    pub terms_url: String,
    /// Privacy URL.
    pub privacy_url: String,
}

impl Default for Branding {
    fn default() -> Self {
        Branding {
            product_name: "Hack Dev Defence".into(),
            logo_path: String::new(),
            legal_entity: String::new(),
            support_email: String::new(),
            terms_url: String::new(),
            privacy_url: String::new(),
        }
    }
}

/// Plans.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema, Default)]
#[serde(deny_unknown_fields, default)]
pub struct Plans {
    /// Plan mode.
    pub mode: PlansMode,
}

/// GeoIP databases.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema, Default)]
#[serde(deny_unknown_fields, default)]
pub struct Geoip {
    /// Country database path (`HDD_GEOIP_DB`).
    pub db_path: String,
    /// ASN database path.
    pub asn_db_path: String,
    /// Licence or provenance of the databases.
    pub source: String,
}

/// External secondary DNS.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema, Default)]
#[serde(deny_unknown_fields, default)]
pub struct SecondaryDns {
    /// Provider.
    pub provider: String,
    /// Environment variable NAME holding the TSIG key (never the key).
    pub tsig_key_env: EnvVarName,
    /// Secondary addresses.
    pub addresses: Vec<String>,
}

/// A vantage point for propagation checks.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema, Default)]
#[serde(deny_unknown_fields, default)]
pub struct VantagePoint {
    /// Name.
    pub name: String,
    /// SSH host.
    pub ssh_host: String,
    /// SSH user.
    pub ssh_user: String,
    /// Private key file (printed as its file name only).
    pub ssh_key_path: SecretPath,
    /// SOCKS proxy `host:port` instead of SSH.
    pub socks_proxy: String,
}

/// Origin access log for header verification.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema, Default)]
#[serde(deny_unknown_fields, default)]
pub struct OriginAccessLog {
    /// SSH host.
    pub ssh_host: String,
    /// Log path.
    pub path: String,
}

/// Facts about the protected site.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields, default)]
pub struct Site {
    /// Site platform (drives honeypot defaults).
    pub platform: SitePlatform,
    /// HAR file path (scrubbed before use).
    pub har_file: String,
    /// Crawl start URL.
    pub crawl_start_url: String,
    /// Methods the replay may use (state-changing methods need per-path allowlisting).
    pub replay_methods: Vec<String>,
    /// Non-HTTP services forced grey-cloud.
    pub non_http_services: Vec<String>,
    /// Extra proxied ports.
    pub extra_proxied_ports: Vec<u16>,
    /// Authentication paths (auth-endpoint hardening).
    pub auth_paths: Vec<String>,
}

impl Default for Site {
    fn default() -> Self {
        Site {
            platform: SitePlatform::default(),
            har_file: String::new(),
            crawl_start_url: String::new(),
            replay_methods: vec!["GET".into(), "HEAD".into()],
            non_http_services: vec!["smtp".into(), "imap".into(), "ssh".into()],
            extra_proxied_ports: Vec::new(),
            auth_paths: vec![
                "/login".into(),
                "/wp-login.php".into(),
                "/signin".into(),
                "/api/auth/login".into(),
            ],
        }
    }
}

/// An upstream CDN in front of HDD.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema, Default)]
#[serde(deny_unknown_fields, default)]
pub struct UpstreamCdn {
    /// Enabled.
    pub enabled: bool,
    /// CIDRs of the CDN whose forwarding headers are trusted.
    pub trusted_cidrs: Vec<String>,
}

/// Alert channels.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema, Default)]
#[serde(deny_unknown_fields, default)]
pub struct Alerts {
    /// Environment variable NAME holding the webhook URL.
    pub webhook_env: EnvVarName,
    /// Environment variable NAME holding the external heartbeat URL.
    pub heartbeat_url_env: EnvVarName,
}

/// Retention.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields, default)]
pub struct Retention {
    /// Event retention in days (plan caps may lower it).
    pub events_days: u32,
    /// Audit retention in days (floor 180).
    pub audit_days: u32,
}

impl Default for Retention {
    fn default() -> Self {
        Retention {
            events_days: 30,
            audit_days: 400,
        }
    }
}

/// Closed lab.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema, Default)]
#[serde(deny_unknown_fields, default)]
pub struct Lab {
    /// Lab enabled.
    pub enabled: bool,
    /// Lab host.
    pub host: String,
    /// Lab CIDR.
    pub cidr: String,
    /// Vuln-Lab enabled.
    pub vulnlab_enabled: bool,
}

/// Mitigation API of the upstream provider.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema, Default)]
#[serde(deny_unknown_fields, default)]
pub struct MitigationApi {
    /// Kind of API.
    pub kind: String,
    /// Environment variable NAME holding the token.
    pub token_env: EnvVarName,
}

/// Lab details for volumetric tests.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema, Default)]
#[serde(deny_unknown_fields, default)]
pub struct DdosLab {
    /// Lab host.
    pub host: String,
    /// Private link description.
    pub private_link: String,
}

/// Upstream DDoS mitigation (section 8.1).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema, Default)]
#[serde(deny_unknown_fields, default)]
pub struct UpstreamDdos {
    /// Mode.
    pub mode: DdosMode,
    /// Provider.
    pub provider: String,
    /// Advertised capacity in Gbit/s, copied from the contract; never assumed.
    pub advertised_capacity_gbps: f64,
    /// Behavior when capacity is exceeded, from the contract.
    pub over_capacity_behavior: String,
    /// Mitigation API.
    pub mitigation_api: MitigationApi,
    /// Pre-provisioned standby or scrubbed edge IPs.
    pub standby_edge_ips: Vec<String>,
    /// Provider contact.
    pub provider_contact: String,
    /// True only after the operator's written confirmation in chat (date recorded).
    pub risk_acceptance_volumetric: bool,
    /// Closed lab for L3/L4 tests.
    pub lab: DdosLab,
}

/// One application component of the origin inventory.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema, Default)]
#[serde(deny_unknown_fields, default)]
pub struct Component {
    /// Name.
    pub name: String,
    /// Version.
    pub version: String,
    /// Package ecosystem.
    pub ecosystem: String,
    /// CPE.
    pub cpe: String,
    /// Package URL.
    pub purl: String,
    /// Reachable from the internet.
    pub internet_facing: bool,
    /// Notes.
    pub notes: String,
}

/// Patch SLAs in days.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields, default)]
pub struct PatchSla {
    /// Known-exploited vulnerabilities.
    pub kev: u32,
    /// Critical.
    pub critical: u32,
    /// High.
    pub high: u32,
    /// Medium.
    pub medium: u32,
}

impl Default for PatchSla {
    fn default() -> Self {
        PatchSla {
            kev: 2,
            critical: 7,
            high: 30,
            medium: 90,
        }
    }
}

/// Origin application inventory (section 8.1).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema, Default)]
#[serde(deny_unknown_fields, default)]
pub struct AppInventory {
    /// Components.
    pub components: Vec<Component>,
    /// SBOM path (CycloneDX or SPDX).
    pub sbom_path: String,
    /// Patch SLAs.
    pub patch_sla_days: PatchSla,
    /// Feed mode.
    pub vuln_feed_mode: FeedMode,
    /// Contact that receives patch-SLA alerts.
    pub origin_owner_contact: String,
}

/// The whole Live Target Profile.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields, default)]
pub struct Profile {
    /// Schema version; must be 5.
    pub schema_version: u32,
    /// `pilot` or `production`.
    pub lifecycle_stage: LifecycleStage,
    /// `owner_only` or `saas`.
    pub deployment_mode: DeploymentMode,
    /// Runtime selection.
    pub runtime: Runtime,
    /// Operator-owned apex hosting www/app/admin/api/ns/status.
    pub platform_domain: String,
    /// Apex zone the operator owns and will protect first.
    pub domain: String,
    /// Real-site mirror for benign traffic and GET/HEAD attack shapes.
    pub test_hostname: String,
    /// Sandbox route; forwards only exact canary paths.
    pub sandbox_hostname: String,
    /// Product surfaces.
    pub surfaces: Surfaces,
    /// The origin.
    pub origin: Origin,
    /// The server(s) running HDD.
    pub platform: Platform,
    /// DNS settings.
    pub dns: Dns,
    /// Registrar.
    pub registrar: Registrar,
    /// Existing DNS.
    pub existing_dns: ExistingDns,
    /// Acceptance runner.
    pub test_runner: TestRunner,
    /// Never-ban and admin-hostname allowlist; must NOT contain the runner IP.
    pub admin_cidrs: Vec<String>,
    /// Port 22 allowlist; may contain the runner IP.
    pub ssh_allow_cidrs: Vec<String>,
    /// Outbound destinations (section 2.1): `[scheme://]host[:port][/path-prefix]`, `*.suffix` for a suffix match.
    pub egress_allowlist: Vec<String>,
    /// ACME.
    pub acme: Acme,
    /// Receives test mail and alerts; the only address the agent may mail.
    pub operator_email: String,
    /// Signup policy.
    pub signup: Signup,
    /// SMTP relay.
    pub smtp: Smtp,
    /// Branding.
    pub branding: Branding,
    /// Plans.
    pub plans: Plans,
    /// GeoIP.
    pub geoip: Geoip,
    /// UI languages shipped.
    pub locales: Vec<String>,
    /// Secondary DNS.
    pub secondary_dns: SecondaryDns,
    /// Vantage points.
    pub vantage_points: Vec<VantagePoint>,
    /// Origin access log.
    pub origin_access_log: OriginAccessLog,
    /// The protected site.
    pub site: Site,
    /// Upstream CDN.
    pub upstream_cdn: UpstreamCdn,
    /// Alerts.
    pub alerts: Alerts,
    /// Retention.
    pub retention: Retention,
    /// Closed lab.
    pub lab: Lab,
    /// True only after the operator's written approval for a `load` run.
    pub load_profile_approved: bool,
    /// Upstream DDoS mitigation (section 8.1).
    pub upstream_ddos: UpstreamDdos,
    /// Secondary DNS is required for cutover.
    pub secondary_dns_required_for_cutover: bool,
    /// Origin inventory.
    pub app_inventory: AppInventory,
}

impl Default for Profile {
    fn default() -> Self {
        Profile {
            schema_version: 5,
            lifecycle_stage: LifecycleStage::default(),
            deployment_mode: DeploymentMode::default(),
            runtime: Runtime::default(),
            platform_domain: String::new(),
            domain: String::new(),
            test_hostname: String::new(),
            sandbox_hostname: String::new(),
            surfaces: Surfaces::default(),
            origin: Origin::default(),
            platform: Platform::default(),
            dns: Dns::default(),
            registrar: Registrar::default(),
            existing_dns: ExistingDns::default(),
            test_runner: TestRunner::default(),
            admin_cidrs: Vec::new(),
            ssh_allow_cidrs: Vec::new(),
            egress_allowlist: Vec::new(),
            acme: Acme::default(),
            operator_email: String::new(),
            signup: Signup::default(),
            smtp: Smtp::default(),
            branding: Branding::default(),
            plans: Plans::default(),
            geoip: Geoip::default(),
            locales: vec!["en".into()],
            secondary_dns: SecondaryDns::default(),
            vantage_points: Vec::new(),
            origin_access_log: OriginAccessLog::default(),
            site: Site::default(),
            upstream_cdn: UpstreamCdn::default(),
            alerts: Alerts::default(),
            retention: Retention::default(),
            lab: Lab::default(),
            load_profile_approved: false,
            upstream_ddos: UpstreamDdos::default(),
            secondary_dns_required_for_cutover: true,
            app_inventory: AppInventory::default(),
        }
    }
}
