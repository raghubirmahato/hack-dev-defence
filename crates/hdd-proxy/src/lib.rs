//! `hdd-proxy`: TLS, host router, pipeline, rate limiter, ACME, cert store, origin health.
//!
//! The HK1 demo track implements a working HTTP/1.1 reverse proxy with the SQL-injection detector of `hdd-waf-core`,
//! the ban ladder, the JSONL event log and the loopback admin listener with its embedded web UI. TLS termination is
//! out of scope for HK1: the proxy runs behind Caddy or Cloudflare (documented in `docs/DEMO.md` and `OPERATIONS.md`).
//!
//! The HTTP/JSON contract shared with the web UI and the tests is [`api`]. The request path is:
//! [`server`] accepts the connection -> [`pipeline`] routes by `Host`, resolves the client IP, buffers up to
//! [`hdd_waf_core::INSPECT_BODY_CAP`] body bytes, calls `hdd_waf_core::inspect` and decides (block/monitor/off) ->
//! [`forward`] exchanges the request with the origin. The admin listener is handled by [`admin`], which dispatches the
//! account routes of [`accounts_api`] first and then the core endpoints of [`api_core`]; [`lockdown`] implements the
//! origin-lockdown and verify-protection probes.
#![forbid(unsafe_code)]

pub mod accounts;
pub mod accounts_api;
pub mod admin;
pub mod ai;
pub mod ai_api;
pub mod api;
pub mod api_core;
pub mod auth;
pub mod ban;
pub mod blockpage;
pub mod config;
pub mod confirm;
pub mod events;
pub mod finding_export;
pub mod findings;
pub mod forward;
pub mod lockdown;
pub mod pipeline;
pub mod server;
pub mod snippets;
pub mod state;
pub mod ui;
pub mod util;
pub mod wizard;

pub use config::{Config, ConfigError, ResolvedSecrets, Validated, ValidatedSite};
pub use state::AppState;
