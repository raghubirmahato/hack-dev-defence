# ARCHITECTURE

Status: **scaffold**. This file records module ownership and the structural rules of the master specification. Each task updates it when it
lands code (per-task protocol step 7). Source of truth: `docs/SPEC.md` (Part A section 5 to 7, Part C).

## 1. What is built

HDD is a self-hosted WAF + authoritative DNS + TLS-terminating reverse proxy, with a web product around it (public site, sign-up and login,
customer dashboard, per-domain controls, platform admin panel). Two runtime profiles run the same code path (R-31): `hosted` (a server,
24/7) and `local` (a personal computer, only while HDD runs). The data plane (proxy, DNS, WAF, firewall) never awaits the database on the
hot path ([DP] definition of done, section 0.7).

## 2. Workspace crates and owners

`First tasks` lists tasks whose title names the crate, otherwise the lowest-numbered tasks whose spec block mentions it (derived from the task files, not an
assignment; T-0001, T-0002 and T-0004 are skipped because they list every crate). The last column counts the task blocks that mention the crate.

| Crate | Kind | Responsibility (section 7) | First tasks | Mentioned by |
| --- | --- | --- | --- | --- |
| `hdd-common` | lib | config, models, kv traits (KvStore, Bus, Limiter) with Redis and in-process backends, pub/sub messages, errors, Ray ID, client-IP resolution, egress client, profile | T-0006, T-0009 | 21 |
| `hdd-waf-core` | lib | normalizer, detectors, tokenizers, scoring, rules, leak scanner (pure, no I/O); the HK1 demo track implements the C4 SQL-injection detector (`inspect`, families H1-H8, custom rules) here ahead of T-0239 | T-0239 | 13 |
| `hdd-auth` | lib | password policy, hashing, MFA (TOTP, WebAuthn), sessions, API keys, RBAC engine | T-0106, T-0113, T-0125 | 4 |
| `hdd-api` | bin | control plane JSON API (:8000) + SSE; OpenAPI | T-0073, T-0086, T-0089, T-0355 | 7 |
| `hdd-web` | bin | SSR product UI (:3000): public, app, admin surfaces; docs renderer; i18n | T-0073 | 20 |
| `hdd-ui` | lib | design tokens -> CSS, component macros, icon sprite, SVG chart kit, islands JS | T-0030, T-0031, T-0034, T-0035 | 11 |
| `hdd-worker` | bin | job runner: mail outbox, webhooks, rollups, ACME scheduling, feeds, verification polling, reports, retention | T-0100, T-0156, T-0348, T-0377 | 9 |
| `hdd-mailer` | lib | SMTP delivery, templates, suppression list | T-0109 | 5 |
| `hdd-notify` | lib | alert routing and channels | T-0453 | 1 |
| `hdd-analytics` | lib | rollups, queries, report data | T-0418 | 1 |
| `hdd-intel` | lib | GeoIP/ASN, reputation lists, threat-intel feeds, verified-bot data | T-0326, T-0346, T-0443 | 3 |
| `hdd-challenge` | lib | proof-of-work challenge, clearance cookies (shared by proxy and web) | T-0108 | 6 |
| `hdd-proxy` | bin | TLS, host router, pipeline, rate limiter, ACME, cert store, origin health; the HK1 demo track implements a working HTTP/1.1 reverse proxy with the inspection pipeline, the ban ladder, the JSONL event log and the loopback admin listener with its embedded web UI here ahead of T-0208 | T-0208 | 6 |
| `hdd-dns` | bin | authoritative DNS | T-0207 | 12 |
| `hdd-firewall` | lib+bin | Enforcer trait, Nftables, IpsetIptables, Noop, hdd-fw-agent | T-0463 | 2 |
| `hdd-xdp-logic` | lib | pure packet-verdict logic (no_std) | T-0465 | 3 |
| `hdd-xdp-ebpf` | excluded | kernel program (only crate allowed unsafe) | T-0466 | 3 |
| `hdd-xdp` | lib | loader, maps, counters, detach timer | T-0465, T-0466, T-0467 | 6 |
| `hdd-shield` | lib | telemetry, escalation state machine, provider and DNS-failover actions | T-0473 | 6 |
| `hdd-vuln` | lib | inventory, feeds, matching, exposure board data, VEX, virtual-patch lifecycle | T-0481 | 9 |
| `hdd-scan` | lib | read-only posture scanner and origin hardening report | T-0487 | 5 |
| `hddctl` | cli | break-glass CLI, deploy, hosting check | T-0212, T-0217, T-0370, T-0384 | 71 |
| `hdd-local` | cli | local runtime: supervisor, embedded PostgreSQL manager, local CA, hosts helper, doctor, self-test, local backups | T-0564 | 7 |
| `hdd-acceptance` | cli | acceptance runner skeleton: status taxonomy, profile validation, `TargetGuard`/egress gates, five load profiles with one shared limiter, kill switch, lifecycle gates, check framework (dependency order, finally cleanup, timeouts, signals), reporter (JSON/Markdown, SHA-256, redaction), inspect-first gate, control-plane argv/vantage plans, registry AC-00..AC-62 and dry run | T-0215 | 11 |
| `hdd-loadgen` | cli | capped generators: lab floods, HTTP load | T-0470 | 8 |
| `hdd-canary` | cli | origin-side canary fixture sidecar (C16.1): serves only `ok.txt`, `leak.txt`, `static.css`, `static.js`, `search.html` under `origin.canary.base_path` plus `GET <base_path>echo-headers`; 1 KB request line / 8 KB header limits, fixed security headers, no request-body read, files read once at startup with an optional manifest check; `hddctl canary generate|verify` (same task) writes a real SHA-256 manifest and probes through `hdd-common::egress` | T-0210 | 5 |
| `hdd-sdk` | lib | generated API client | T-0458 | 1 |
| `hdd-xtask` | cli | build/verify/release automation | T-0005 | 3 |
| `hdd-vulnlab` | cli (lab) | Vuln-Lab: intentionally vulnerable applications, lab only | T-0493, T-0274, T-0516, T-0518 | 4 |

Kinds: `lib`, `bin` (service), `cli` (command-line tool, may print to stdout), `excluded` (own toolchain and target, not in the default build).

### 2.1 Modules implemented so far (P00)

| Crate | Module | Owner task | What it is |
| --- | --- | --- | --- |
| `hdd-common` | `profile` (`types`, `secrets`, `validate`) | T-0006 | Live Target Profile v5: strict types mirroring section 8, `EnvVarName` / `SecretPath` (no secret value can be parsed or printed), strict YAML parsing under a budget, the pure validator with its rule catalog, the JSON Schema |
| `hdd-common` | `net` | T-0006, T-0009 | `Cidr`, host name and e-mail syntax, IPv4-mapped unwrapping (panic-free, property-tested) |
| `hdd-common` | `egress` (`allow`, `url`, `ssrf`, `resolver`, `client`, `target`, `killswitch`, `denylog`, `probe`) | T-0009 | The single outbound path (R-22): allowlist `Client`, SSRF-guarded `UserUrlClient`, `TargetGuard`, kill switch, deny log, probes for `hddctl preflight` |
| `hdd-common` | `profile::capability`, `profile::env` | T-0561 | The capability matrix of C18.2 (`Profile::availability`, `refusals`) and the typed environment overrides of B10 with a JSON Schema |
| `hdd-common` | `buildplan` | T-0561 | Build track (H or L) and the "what can run here" plan from the acceptance registry; looks for tools on `PATH`, starts nothing |
| `hdd-common` | `parity` | T-0561 | The R-31 parity harness: compares decision fields and ban intent of two backends, excludes identity key, enforcement backend, `config_revision` and timestamps; UNVERIFIED when nothing can be compared |
| `hdd-common` | `kv` (`memory`, `redis`, `bus`, `limiter`, `rate`, `rehydrate`, `metrics`, `keys`, `clock`, `startup`, `conformance`) | T-0562 | `KvStore`, `Bus` and `Limiter` with the in-process and the Redis backend, the three rate algorithms (counter, exact, gcra), restart rehydration, metrics and the shared conformance suite; the only module that talks to Redis (`xtask kv-lint`) |
| `hdd-local` | `pg` (`manifest`, `fetch`, `archive`, `cluster`, `backup`, `cli`, `files`, `sys`, `telemetry`) | T-0563 | The embedded PostgreSQL manager: pinned distribution, download through the egress module, verified and bounded extraction, `initdb`, start/stop, roles, encrypted logical backups; the `hdd-local` binary (`db`, `backup`, `restore`) and `cargo xtask db` call it |
| `hddctl` | `preflight` | T-0006 | `--profile-only` (pure) and the two egress-guarded reachability probes |
| `hdd-xtask` | `verify`, `spec`, `tasks`, `claims`, `rust_share`, `secrets`, `rules`, `deps`, `profile_check`, `matrix`, `gate`, `ux_docs` | T-0005, T-0008, T-0010, T-0011 | Build/verify/governance automation; every command is listed in OPERATIONS.md |

Dependencies: external crates are registered in `docs/vetting.toml` (R-08); a new one without an entry fails `cargo xtask verify`. `hdd-xtask` depends on `hdd-common` (profile schema and example checks); no shipped crate depends on `hdd-xtask`.

## 3. Structural rules (enforced mechanically by `cargo xtask verify`, T-0005)

- `#![forbid(unsafe_code)]` in every crate except `hdd-xdp-ebpf` (ADR-0025). Workspace lints deny `unwrap`, `expect`, `panic`, indexing, `todo`,
  `unimplemented`, `dbg!` and `print_stdout` outside tests (R-01); a CLI crate opts out of `print_stdout` at crate level only.
- `hdd-waf-core` is pure: no I/O, no clock, no network. `hdd-xdp-logic` is `no_std` and has no `unsafe`.
- Only `hdd-common::kv` talks to Redis (`xtask kv-lint`, R-31). Only `hdd-common::egress` makes outbound connections (R-22).
- Only the host agent (`hdd-fw-agent` plus the XDP loader) holds `NET_ADMIN`/BPF privileges (section 7).
- `hdd-vulnlab` is a workspace member but not a default member, and must not appear in the dependency graph of any shipped binary
  (`cargo tree -p hdd-proxy -e normal`, A4 of T-0004).
- Service ports (section 6 and B10): `hdd-api` 127.0.0.1:8000, `hdd-web` 127.0.0.1:3000, metrics 127.0.0.1:9100, proxy 80/443, DNS 53. In the
  local profile the control plane binds loopback only, under any setting (section 2.11).

## 4. Rust-first exceptions (section 5, machine-checked by `cargo xtask rust-share`)

Non-Rust is allowed only for: `install.sh` (50 lines max, fetches and verifies `hddctl`), external test oracles (`dig`, `delv`, `openssl`,
`h2spec`, `testssl.sh`; lab-only `sqlmap`, `nikto`, `wapiti`, `nuclei`, ZAP baseline, `ffuf`), a Chromium binary and vendored `axe-core` for
browser tests, vendored HTMX plus at most 3,000 lines / 45 KB gzip of first-party ES-module islands, CSS (at most 12,000 hand-written lines),
askama HTML templates (at most 40,000 lines), fonts and SVG icons, Markdown sources, the pinned nightly toolchain plus `bpf-linker` for
`hdd-xdp-ebpf` only, declarative installer manifests, and the Postgres/Redis servers themselves. Hand-written Rust must stay at or above 90% of
programming-language lines (DEV-V5-002).

**Bootstrap exception (DEV-V5-000), closed:** the one-off Python tool that split the specification and generated the task files was
deleted on 2026-10-18 when `cargo xtask spec split|check` and `tasks index` reproduced its outputs (see `docs/DEVIATIONS.md`).

## 5. Repository map

| Path | Content |
| --- | --- |
| `crates/` | workspace crates (table above) |
| `lab/` | `vulnlab/` (never shipped), `netns/`, `oracles/` |
| `design/` | tokens (source of truth), brand, prototypes (design artifacts, not shipped), reviews, coverage sources, licenses |
| `i18n/` | `en/` Fluent catalogs, `pseudo/` generated |
| `legal/` | templates marked "operator must review" |
| `migrations/`, `fuzz/`, `benches/` | database migrations, fuzz targets, criterion benchmarks |
| `tests/fixtures/` | tagged attack fixtures (class A/B/C), benign corpora, held-out sets (never used for tuning) |
| `docker/`, `deploy/`, `packaging/` | container builds, systemd units and cloud-init, per-OS installer templates |
| `docs/` | `SPEC.md` (verbatim), `spec/` (split), `tasks/` (one file per task), `phases/`, `gates/`, `adr/`, `diagnoses/`, UX, lab, site |
