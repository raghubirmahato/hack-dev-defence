# STATUS

Entry point 2 of 3 (AGENTS.md, STATUS.md, HANDOFF.md). Updated at every task completion. States: `todo`, `designing`, `red`, `green`, `verified`, `accepted`, `done`, `blocked(<reason>)`, `deferred(<reason>, <effort>)`.

## Current phase and milestone

- Phase: **P00 Bootstrap and governance** (gate G00, milestone M0). Spec: v5.2, sha256 in `docs/SPEC.sha256`.
- Builder track: **Track L** (Windows, no Docker; see `docs/ENV.md`). Hosted-only checks are UNVERIFIED(`environment_unsupported`) until a Linux host is supplied.
- **Every pass condition of G00 holds with evidence** ([docs/gates/G00.md](docs/gates/G00.md)); the gate **passed**: committed on 2026-10-19 at the operator's request (1ec43bd, 051eeac, fb82732) and tagged `gate-G00` on fb82732; the pre-commit secret-scan hook is installed (`core.hooksPath=.githooks`).
- The first response (T-0007) was delivered on 2026-10-19 ([docs/FIRST-RESPONSE.md](docs/FIRST-RESPONSE.md)); **no answer has been given**, so all 58 questions are OPEN. `hdd.live.yaml` does not exist yet.
- All ten P00 rows are `done` (promoted 2026-10-19; T-0003 was re-run twice, identical).
- DS0 (section 0.9) was built on 2026-10-19: **T-0561** (runtime profile model, capability matrix, `profile-lint`, `kv-lint`, parity harness, `hddctl preflight --plan`), **T-0562** (`KvStore`/`Bus`/`Limiter`, `MemoryKv`, `RedisKv`, conformance suite, rehydration, budgets) and **T-0563** (embedded PostgreSQL manager, `cargo xtask db`, encrypted backups). Their states and what is UNVERIFIED are in the table and the list below. Next: T-0011, or T-0564 and the other DS1 tasks when the operator has answered Q-048.

Task counts: done=13, todo=568, verified=18 (total 599).

## Open risks

| Risk | Mitigation | Owner task |
| --- | --- | --- |
| The operator has not answered the first response (all questions OPEN, defaults apply for development) | Answers are recorded in `docs/OPERATOR-CONFIRMATIONS.md` | T-0007 |
| ADR-0001 is `spiking`: `ring` is the provisional rustls provider (flagged FFI in `docs/vetting.toml`) | T-0354 compares `ring` and `aws-lc-rs` for the data plane and records the decision | T-0354 |
| `cargo vet` passes only because all 175 third-party crates are exempted; no published audit set is imported (a trust decision) | Operator chooses audit sets to import (Mozilla, Google, Bytecode Alliance, ...) or accepts the exemptions | T-0517 |
| Stubs in `verify` (tracked here as `stub`): `attack-matrix check` -> T-0245, `contrast-check` -> T-0030, `i18n check` -> T-0082, `routes check` -> T-0073 | Each is replaced by its task; until then `verify` reports them `UNVERIFIED(stage_not_reached)` | T-0245, T-0030, T-0082, T-0073 |
| The coverage-guided fuzz target, the data-plane benchmark, coverage and mutation tooling do not exist yet | UNVERIFIED(`tool_unavailable`) / (`stage_not_reached`); proptests cover the parsers meanwhile | T-0259, T-0256, T-0258 |
| Allowlisted host names are trusted to resolve honestly (only the metadata/link-local/multicast baseline is enforced); the DNS stub resolver has no TCP fallback (fails closed) | Documented in `docs/STRIDE.md`; the SSRF client is strict for user URLs | T-0163, T-0156 |
| Section 2.9 names `egress.private_origin_allowlist` but the profile of section 8 has no such field; only the `SsrfPolicy` builder exists (ASM-009) | T-0163 decides the profile field together with the operator | T-0163 |

## Open questions

The full register (58 questions, with defaults and what each blocks) is in [docs/OPERATOR-QUESTIONS.md](docs/OPERATOR-QUESTIONS.md). None is answered yet (all OPEN; the first response was delivered on 2026-10-19, see [docs/FIRST-RESPONSE.md](docs/FIRST-RESPONSE.md)). Level: pilot = 11, cutover = 15, feature = 26, default = 6 questions (definitions in the register).

| Id | Level | Group | Question | Default (dev/pilot) | Blocks |
| --- | --- | --- | --- | --- | --- |
| Q-001 | feature | Deployment | Do you want HDD for your own domains only (`owner_only`) or as a service for other people (`saas`)? | `owner_only` | public signup, billing, tenant-safety guards (saas) |
| Q-002 | feature | Deployment | Which hosting provider, plan, region and uplink speed does the VPS have? | unknown (capacity UNVERIFIED) | shield capacity figures |
| Q-003 | cutover | Deployment | Is a second VPS or a second provider available for a standby edge and a secondary DNS? | none | cutover gate (secondary DNS), AC-21, AC-28, AC-27 |
| Q-004 | feature | Deployment | Is there a closed lab machine (or two machines on a private link) for volumetric tests and the Vuln-Lab? | none | AC-26, AC-29, AC-38, AC-39 lab portions (UNVERIFIED) |
| Q-005 | feature | Brand and product | What is the product name, logo, primary language(s) and locale(s)? | Hack Dev Defence, English | publication of the public site |
| Q-006 | cutover | Brand and product | Who owns the legal text (Terms, Privacy, AUP, DPA) and who reviews it? | operator counsel | public site publication, open signup |
| Q-007 | cutover | Brand and product | Should signup be `disabled`, `invite_only` or `open`? Which email domains are allowed or blocked? Disposable-email policy? | `invite_only` | enabling public signup |
| Q-008 | feature | Brand and product | Which plans and limits do you want (domains, seats, rules, retention, API rate)? | `unlimited` in `owner_only` | paid tiers |
| Q-009 | feature | Brand and product | Do you want billing? Which payment provider and jurisdiction? | none | T-0558 |
| Q-010 | feature | Brand and product | Where is the status page hosted (off the VPS is strongly recommended)? | local static (flagged) | truthful status during saturation |
| Q-011 | feature | Email | SMTP relay host, port, TLS mode, credentials and the sender address for HDD mail; do you control SPF, DKIM and DMARC for the sending domain? | local SMTP sink only | real email delivery tests, AC-46 |
| Q-012 | feature | Email | Operator email for alerts and acceptance mails | none | alert tests |
| Q-013 | feature | Security policy | Password breach check mode: `offline_list`, `hibp_range` (egress to the range API) or `off`? | `offline_list` | enabling range mode needs egress allowlist |
| Q-014 | default | Security policy | Should org owners be able to require MFA for all members? Platform roles always require MFA. | yes | - |
| Q-015 | default | Security policy | IP truncation default for tenants and retention defaults (events/audit) | truncate off, 30 d / 400 d | - |
| Q-016 | default | Security policy | Which presets should new domains start with (recommended: Monitor first, then Balanced)? | `monitor_first` | - |
| Q-017 | feature | Security policy | Is the origin application known to be vulnerable (legacy CMS, old framework)? Which components and versions? | unknown | exposure board matching (AC-30) |
| Q-018 | default | Admin access | Admin surface exposure: `tunnel_only` (SSH/WireGuard) or `routed_with_cidr`? Which CIDRs? | `tunnel_only` | routed exposure |
| Q-019 | pilot | Admin access | What is the runner's source IP and your workstation IP? (Runner must not be in `admin_cidrs`.) | detect | live acceptance |
| Q-020 | pilot | Admin access | SSH source CIDRs for port 22 | operator IP only | deploy |
| Q-021 | pilot | Domains | Platform domain and the apex you want to protect first; registrar and DNS provider; who can change NS at the registrar? | none | P11 deploy; cutover |
| Q-022 | pilot | Domains | Which subzones may the pilot delegate (`test_hostname`, `sandbox_hostname`)? Can you add NS records for them? | none | STOP #1 |
| Q-023 | cutover | Domains | Is there a DS record at the parent for the apex today (DNSSEC enabled at the current provider)? | unknown | cutover (DS check) |
| Q-024 | feature | Domains | Which hostnames are non-HTTP services (mail, SSH, FTP, game servers, VPN) that must stay grey? | none | parity (AC-23) |
| Q-025 | pilot | Origin | Origin address, port, TLS verification mode, Host header; is it behind a CDN or cloud load balancer? | none | P11 |
| Q-026 | cutover | Origin | Can you apply an origin firewall allowlist and a secret header or mTLS? Where (nginx, Apache, cloud firewall)? | pending | AC-18, cutover gate |
| Q-027 | pilot | Origin | Can you place the canary files (and optionally `hdd-canary`) on the origin? | none | AC-05 header checks, AC-10 live (UNVERIFIED) |
| Q-028 | feature | Origin | Do you have an origin access log path/stream for header verification when the canary echo is not installed? | none | - |
| Q-029 | cutover | DDoS | Is mitigation always-on or on-demand? Advertised capacity? What happens when exceeded? Mitigation API or support path? | `mode: none` (pilot only) | cutover unless risk accepted in writing |
| Q-030 | feature | DDoS | Do you own an ASN (RTBH possible)? Do you want BGP integration (Tier 4)? | no | T-0555 |
| Q-031 | feature | DDoS | Heartbeat URL for an external dead-man monitor you run | none | shield alerts under saturation |
| Q-032 | cutover | DNS | External secondary DNS provider and TSIG key exchange details | none | AC-21, cutover gate 2 |
| Q-033 | cutover | TLS | ACME CA preference, account email, CAA policy; approve one-time production issuance when ready | staging only | production issuance (T-0538) |
| Q-034 | feature | TLS | Is a CT monitoring/search service permitted (egress allowlist)? | none | CT signals UNVERIFIED |
| Q-035 | feature | Data | GeoIP/ASN database (license holder) and update method | none | country rules (UNVERIFIED) |
| Q-036 | feature | Data | Threat-intel feeds you permit (hosts, licenses) | disabled | feeds |
| Q-037 | cutover | Data | Backup destination (local, SFTP, S3-compatible), `age` recipient public keys, offline key escrow owner | local only | DR drill, production |
| Q-038 | cutover | Operations | Who is on call, escalation contacts, maintenance windows, and who authorizes rollback? | operator | cutover |
| Q-039 | pilot | Operations | Provider acceptable-use confirmation for security testing from the runner (date) | missing | first live test |
| Q-040 | pilot | Operations | Egress allowlist entries (CA, feeds, SMTP, GeoIP, package mirrors, CT, release host) | minimal | feeds, ACME, mail |
| Q-041 | cutover | Release | Release signing approach (offline key, hardware token, keyless CI) and update channel | offline key | signed upgrades |
| Q-042 | feature | Release | Do you want auto-update (default off) and which channel? | off, stable | - |
| Q-043 | cutover | Compliance | Jurisdiction, DPO needs, breach-notification contacts, data residency | unknown | legal approval |
| Q-044 | cutover | Compliance | Public vulnerability disclosure contact and PGP/age key | none | public launch |
| Q-045 | feature | UX | Design sign-off reviewers and the date for the P03 review | operator | build of affected screens |
| Q-046 | default | UX | Preferred theme default (dark first) and density default | dark, comfortable | - |
| Q-047 | default | Scope | Which Tier 2 to 6 items are priorities after M12? | as listed | - |
| Q-048 | pilot | Runtime | Do you want to run HDD on your own computer (`local`), on a server (`hosted`), or both? Which operating system is your computer? | both, local first | M5 and M12 apply to hosted only |
| Q-049 | feature | Runtime | For `local`: may HDD install its name-constrained local certificate authority into your user trust store (otherwise HTTP-only on loopback or a browser exception)? | ask during first-run setup | TLS in browsers |
| Q-050 | feature | Runtime | For `local`: will you expose it beyond this computer (LAN or an operator-run tunnel)? Which tunnel provider, if any? | no exposure | exposure checks |
| Q-051 | pilot | Hosting | For 24/7: which server or provider and region will run HDD, and which hosting profile (H1 to H5) fits? | H1 single VPS | STOP #1 |
| Q-052 | pilot | Hosting | Does the server's provider allow inbound 53, 80 and 443 and outbound 25 or 587? Is a second server or provider available for H2? | unknown | HC items UNVERIFIED |
| Q-053 | cutover | Hosting | Where should backups go (local, SFTP, S3-compatible), who holds the encryption key and the master-key escrow, and who is on call for the 24/7 runbooks? | local only | AC-56 remote backup |
| Q-054 | feature | Protection scope | Which paths of your sites should sit behind the access gate (admin areas, database tools) and which business flows matter most (login, signup, checkout, OTP, search)? | templates by site platform | AC-57 scenarios |
| Q-055 | feature | Protection scope | Do you have an OpenAPI or GraphQL description for your APIs? | learn from traffic | spec import |
| Q-056 | cutover | Bypass | How will each origin be locked down: outbound tunnel, signed origin authentication, or a firewall allowlist (and can the origin host be changed at all)? | signed origin authentication plus firewall instructions | `block` mode for that site |
| Q-057 | feature | Learned detection | May Sentinel (learned detection) run in `shadow` on your sites, and who approves any promotion to `assist` or `block`? | shadow only | promotion beyond shadow |
| Q-058 | feature | Learned detection | May the optional analyst (a language model) be used, and if so which provider or local model, knowing evidence fields are redacted? | off | analyst features |

## UNVERIFIED list

| ID | Reason code | What the operator must supply |
| --- | --- | --- |
| nightly toolchain, `bpf-linker` | UNVERIFIED(`tool_unavailable`) | Install on a Linux builder before P25 (hdd-xdp-ebpf, AC-26) |
| Docker / compose | UNVERIFIED(`environment_unsupported`) | Nothing for Track L; a Linux/Docker host only if compose-based checks are wanted |
| `nft`, `iptables`, BTF/XDP probe, kernel version, ethtool | UNVERIFIED(`environment_unsupported`) | A Linux lab host (Q-004) for P25, AC-26, AC-29 |
| `cargo-llvm-cov`, `cargo-mutants`, `cargo-fuzz`, `cosign` | UNVERIFIED(`tool_unavailable`) | Install (after vetting, R-08) before the matching step (T-0258, T-0259, T-0517); installed and vetted this session: `tokei`, `cargo-vet`, `cargo-geiger` |
| Coverage-guided fuzz target for the egress parsers; data-plane benchmark | UNVERIFIED(`tool_unavailable`) / (`stage_not_reached`) | `cargo-fuzz` + nightly (T-0259); criterion + proxy (T-0256) |
| `verify` stubs: attack-matrix, contrast, i18n, routes checks, `profile-parity` | UNVERIFIED(`stage_not_reached`) | Implemented by T-0245, T-0030, T-0082, T-0073 and (parity: detection engine, ban pipeline, fixtures) T-0564 |
| `RedisKv`, `RedisBus`, the Redis latency budget, the chaos test (T-0562 A1/A4 Redis halves) | UNVERIFIED(`environment_unsupported`) | A Redis 7 or newer throw-away server: set `HDD_TEST_REDIS_URL` and run `cargo xtask verify --only kv-redis` |
| Embedded PostgreSQL on macOS and Linux, the CI workflow `embedded-db.yml`, the SLSA provenance of the archive (T-0563) | UNVERIFIED(`environment_unsupported`) | A macOS and a Linux runner (the workflow has never run); only Windows x64 was exercised |
| Reachability probes against real hosts (nameserver names, SMTP relay), outbound connectivity | UNVERIFIED(`human_step_pending`) | `hdd.live.yaml` with `egress_allowlist` (`dns://` resolvers, `tcp://smtp:port`; Q-040); only loopback test servers were contacted |
| VPS discovery (`deploy_mode: ssh`) | UNVERIFIED(`human_step_pending`) | An SSH account in `platform.ssh` of `hdd.live.yaml` (Q-020, Q-021) |
| Headless browser launch, fonts rendering | UNVERIFIED(`stage_not_reached`) | Proven by the UI tasks (T-0075); a Chrome-family browser exists on this builder |
| Operator answers to the 58 questions (some default, some block the pilot or cutover) | UNVERIFIED(`human_step_pending`) | Answers by id, see the levels in the open-questions table |

## Last gate report summary

G00 attempted 2026-10-18, first response delivered 2026-10-19: **passed** (tag `gate-G00` on fb82732). Report: [docs/gates/G00.md](docs/gates/G00.md); evidence and logs with sha256: `docs/gates/evidence/G00/`. `cargo xtask verify`: 20 PASS, 0 FAIL, 4 UNVERIFIED (the named stubs). Earlier progress notes: `docs/gates/G00-progress.md`.

## Task table

| ID | Title | State | Evidence | Commit |
| --- | --- | --- | --- | --- |
| [T-0001](docs/tasks/P00/T-0001.md) | Save the specification verbatim, split it, and index every task | done | spec-check, tasks-check; docs/gates/G00.md | |
| [T-0002](docs/tasks/P00/T-0002.md) | Create the state files and the deviation log | done | rules step; docs/gates/G00.md | |
| [T-0003](docs/tasks/P00/T-0003.md) | Environment discovery with read-only commands | done | docs/ENV.md; re-run twice 2026-10-19, identical: docs/gates/evidence/G00/t0003-rerun/ | |
| [T-0004](docs/tasks/P00/T-0004.md) | Cargo workspace, lints, toolchain and dependency policy | done | cargo-check.log, deny, unsafe-scan, vulnlab-graph; docs/gates/G00.md | |
| [T-0005](docs/tasks/P00/T-0005.md) | `hdd-xtask`: verify pipeline, spec tools and claims-lint | done | verify run + negative demos + hook demo: docs/gates/evidence/G00/; docs/gates/G00.md | |
| [T-0006](docs/tasks/P00/T-0006.md) | Live profile v5: schema, example file and validator | done | profile tests, preflight outputs: docs/gates/evidence/G00/; docs/gates/G00.md | |
| [T-0007](docs/tasks/P00/T-0007.md) | Deliver the first response and seed the open-questions register | done | docs/FIRST-RESPONSE.md; first-response checks in the rules step; docs/gates/G00.md | |
| [T-0008](docs/tasks/P00/T-0008.md) | ADR process and the initial decision queue | done | adr-check, dependency-vetting, docs/vetting.toml; docs/gates/G00.md | |
| [T-0009](docs/tasks/P00/T-0009.md) | Egress client, SSRF guard, target allowlist and kill switch | done | egress test suite; docs/STRIDE.md; docs/gates/G00.md | |
| [T-0010](docs/tasks/P00/T-0010.md) | Capability matrix, requirement tooling and gate G00 | done | matrix + gate-report tooling; gate G00 passed (tag gate-G00); docs/gates/G00.md | |
| [T-0011](docs/tasks/P01/T-0011.md) | Product principles, success measures and UX charter | verified | docs/evidence/P01/T-0011-*; docs/UX/CHARTER.md, MEASURES.md, decisions/UXD-001..003.md; `cargo xtask ux-docs` | |
| [T-0012](docs/tasks/P01/T-0012.md) | Personas and jobs-to-be-done | verified | docs/evidence/P01/T-0012-*; docs/UX/personas/*, persona-journey-matrix.md; `cargo xtask ux-docs` | |
| [T-0013](docs/tasks/P01/T-0013.md) | Pattern review of comparable products (documented first principles) | verified | docs/evidence/P01/T-0013-*; docs/UX/PATTERNS.md, design-requirements.md; review UNVERIFIED(capability_not_supplied) | |
| [T-0014](docs/tasks/P01/T-0014.md) | Information architecture and URL scheme | verified | docs/evidence/P01/T-0014-*; docs/UX/IA.md, routes.toml; `cargo xtask ux-docs` | |
| [T-0015](docs/tasks/P01/T-0015.md) | Navigation model and wayfinding | verified | docs/evidence/P01/T-0015-*; docs/UX/NAVIGATION.md; `cargo xtask ux-docs` | |
| [T-0016](docs/tasks/P01/T-0016.md) | Journey maps J-01 to J-12 (acquisition to origin test) | verified | docs/evidence/P01/T-0016-*; docs/UX/journeys/J-01..J-12.md, spec-patches.md; `cargo xtask ux-docs` | |
| [T-0017](docs/tasks/P01/T-0017.md) | Journey maps J-13 to J-24 (DNS, TLS, protection, appeals, lockdown) | verified | docs/evidence/P01/T-0017-*; docs/UX/journeys/J-13..J-24.md; `cargo xtask ux-docs` | |
| [T-0018](docs/tasks/P01/T-0018.md) | Journey maps J-25 to J-34 (readiness, teams, API, admin, privacy, incident) | verified | docs/evidence/P01/T-0018-*; docs/UX/journeys/J-25..J-34.md, journey-dependencies.md; `cargo xtask ux-docs` | |
| [T-0019](docs/tasks/P01/T-0019.md) | Content strategy, microcopy guide and the claims dictionary | verified | docs/evidence/P01/T-0019-*; docs/UX/CONTENT.md, glossary.md, i18n/en/copy-deck.ftl; claims context rules | |
| [T-0020](docs/tasks/P01/T-0020.md) | Error-handling UX model and visitor-facing error philosophy | verified | docs/evidence/P01/T-0020-verify/summary.json | |
| [T-0021](docs/tasks/P01/T-0021.md) | State patterns: empty, loading, offline, permission-denied, partial data | todo |  | |
| [T-0022](docs/tasks/P01/T-0022.md) | Accessibility strategy and test plan | verified | docs/evidence/P01/T-0022-*; docs/UX/ACCESSIBILITY.md, a11y-checklists/, wcag22-criteria.toml | |
| [T-0023](docs/tasks/P01/T-0023.md) | Internationalization and localization strategy | verified | docs/evidence/P01/T-0023-verify/summary.json | |
| [T-0024](docs/tasks/P01/T-0024.md) | Responsive and device strategy | verified | docs/evidence/P01/T-0024-*; docs/UX/RESPONSIVE.md | |
| [T-0025](docs/tasks/P01/T-0025.md) | Security UX: dangerous actions, lockout prevention, honest warnings | verified | docs/evidence/P01/T-0025-*; docs/UX/SECURITY-UX.md, dangerous-actions.md, i18n/en/security-ux.ftl | |
| [T-0026](docs/tasks/P01/T-0026.md) | Onboarding and activation design (checklist, readiness semantics) | verified | docs/evidence/P01/T-0026-*; docs/UX/ONBOARDING.md, READINESS-MODEL.md, i18n/en/onboarding.ftl | |
| [T-0027](docs/tasks/P01/T-0027.md) | Data visualization and dashboard information design | verified | docs/evidence/P01/T-0027-*; docs/UX/DATAVIZ.md, metrics-dictionary.md | |
| [T-0028](docs/tasks/P01/T-0028.md) | UX review pack and operator decision list | todo |  | |
| [T-0029](docs/tasks/P02/T-0029.md) | Brand foundations: name, logo mark, wordmark, favicons | todo |  | |
| [T-0030](docs/tasks/P02/T-0030.md) | Color tokens, themes and the contrast checker | todo |  | |
| [T-0031](docs/tasks/P02/T-0031.md) | Typography tokens and self-hosted fonts | todo |  | |
| [T-0032](docs/tasks/P02/T-0032.md) | Spacing, size, radius, elevation, z-index tokens and the token build pipeline | todo |  | |
| [T-0033](docs/tasks/P02/T-0033.md) | Motion tokens and reduced-motion behavior | todo |  | |
| [T-0034](docs/tasks/P02/T-0034.md) | Icon system and SVG sprite pipeline | todo |  | |
| [T-0035](docs/tasks/P02/T-0035.md) | CSS architecture, cascade layers and the stylesheet bundler | todo |  | |
| [T-0036](docs/tasks/P02/T-0036.md) | Layout primitives and the application frame | todo |  | |
| [T-0037](docs/tasks/P02/T-0037.md) | Buttons, links and icon buttons | todo |  | |
| [T-0038](docs/tasks/P02/T-0038.md) | Text inputs, textarea, labels, help and error summary | todo |  | |
| [T-0039](docs/tasks/P02/T-0039.md) | Selection controls: checkbox, radio, switch, select, segmented control | todo |  | |
| [T-0040](docs/tasks/P02/T-0040.md) | Advanced inputs: password, OTP, tag input, copy field, file dropzone, restricted regex input | todo |  | |
| [T-0041](docs/tasks/P02/T-0041.md) | Feedback components: toast, banner, inline message, progress, spinner, skeleton, empty and error states | todo |  | |
| [T-0042](docs/tasks/P02/T-0042.md) | Overlays: dialog, drawer, confirm dialog, popover, tooltip, dropdown menu | todo |  | |
| [T-0043](docs/tasks/P02/T-0043.md) | Navigation components: sidebar, top bar, tabs, breadcrumbs, pagination, stepper, switchers | todo |  | |
| [T-0044](docs/tasks/P02/T-0044.md) | Data display: table, key-value list, timeline, badges, cards, diff viewer | todo |  | |
| [T-0045](docs/tasks/P02/T-0045.md) | Security-domain components: Ray ID, IP chip, countdown, payload viewer, readiness ring, cloud toggle, nameserver card, verification poller | todo |  | |
| [T-0046](docs/tasks/P02/T-0046.md) | Chart and map visual specification (style, data tables, patterns) | todo |  | |
| [T-0047](docs/tasks/P02/T-0047.md) | Component gallery, documentation standard and the browser smoke harness v0 | todo |  | |
| [T-0048](docs/tasks/P02/T-0048.md) | Command palette, theme/locale/density toggles and the user menu | todo |  | |
| [T-0049](docs/tasks/P02/T-0049.md) | Rule builder and condition-group components | todo |  | |
| [T-0050](docs/tasks/P02/T-0050.md) | Theming runtime, high-contrast and forced-colors support | todo |  | |
| [T-0051](docs/tasks/P02/T-0051.md) | Print stylesheet and report/PDF styles | todo |  | |
| [T-0052](docs/tasks/P02/T-0052.md) | Design system release, visual baselines and gate G02 | todo |  | |
| [T-0053](docs/tasks/P03/T-0053.md) | Prototype tooling and policy | todo |  | |
| [T-0054](docs/tasks/P03/T-0054.md) | Public pages (S-001 to S-018) | todo |  | |
| [T-0055](docs/tasks/P03/T-0055.md) | Authentication screens (S-020 to S-034) | todo |  | |
| [T-0056](docs/tasks/P03/T-0056.md) | Onboarding wizard and MFA enrollment flows (S-035, S-030, S-031) | todo |  | |
| [T-0057](docs/tasks/P03/T-0057.md) | App shell, organization overview and domains list (S-040, S-041) | todo |  | |
| [T-0058](docs/tasks/P03/T-0058.md) | Add-domain wizard, all eight steps (S-042) | todo |  | |
| [T-0059](docs/tasks/P03/T-0059.md) | Domain overview, readiness and DNS screens (S-043 to S-049, S-099) | todo |  | |
| [T-0060](docs/tasks/P03/T-0060.md) | TLS and origin screens (S-050 to S-053, S-098) | todo |  | |
| [T-0061](docs/tasks/P03/T-0061.md) | Security center screens (S-054 to S-057) | todo |  | |
| [T-0062](docs/tasks/P03/T-0062.md) | Rules, rule builder, dry-run and exceptions (S-058 to S-060, S-064) | todo |  | |
| [T-0063](docs/tasks/P03/T-0063.md) | Rate limiting, bots, access, honeypots, outbound, block page, access gate, API discovery, business flows, coverage (S-061 to S-063, S-095 to S-097, S-131 to S-134) | todo |  | |
| [T-0064](docs/tasks/P03/T-0064.md) | Live monitor, event detail and analytics (S-065, S-066, S-070 to S-072) | todo |  | |
| [T-0065](docs/tasks/P03/T-0065.md) | IP jail, appeals and visitor-facing pages (S-067 to S-069, S-140 to S-148) | todo |  | |
| [T-0066](docs/tasks/P03/T-0066.md) | Reports, notifications, integrations and webhooks (S-073 to S-079) | todo |  | |
| [T-0067](docs/tasks/P03/T-0067.md) | Team, API keys, audit, plan, settings and account screens (S-080 to S-094) | todo |  | |
| [T-0068](docs/tasks/P03/T-0068.md) | Platform admin screens (S-100 to S-130, S-135, S-136) | todo |  | |
| [T-0069](docs/tasks/P03/T-0069.md) | Accessibility, content and heuristic review of all prototypes | todo |  | |
| [T-0070](docs/tasks/P03/T-0070.md) | Usability walkthrough, design sign-off request and gate G03 | todo |  | |
| [T-0071](docs/tasks/P04/T-0071.md) | UI stack spike and ADR: askama + HTMX + vanilla islands versus Leptos SSR | todo |  | |
| [T-0072](docs/tasks/P04/T-0072.md) | Asset pipeline: CSS and JS bundling, SRI manifest, precompression | todo |  | |
| [T-0073](docs/tasks/P04/T-0073.md) | `hdd-web` skeleton: surfaces, host routing, configuration and graceful lifecycle | todo |  | |
| [T-0074](docs/tasks/P04/T-0074.md) | Template layer: page contexts, layouts, partial rendering and `SafeHtml` | todo |  | |
| [T-0075](docs/tasks/P04/T-0075.md) | Security headers, CSP with nonces, Trusted Types and violation reporting | todo |  | |
| [T-0076](docs/tasks/P04/T-0076.md) | Static asset serving: caching, compression, ranges and path safety | todo |  | |
| [T-0077](docs/tasks/P04/T-0077.md) | HTMX integration policy and configuration | todo |  | |
| [T-0078](docs/tasks/P04/T-0078.md) | Islands framework and the first-party interactive modules | todo |  | |
| [T-0079](docs/tasks/P04/T-0079.md) | Form handling library: extraction, validation, errors, idempotency and PRG | todo |  | |
| [T-0080](docs/tasks/P04/T-0080.md) | CSRF protection and request-origin verification | todo |  | |
| [T-0081](docs/tasks/P04/T-0081.md) | Cookie utilities and preference cookies | todo |  | |
| [T-0082](docs/tasks/P04/T-0082.md) | Internationalization runtime (Fluent), key checks and pseudo-locale | todo |  | |
| [T-0083](docs/tasks/P04/T-0083.md) | Date, time, number and unit formatting; time zones | todo |  | |
| [T-0084](docs/tasks/P04/T-0084.md) | Flash and toast contract: `HX-Trigger`, flash cookies and no-JS fallbacks | todo |  | |
| [T-0085](docs/tasks/P04/T-0085.md) | Error pages and `Problem` rendering with content negotiation | todo |  | |
| [T-0086](docs/tasks/P04/T-0086.md) | SSE plumbing and the live-feed island | todo |  | |
| [T-0087](docs/tasks/P04/T-0087.md) | Table infrastructure: cursor pagination, URL state, saved views, CSV export | todo |  | |
| [T-0088](docs/tasks/P04/T-0088.md) | SVG chart renderer in Rust | todo |  | |
| [T-0089](docs/tasks/P04/T-0089.md) | Browser end-to-end harness: real server, real databases, helpers | todo |  | |
| [T-0090](docs/tasks/P04/T-0090.md) | Visual regression pipeline | todo |  | |
| [T-0091](docs/tasks/P04/T-0091.md) | Accessibility test harness: axe, keyboard traversal, reflow, spacing, zoom, forced colors | todo |  | |
| [T-0092](docs/tasks/P04/T-0092.md) | Performance budgets and lab Web Vitals checks | todo |  | |
| [T-0093](docs/tasks/P04/T-0093.md) | Frontend security test suite | todo |  | |
| [T-0094](docs/tasks/P04/T-0094.md) | Serve the gallery at `/admin/design-system` and pass gate G04 | todo |  | |
| [T-0095](docs/tasks/P05/T-0095.md) | Public surface scaffolding and the landing page (S-001) | todo |  | |
| [T-0096](docs/tasks/P05/T-0096.md) | Features and "How protection works, and its limits" (S-002, S-003) with claims evidence | todo |  | |
| [T-0097](docs/tasks/P05/T-0097.md) | Documentation engine: Markdown rendering, sanitization, TOC and search | todo |  | |
| [T-0098](docs/tasks/P05/T-0098.md) | Documentation content v1 | todo |  | |
| [T-0099](docs/tasks/P05/T-0099.md) | API reference page (S-007) from OpenAPI | todo |  | |
| [T-0100](docs/tasks/P05/T-0100.md) | Status page (S-008) with real probes | todo |  | |
| [T-0101](docs/tasks/P05/T-0101.md) | Legal pages, cookie information and subprocessors (S-010 to S-013) | todo |  | |
| [T-0102](docs/tasks/P05/T-0102.md) | Contact, abuse report and security disclosure (S-009, S-014) | todo |  | |
| [T-0103](docs/tasks/P05/T-0103.md) | Sitemap, robots, canonical URLs, metadata and caching for public pages | todo |  | |
| [T-0104](docs/tasks/P05/T-0104.md) | Public site gate G05 | todo |  | |
| [T-0105](docs/tasks/P06/T-0105.md) | Identity data model, migrations and database roles | todo |  | |
| [T-0106](docs/tasks/P06/T-0106.md) | Password policy, hashing, breached-password check and strength estimator | todo |  | |
| [T-0107](docs/tasks/P06/T-0107.md) | Signup: API and UI (S-020) | todo |  | |
| [T-0108](docs/tasks/P06/T-0108.md) | Signup abuse controls and the proof-of-work core library | todo |  | |
| [T-0109](docs/tasks/P06/T-0109.md) | `hdd-mailer`: SMTP delivery, outbox, retries, suppression and domain checks | todo |  | |
| [T-0110](docs/tasks/P06/T-0110.md) | Email templates catalog | todo |  | |
| [T-0111](docs/tasks/P06/T-0111.md) | Email verification flow (S-021, S-022) | todo |  | |
| [T-0112](docs/tasks/P06/T-0112.md) | Login API and UI (S-023) | todo |  | |
| [T-0113](docs/tasks/P06/T-0113.md) | Session management | todo |  | |
| [T-0114](docs/tasks/P06/T-0114.md) | TOTP enrollment and verification (S-030, S-024) | todo |  | |
| [T-0115](docs/tasks/P06/T-0115.md) | Recovery codes (S-031, S-025) | todo |  | |
| [T-0116](docs/tasks/P06/T-0116.md) | WebAuthn passkeys (S-026) | todo |  | |
| [T-0117](docs/tasks/P06/T-0117.md) | MFA policy enforcement | todo |  | |
| [T-0118](docs/tasks/P06/T-0118.md) | Step-up re-authentication (S-032) | todo |  | |
| [T-0119](docs/tasks/P06/T-0119.md) | Password reset (S-027, S-028) | todo |  | |
| [T-0120](docs/tasks/P06/T-0120.md) | Change password and change email | todo |  | |
| [T-0121](docs/tasks/P06/T-0121.md) | Sessions, devices and security timeline UI (S-089, S-088) | todo |  | |
| [T-0122](docs/tasks/P06/T-0122.md) | Login anomaly detection and notifications | todo |  | |
| [T-0123](docs/tasks/P06/T-0123.md) | Account lock, unlock and recovery policy | todo |  | |
| [T-0124](docs/tasks/P06/T-0124.md) | API keys: lifecycle, scopes, bearer authentication (S-080) | todo |  | |
| [T-0125](docs/tasks/P06/T-0125.md) | RBAC engine and route-permission enforcement | todo |  | |
| [T-0126](docs/tasks/P06/T-0126.md) | Organization model: creation, slug rules, switcher data, quotas hooks | todo |  | |
| [T-0127](docs/tasks/P06/T-0127.md) | Team invitations and role management (S-081 to S-083) | todo |  | |
| [T-0128](docs/tasks/P06/T-0128.md) | Tenant isolation: RLS plumbing and the BOLA test suite | todo |  | |
| [T-0129](docs/tasks/P06/T-0129.md) | Account profile and preferences (S-087) | todo |  | |
| [T-0130](docs/tasks/P06/T-0130.md) | Data export and account deletion (S-090) | todo |  | |
| [T-0131](docs/tasks/P06/T-0131.md) | Audit log core, hash chain and user-visible security timeline | todo |  | |
| [T-0132](docs/tasks/P06/T-0132.md) | Identity abuse test suite against HDD's own login | todo |  | |
| [T-0133](docs/tasks/P06/T-0133.md) | Identity end-to-end browser tests (AC-35) | todo |  | |
| [T-0134](docs/tasks/P06/T-0134.md) | Bootstrap admin, platform roles and the first-run experience | todo |  | |
| [T-0135](docs/tasks/P06/T-0135.md) | Identity security hardening review | todo |  | |
| [T-0136](docs/tasks/P06/T-0136.md) | Identity gate G06 | todo |  | |
| [T-0137](docs/tasks/P07/T-0137.md) | App frame, sidebar, top bar and switchers | todo |  | |
| [T-0138](docs/tasks/P07/T-0138.md) | Navigation state, breadcrumbs, titles and keyboard shortcuts | todo |  | |
| [T-0139](docs/tasks/P07/T-0139.md) | Organization overview (S-040) | todo |  | |
| [T-0140](docs/tasks/P07/T-0140.md) | Rollup pipeline v0 and the metrics foundation for analytics | todo |  | |
| [T-0141](docs/tasks/P07/T-0141.md) | Notification center and bell (S-075) | todo |  | |
| [T-0142](docs/tasks/P07/T-0142.md) | Command palette and global search (S-091) | todo |  | |
| [T-0143](docs/tasks/P07/T-0143.md) | Onboarding checklist component and persistence | todo |  | |
| [T-0144](docs/tasks/P07/T-0144.md) | Empty-state implementations and honest-data guards | todo |  | |
| [T-0145](docs/tasks/P07/T-0145.md) | Organization settings (S-086) | todo |  | |
| [T-0146](docs/tasks/P07/T-0146.md) | Plans, quotas and usage metering (S-085) | todo |  | |
| [T-0147](docs/tasks/P07/T-0147.md) | Audit log UI (S-084) | todo |  | |
| [T-0148](docs/tasks/P07/T-0148.md) | Help menu, shortcuts overlay, in-app docs links and feedback | todo |  | |
| [T-0149](docs/tasks/P07/T-0149.md) | Platform announcements display | todo |  | |
| [T-0150](docs/tasks/P07/T-0150.md) | Global error, permission and offline handling in the app | todo |  | |
| [T-0151](docs/tasks/P07/T-0151.md) | App shell accessibility, visual and performance verification | todo |  | |
| [T-0152](docs/tasks/P07/T-0152.md) | App shell gate G07 | todo |  | |
| [T-0153](docs/tasks/P08/T-0153.md) | Domain data model and lifecycle state machine | todo |  | |
| [T-0154](docs/tasks/P08/T-0154.md) | Domain input validation, normalization and claim rules | todo |  | |
| [T-0155](docs/tasks/P08/T-0155.md) | Add-domain wizard step 1: enter domains (S-042) | todo |  | |
| [T-0156](docs/tasks/P08/T-0156.md) | Existing-DNS scan job (step 2) | todo |  | |
| [T-0157](docs/tasks/P08/T-0157.md) | DNS import adapters: zone file, manual entry, AXFR and provider placeholders | todo |  | |
| [T-0158](docs/tasks/P08/T-0158.md) | Record classification, proxy defaults and origin-leak hints | todo |  | |
| [T-0159](docs/tasks/P08/T-0159.md) | Integration mode selector and requirement computation (step 3) | todo |  | |
| [T-0160](docs/tasks/P08/T-0160.md) | Ownership verification engine | todo |  | |
| [T-0161](docs/tasks/P08/T-0161.md) | NS delegation checker and DS detection | todo |  | |
| [T-0162](docs/tasks/P08/T-0162.md) | CNAME and A-record verification for partial modes | todo |  | |
| [T-0163](docs/tasks/P08/T-0163.md) | Origin configuration (step 6) and SSRF guard at save time | todo |  | |
| [T-0164](docs/tasks/P08/T-0164.md) | Origin connectivity test (server-side probe) | todo |  | |
| [T-0165](docs/tasks/P08/T-0165.md) | Origin IP exposure analysis | todo |  | |
| [T-0166](docs/tasks/P08/T-0166.md) | TLS planning step: pre-issuance paths and CAA checks | todo |  | |
| [T-0167](docs/tasks/P08/T-0167.md) | Protection preset selection (step 7) | todo |  | |
| [T-0168](docs/tasks/P08/T-0168.md) | Go-live checklist and activation (step 8) | todo |  | |
| [T-0169](docs/tasks/P08/T-0169.md) | Pre-cutover testing helpers: `--resolve` commands, hosts snippet, preview hostname | todo |  | |
| [T-0170](docs/tasks/P08/T-0170.md) | Pause, resume and emergency bypass semantics | todo |  | |
| [T-0171](docs/tasks/P08/T-0171.md) | Domain overview page (S-043) | todo |  | |
| [T-0172](docs/tasks/P08/T-0172.md) | Protection Readiness Score engine and page (S-044) | todo |  | |
| [T-0173](docs/tasks/P08/T-0173.md) | Domain settings and decommission wizard (S-094) | todo |  | |
| [T-0174](docs/tasks/P08/T-0174.md) | Domain transfer between organizations and dispute resolution | todo |  | |
| [T-0175](docs/tasks/P08/T-0175.md) | Onboarding end-to-end tests for all integration modes (AC-37) | todo |  | |
| [T-0176](docs/tasks/P08/T-0176.md) | Domain onboarding gate G08 | todo |  | |
| [T-0177](docs/tasks/P09/T-0177.md) | DNS data model, zone lifecycle and records API | todo |  | |
| [T-0178](docs/tasks/P09/T-0178.md) | Per-type record validation library | todo |  | |
| [T-0179](docs/tasks/P09/T-0179.md) | Zone snapshot model and the pure answer engine | todo |  | |
| [T-0180](docs/tasks/P09/T-0180.md) | SPF, DKIM and DMARC helpers and linting | todo |  | |
| [T-0181](docs/tasks/P09/T-0181.md) | DNS records screen (S-045) with proxy toggles and bulk actions | todo |  | |
| [T-0182](docs/tasks/P09/T-0182.md) | DNS record editor (S-046) with "what will resolve" preview | todo |  | |
| [T-0183](docs/tasks/P09/T-0183.md) | Mail safety panel and the CAA wizard | todo |  | |
| [T-0184](docs/tasks/P09/T-0184.md) | Import/export and the parity report UI (S-047) | todo |  | |
| [T-0185](docs/tasks/P09/T-0185.md) | Zone version history, diff and rollback (S-048) | todo |  | |
| [T-0186](docs/tasks/P09/T-0186.md) | DNS change-safety engine | todo |  | |
| [T-0187](docs/tasks/P09/T-0187.md) | Record templates library with provenance | todo |  | |
| [T-0188](docs/tasks/P09/T-0188.md) | SOA, TTL policy and zone settings | todo |  | |
| [T-0189](docs/tasks/P09/T-0189.md) | DNSSEC status and DS check UI (S-049) | todo |  | |
| [T-0190](docs/tasks/P09/T-0190.md) | Propagation checker (S-099) | todo |  | |
| [T-0191](docs/tasks/P09/T-0191.md) | Secondary DNS and TSIG settings (data model and UI hooks) | todo |  | |
| [T-0192](docs/tasks/P09/T-0192.md) | Dangling record and takeover candidate scanner | todo |  | |
| [T-0193](docs/tasks/P09/T-0193.md) | DNS analytics views and control-plane DNS tests | todo |  | |
| [T-0194](docs/tasks/P09/T-0194.md) | DNS management gate G09 | todo |  | |
| [T-0195](docs/tasks/P10/T-0195.md) | Certificate data model and envelope encryption | todo |  | |
| [T-0196](docs/tasks/P10/T-0196.md) | TLS settings model, policy validator and UI (S-050) | todo |  | |
| [T-0197](docs/tasks/P10/T-0197.md) | Certificates screen (S-051) and ACME error explanations | todo |  | |
| [T-0198](docs/tasks/P10/T-0198.md) | ACME order state machine and CA rate-limit budget service | todo |  | |
| [T-0199](docs/tasks/P10/T-0199.md) | Custom certificate upload and validation | todo |  | |
| [T-0200](docs/tasks/P10/T-0200.md) | HSTS, redirect and minimum TLS policy engine with preload guidance | todo |  | |
| [T-0201](docs/tasks/P10/T-0201.md) | CAA and Certificate Transparency monitoring | todo |  | |
| [T-0202](docs/tasks/P10/T-0202.md) | Origin TLS verification diagnostics and pin management | todo |  | |
| [T-0203](docs/tasks/P10/T-0203.md) | Certificate expiry alerting with lifetime-relative thresholds | todo |  | |
| [T-0204](docs/tasks/P10/T-0204.md) | Wildcard and preview-zone certificate flows | todo |  | |
| [T-0205](docs/tasks/P10/T-0205.md) | TLS control-plane test suite | todo |  | |
| [T-0206](docs/tasks/P10/T-0206.md) | TLS management gate G10 | todo |  | |
| [T-0207](docs/tasks/P11/T-0207.md) | Minimal `hdd-dns` and the server-core spike | todo |  | |
| [T-0208](docs/tasks/P11/T-0208.md) | Minimal `hdd-proxy`: TLS, host routing, origin forwarding, challenge serving | todo |  | |
| [T-0209](docs/tasks/P11/T-0209.md) | ACME client v0 (staging): HTTP-01 issuance and hot reload | todo |  | |
| [T-0210](docs/tasks/P11/T-0210.md) | `hdd-canary` sidecar and canary files | verified | docs/evidence/P11/T-0210-verify/summary.json | |
| [T-0211](docs/tasks/P11/T-0211.md) | Configuration distribution v0: snapshots, config bus and resync | todo |  | |
| [T-0212](docs/tasks/P11/T-0212.md) | `hddctl deploy` v0: systemd, services, firewall baseline, rollback | todo |  | |
| [T-0213](docs/tasks/P11/T-0213.md) | Kernel tuning v0 (L2 subset) with undo | todo |  | |
| [T-0214](docs/tasks/P11/T-0214.md) | Telemetry v0 across services | todo |  | |
| [T-0215](docs/tasks/P11/T-0215.md) | Acceptance runner skeleton | verified | docs/evidence/P11/T-0215-verify/summary.json | |
| [T-0216](docs/tasks/P11/T-0216.md) | STOP #1: instruction generator and human-step detection | todo |  | |
| [T-0217](docs/tasks/P11/T-0217.md) | AC-00 preflight on the pilot (`hddctl preflight`) | todo |  | |
| [T-0218](docs/tasks/P11/T-0218.md) | First live checks: AC-03 basic, AC-04 staging, AC-05 canary subset | todo |  | |
| [T-0219](docs/tasks/P11/T-0219.md) | Walking-skeleton report and decision confirmations | todo |  | |
| [T-0220](docs/tasks/P11/T-0220.md) | Walking skeleton gate G11 | todo |  | |
| [T-0221](docs/tasks/P12/T-0221.md) | Security overview screen (S-054) | todo |  | |
| [T-0222](docs/tasks/P12/T-0222.md) | WAF settings screen (S-055) and the switch-to-block dialog | todo |  | |
| [T-0223](docs/tasks/P12/T-0223.md) | Attack categories screen (S-056) and category policy model | todo |  | |
| [T-0224](docs/tasks/P12/T-0224.md) | Vulnerable-Origin Shield screen (S-057) and the "Try a payload" tool | todo |  | |
| [T-0225](docs/tasks/P12/T-0225.md) | Auth endpoint manager: declared and detected endpoints | todo |  | |
| [T-0226](docs/tasks/P12/T-0226.md) | Exceptions manager (S-064) | todo |  | |
| [T-0227](docs/tasks/P12/T-0227.md) | Rules list screen (S-058) and rule model | todo |  | |
| [T-0228](docs/tasks/P12/T-0228.md) | Rule builder (S-059): server-side validation, sentence preview, sample tester | todo |  | |
| [T-0229](docs/tasks/P12/T-0229.md) | Rule dry-run and baseline replay (S-060) | todo |  | |
| [T-0230](docs/tasks/P12/T-0230.md) | Rate limiting screen (S-061) and rule model | todo |  | |
| [T-0231](docs/tasks/P12/T-0231.md) | Bots and challenge screen (S-062) | todo |  | |
| [T-0232](docs/tasks/P12/T-0232.md) | Access lists screen (S-063) with self-lockout preview and CSV import | todo |  | |
| [T-0233](docs/tasks/P12/T-0233.md) | Honeypots and decoys screen (S-095) | todo |  | |
| [T-0234](docs/tasks/P12/T-0234.md) | Configuration revisions screen (S-092): timeline, diff, rollback | todo |  | |
| [T-0235](docs/tasks/P12/T-0235.md) | Domain emergency controls (S-093): under attack, safe mode, pause | todo |  | |
| [T-0236](docs/tasks/P12/T-0236.md) | Block page customization (S-096) with shared visitor templates | todo |  | |
| [T-0237](docs/tasks/P12/T-0237.md) | Security policy document, validation, compile and versioning (execute first in P12) | todo |  | |
| [T-0238](docs/tasks/P12/T-0238.md) | Security console end-to-end tests, accessibility and gate G12 | todo |  | |
| [T-0239](docs/tasks/P13/T-0239.md) | `hdd-waf-core` skeleton, public API and purity enforcement | todo |  | |
| [T-0240](docs/tasks/P13/T-0240.md) | Request model and vector extraction | todo |  | |
| [T-0241](docs/tasks/P13/T-0241.md) | Normalizer: the `decoded` view | todo |  | |
| [T-0242](docs/tasks/P13/T-0242.md) | Canonicalizer: the `canonical` view | todo |  | |
| [T-0243](docs/tasks/P13/T-0243.md) | Normalizer property tests, differential tests and fuzz targets | todo |  | |
| [T-0244](docs/tasks/P13/T-0244.md) | Prefilter and signature engine (Aho-Corasick plus regex automata) | todo |  | |
| [T-0245](docs/tasks/P13/T-0245.md) | Rule model, rule files and packs | todo |  | |
| [T-0246](docs/tasks/P13/T-0246.md) | Scoring engine, thresholds and `docs/SCORING.md` | todo |  | |
| [T-0247](docs/tasks/P13/T-0247.md) | Exceptions engine | todo |  | |
| [T-0248](docs/tasks/P13/T-0248.md) | Custom rule evaluation | todo |  | |
| [T-0249](docs/tasks/P13/T-0249.md) | Bounded parsers: forms, multipart, JSON, XML and decompression | todo |  | |
| [T-0250](docs/tasks/P13/T-0250.md) | GraphQL light parser and vector extraction | todo |  | |
| [T-0251](docs/tasks/P13/T-0251.md) | Field-kind context typing | todo |  | |
| [T-0252](docs/tasks/P13/T-0252.md) | Verdict and event model, evidence extraction and ban intents | todo |  | |
| [T-0253](docs/tasks/P13/T-0253.md) | Redaction library | todo |  | |
| [T-0254](docs/tasks/P13/T-0254.md) | Fixture system, payload classes and held-out sets | todo |  | |
| [T-0255](docs/tasks/P13/T-0255.md) | Benign corpora v1 and the false-positive gate | todo |  | |
| [T-0256](docs/tasks/P13/T-0256.md) | Performance engineering and global inspection budgets | todo |  | |
| [T-0257](docs/tasks/P13/T-0257.md) | Over-limit policy implementation | todo |  | |
| [T-0258](docs/tasks/P13/T-0258.md) | Mutation testing and test-quality gates | todo |  | |
| [T-0259](docs/tasks/P13/T-0259.md) | Fuzz targets, corpora and nightly campaign for the engine | todo |  | |
| [T-0260](docs/tasks/P13/T-0260.md) | Inspect API (`POST /api/v1/waf/inspect`) and dry-run semantics | todo |  | |
| [T-0261](docs/tasks/P13/T-0261.md) | Proxy integration: pipeline stages 11 to 15 in monitor, log and block modes | todo |  | |
| [T-0262](docs/tasks/P13/T-0262.md) | WAF core gate G13 | todo |  | |
| [T-0263](docs/tasks/P14/T-0263.md) | SQL tokenizer with dialect awareness | todo |  | |
| [T-0264](docs/tasks/P14/T-0264.md) | Fingerprint engine and fingerprint database tooling | todo |  | |
| [T-0265](docs/tasks/P14/T-0265.md) | Hard family H1: tautologies and always-true predicates | todo |  | |
| [T-0266](docs/tasks/P14/T-0266.md) | Hard family H2: quote breakout followed by comment or terminator | todo |  | |
| [T-0267](docs/tasks/P14/T-0267.md) | Hard family H3: UNION-based extraction and column probing | todo |  | |
| [T-0268](docs/tasks/P14/T-0268.md) | Hard family H4: stacked queries and dangerous statements | todo |  | |
| [T-0269](docs/tasks/P14/T-0269.md) | Hard family H5: blind, time-based, error-based and out-of-band functions | todo |  | |
| [T-0270](docs/tasks/P14/T-0270.md) | Hard family H6: schema and metadata discovery in SQL context | todo |  | |
| [T-0271](docs/tasks/P14/T-0271.md) | Authentication-bypass idioms (H7) and evasion constructs (H8) | todo |  | |
| [T-0272](docs/tasks/P14/T-0272.md) | Field-kind context policy and learned parameter shapes | todo |  | |
| [T-0273](docs/tasks/P14/T-0273.md) | SQLi ban policy: from hard hit to `BanIntent` | todo |  | |
| [T-0274](docs/tasks/P14/T-0274.md) | Auth-endpoint SQLi mode and the success-after-attack tripwire | todo |  | |
| [T-0275](docs/tasks/P14/T-0275.md) | NoSQL, LDAP, XPath and GraphQL injection detectors | todo |  | |
| [T-0276](docs/tasks/P14/T-0276.md) | Write-path hardening and second-order injection mitigation | todo |  | |
| [T-0277](docs/tasks/P14/T-0277.md) | Time-based attack behavioral detector | todo |  | |
| [T-0278](docs/tasks/P14/T-0278.md) | SQLi core fixtures and variant generators | todo |  | |
| [T-0279](docs/tasks/P14/T-0279.md) | SQL-prose and structured benign suite | todo |  | |
| [T-0280](docs/tasks/P14/T-0280.md) | sqlmap campaign harness (lab-only) and coverage measurement | todo |  | |
| [T-0281](docs/tasks/P14/T-0281.md) | SQLi metrics, events and analytics | todo |  | |
| [T-0282](docs/tasks/P14/T-0282.md) | SQLi shield UI integration: subtype toggles, strictness, payload tester wiring | todo |  | |
| [T-0283](docs/tasks/P14/T-0283.md) | AC-39 SQLi matrix test implementation (engine, inspect API and proxy level) | todo |  | |
| [T-0284](docs/tasks/P14/T-0284.md) | SQL injection shield gate G14 | todo |  | |
| [T-0285](docs/tasks/P15/T-0285.md) | XSS: HTML and JavaScript-context tokenizer and vector library | todo |  | |
| [T-0286](docs/tasks/P15/T-0286.md) | XSS: encoding evasion, polyglots, mutation vectors and DOM hints | todo |  | |
| [T-0287](docs/tasks/P15/T-0287.md) | Stored-XSS controls: write-path emphasis and response-side hooks | todo |  | |
| [T-0288](docs/tasks/P15/T-0288.md) | Path traversal, LFI and RFI | todo |  | |
| [T-0289](docs/tasks/P15/T-0289.md) | Command injection: shell lexer and detectors | todo |  | |
| [T-0290](docs/tasks/P15/T-0290.md) | Code injection and server-side template injection | todo |  | |
| [T-0291](docs/tasks/P15/T-0291.md) | JNDI/Log4Shell, OGNL, SpEL and expression-language injection | todo |  | |
| [T-0292](docs/tasks/P15/T-0292.md) | XXE and XML attack detection | todo |  | |
| [T-0293](docs/tasks/P15/T-0293.md) | SSRF-in-parameters detector | todo |  | |
| [T-0294](docs/tasks/P15/T-0294.md) | CRLF, header and email-header injection | todo |  | |
| [T-0295](docs/tasks/P15/T-0295.md) | Open redirect detection and redirect allowlists | todo |  | |
| [T-0296](docs/tasks/P15/T-0296.md) | Deserialization signatures | todo |  | |
| [T-0297](docs/tasks/P15/T-0297.md) | File upload defenses | todo |  | |
| [T-0298](docs/tasks/P15/T-0298.md) | HTTP method policy and request-semantics anomalies | todo |  | |
| [T-0299](docs/tasks/P15/T-0299.md) | Host header and virtual-host confusion | todo |  | |
| [T-0300](docs/tasks/P15/T-0300.md) | Request-smuggling detection at the WAF layer | todo |  | |
| [T-0301](docs/tasks/P15/T-0301.md) | CSRF enforcement mode (Fetch Metadata and Origin) and CORS anomaly signals | todo |  | |
| [T-0302](docs/tasks/P15/T-0302.md) | API protection: positive security from OpenAPI/JSON Schema, content-type enforcement | todo |  | |
| [T-0303](docs/tasks/P15/T-0303.md) | BOLA/IDOR enumeration heuristics and mass-assignment signals | todo |  | |
| [T-0304](docs/tasks/P15/T-0304.md) | GraphQL protection policy enforcement | todo |  | |
| [T-0305](docs/tasks/P15/T-0305.md) | WebSocket protections | todo |  | |
| [T-0306](docs/tasks/P15/T-0306.md) | Scanner and attack-tool fingerprints | todo |  | |
| [T-0307](docs/tasks/P15/T-0307.md) | Directory and file enumeration (forced browsing) detector | todo |  | |
| [T-0308](docs/tasks/P15/T-0308.md) | CMS and framework probe detection | todo |  | |
| [T-0309](docs/tasks/P15/T-0309.md) | Sensitive-file honeypots, decoys and the tarpit option | todo |  | |
| [T-0310](docs/tasks/P15/T-0310.md) | Virtual patch pack v1 (known-component exploits) | todo |  | |
| [T-0311](docs/tasks/P15/T-0311.md) | Information-disclosure controls: debug endpoints and error masking | todo |  | |
| [T-0312](docs/tasks/P15/T-0312.md) | Business-logic abuse signals (rate, sequence and parameter tampering heuristics) | todo |  | |
| [T-0313](docs/tasks/P15/T-0313.md) | Attack-matrix coverage check and detector registry | todo |  | |
| [T-0314](docs/tasks/P15/T-0314.md) | Detector gate G15 | todo |  | |
| [T-0315](docs/tasks/P16/T-0315.md) | Client IP resolution and IP keys | todo |  | |
| [T-0316](docs/tasks/P16/T-0316.md) | Ban store: local enforcement copy, Redis, Postgres and resync | todo |  | |
| [T-0317](docs/tasks/P16/T-0317.md) | Ban policy engine: intent to ban, TTL ladder, scopes and attack diversity | todo |  | |
| [T-0318](docs/tasks/P16/T-0318.md) | Never-ban list and tenant allowlist semantics | todo |  | |
| [T-0319](docs/tasks/P16/T-0319.md) | IP Jail pipeline stage and branded 403 | todo |  | |
| [T-0320](docs/tasks/P16/T-0320.md) | Ban APIs, events and audit | todo |  | |
| [T-0321](docs/tasks/P16/T-0321.md) | IP jail UI (S-067) and ban detail (S-068) | todo |  | |
| [T-0322](docs/tasks/P16/T-0322.md) | Ban stream contract for the host agent and enforcement acknowledgments | todo |  | |
| [T-0323](docs/tasks/P16/T-0323.md) | Org-wide propagation and platform-wide global jail promotion | todo |  | |
| [T-0324](docs/tasks/P16/T-0324.md) | Appeals: visitor flow, workflow and owner inbox (S-145, S-146, S-069) | todo |  | |
| [T-0325](docs/tasks/P16/T-0325.md) | Ban evasion defenses: campaign detector and fingerprint-linked escalation | todo |  | |
| [T-0326](docs/tasks/P16/T-0326.md) | Shared-address (CGNAT) collateral mitigation | todo |  | |
| [T-0327](docs/tasks/P16/T-0327.md) | Self-lockout prevention across ban, access and rule changes | todo |  | |
| [T-0328](docs/tasks/P16/T-0328.md) | Ban ladder decay, caps and eviction | todo |  | |
| [T-0329](docs/tasks/P16/T-0329.md) | Ban forensics: evidence capture, event aggregation and privacy | todo |  | |
| [T-0330](docs/tasks/P16/T-0330.md) | Ban end-to-end tests with a builder-local vulnerable test origin | todo |  | |
| [T-0331](docs/tasks/P16/T-0331.md) | Ban metrics, alerts and mass-ban (poisoning) anomaly detection | todo |  | |
| [T-0332](docs/tasks/P16/T-0332.md) | Bans and jail gate G16 | todo |  | |
| [T-0333](docs/tasks/P17/T-0333.md) | Rate limiter core: Redis sliding window with local fallback | todo |  | |
| [T-0334](docs/tasks/P17/T-0334.md) | Per-path and auth-endpoint rate rules (engine side) | todo |  | |
| [T-0335](docs/tasks/P17/T-0335.md) | Rate-limit actions: 429 page, auto-ban and progressive penalties | todo |  | |
| [T-0336](docs/tasks/P17/T-0336.md) | Slow-attack mitigation at application layer | todo |  | |
| [T-0337](docs/tasks/P17/T-0337.md) | Challenge engine: proof-of-work tokens, clearance cookies and replay protection | todo |  | |
| [T-0338](docs/tasks/P17/T-0338.md) | Challenge page UX (S-141) and under-attack interstitial (S-147) | todo |  | |
| [T-0339](docs/tasks/P17/T-0339.md) | Under-attack mode (site-level) and automatic triggers | todo |  | |
| [T-0340](docs/tasks/P17/T-0340.md) | Bot scoring engine | todo |  | |
| [T-0341](docs/tasks/P17/T-0341.md) | Verified bots: forward-confirmed reverse DNS and published ranges | todo |  | |
| [T-0342](docs/tasks/P17/T-0342.md) | TLS fingerprint spike (JA3/JA4) and ADR | todo |  | |
| [T-0343](docs/tasks/P17/T-0343.md) | Credential-stuffing and brute-force detector | todo |  | |
| [T-0344](docs/tasks/P17/T-0344.md) | Account-enumeration and user-differential signals | todo |  | |
| [T-0345](docs/tasks/P17/T-0345.md) | Form abuse defenses: signup, contact, comment, checkout | todo |  | |
| [T-0346](docs/tasks/P17/T-0346.md) | IP reputation: local scores, Tor/VPN/datacenter lists and feed ingestion | todo |  | |
| [T-0347](docs/tasks/P17/T-0347.md) | GeoIP and ASN enrichment | todo |  | |
| [T-0348](docs/tasks/P17/T-0348.md) | Threat-intel feed engine (platform-managed) | todo |  | |
| [T-0349](docs/tasks/P17/T-0349.md) | Adaptive thresholds and baselines | todo |  | |
| [T-0350](docs/tasks/P17/T-0350.md) | Anti-scraping and crawl abuse controls | todo |  | |
| [T-0351](docs/tasks/P17/T-0351.md) | Behavioral defense end-to-end tests (AC-11, AC-44, stuffing lab, AC-48 subset) | todo |  | |
| [T-0352](docs/tasks/P17/T-0352.md) | Behavioral defenses gate G17 | todo |  | |
| [T-0353](docs/tasks/P18/T-0353.md) | Listener and accept loop; proxy-core decision (Pingora versus own) | todo |  | |
| [T-0354](docs/tasks/P18/T-0354.md) | TLS termination: crypto provider ADR, SNI resolver, policy and refusal behavior | todo |  | |
| [T-0355](docs/tasks/P18/T-0355.md) | Host router and the multi-tenant snapshot model | todo |  | |
| [T-0356](docs/tasks/P18/T-0356.md) | HTTP/1.1 server hardening | todo |  | |
| [T-0357](docs/tasks/P18/T-0357.md) | HTTP/2 server hardening | todo |  | |
| [T-0358](docs/tasks/P18/T-0358.md) | h2-to-h1 downgrade safety and header normalization | todo |  | |
| [T-0359](docs/tasks/P18/T-0359.md) | Pipeline framework: stages, budgets, short-circuit and test harness | todo |  | |
| [T-0360](docs/tasks/P18/T-0360.md) | Request body handling: caps, decompression, chunked reassembly and 100-continue | todo |  | |
| [T-0361](docs/tasks/P18/T-0361.md) | Upstream header policy, Ray ID and secret origin header | todo |  | |
| [T-0362](docs/tasks/P18/T-0362.md) | Pipeline integration: stages 6 to 15 ordering, failure modes and end-to-end behavior tests | todo |  | |
| [T-0363](docs/tasks/P18/T-0363.md) | Streaming, backpressure, graceful drain and overload behavior | todo |  | |
| [T-0364](docs/tasks/P18/T-0364.md) | Resilience: Redis and Postgres failure behavior, restarts and recovery | todo |  | |
| [T-0365](docs/tasks/P18/T-0365.md) | Origin client: pooling, TLS verification, SSRF connect guard, redirects and loop detection | todo |  | |
| [T-0366](docs/tasks/P18/T-0366.md) | Visitor pages: data-plane templates, CSP, shared renderer and JSON variants | todo |  | |
| [T-0367](docs/tasks/P18/T-0367.md) | WebSocket and gRPC passthrough | todo |  | |
| [T-0368](docs/tasks/P18/T-0368.md) | Event pipeline: bounded channels, batch inserts, aggregation and sampling | todo |  | |
| [T-0369](docs/tasks/P18/T-0369.md) | Origin health checks, passive detection and serve-stale | todo |  | |
| [T-0370](docs/tasks/P18/T-0370.md) | Safe mode: file flag, API and `hddctl` | todo |  | |
| [T-0371](docs/tasks/P18/T-0371.md) | Automatic rollback engine for rule and policy changes | todo |  | |
| [T-0372](docs/tasks/P18/T-0372.md) | Proxy metrics, tracing, performance budgets and Ray ID tests | todo |  | |
| [T-0373](docs/tasks/P18/T-0373.md) | Raw-socket protocol test suite (AC-14) and oracle checks | todo |  | |
| [T-0374](docs/tasks/P18/T-0374.md) | Proxy data-plane gate G18 | todo |  | |
| [T-0375](docs/tasks/P19/T-0375.md) | Certificate store, SNI resolver cache and hot reload | todo |  | |
| [T-0376](docs/tasks/P19/T-0376.md) | ACME client wrapper (`instant-acme`): accounts, orders, HTTP-01, DNS-01 and ARI | todo |  | |
| [T-0377](docs/tasks/P19/T-0377.md) | Issuance and renewal scheduler with jitter and alerts | todo |  | |
| [T-0378](docs/tasks/P19/T-0378.md) | Multi-tenant domain validation guards for issuance | todo |  | |
| [T-0379](docs/tasks/P19/T-0379.md) | Certificate Transparency monitoring wiring and issuance verification | todo |  | |
| [T-0380](docs/tasks/P19/T-0380.md) | Default certificate policy and `unrecognized_name` behavior | todo |  | |
| [T-0381](docs/tasks/P19/T-0381.md) | TLS policy verification: protocol, ciphers, HSTS and redirect behavior | todo |  | |
| [T-0382](docs/tasks/P19/T-0382.md) | OCSP stapling decision and certificate status practices | todo |  | |
| [T-0383](docs/tasks/P19/T-0383.md) | Origin mutual TLS (client certificates) option | todo |  | |
| [T-0384](docs/tasks/P19/T-0384.md) | Internal PKI and mTLS between platform services (`hddctl pki`) | todo |  | |
| [T-0385](docs/tasks/P19/T-0385.md) | TLS end-to-end acceptance (AC-04) including DNS-01 wildcard and production rehearsal | todo |  | |
| [T-0386](docs/tasks/P19/T-0386.md) | Certificate store and ACME gate G19 | todo |  | |
| [T-0387](docs/tasks/P20/T-0387.md) | ADR: DNS server core (hickory-server customization versus own packet loop) and workspace wiring | todo |  | |
| [T-0388](docs/tasks/P20/T-0388.md) | Snapshot ingestion, atomic swap and the DNS data-plane role | todo |  | |
| [T-0389](docs/tasks/P20/T-0389.md) | Protocol-correct answering: rcodes, wildcards, ANY, delegation, CNAME and DNAME-free semantics | todo |  | |
| [T-0390](docs/tasks/P20/T-0390.md) | Proxied (orange-cloud) answers, edge/ACME/preview synthetic names and origin non-disclosure | todo |  | |
| [T-0391](docs/tasks/P20/T-0391.md) | CNAME flattening resolver (bounded, cached, loop-safe, never recursive for clients) | todo |  | |
| [T-0392](docs/tasks/P20/T-0392.md) | Transport hardening: UDP/TCP listeners, EDNS0, truncation and connection limits | todo |  | |
| [T-0393](docs/tasks/P20/T-0393.md) | Abuse controls: response-rate limiting, DNS cookies, per-source caps and random-subdomain detection | todo |  | |
| [T-0394](docs/tasks/P20/T-0394.md) | TSIG zone transfers (AXFR/IXFR) and NOTIFY for external secondaries | todo |  | |
| [T-0395](docs/tasks/P20/T-0395.md) | Topologies, automatic NS/SOA, serial policy and glue | todo |  | |
| [T-0396](docs/tasks/P20/T-0396.md) | ACME DNS-01 serving, CNAME-delegated challenges and secondary-aware waiting | todo |  | |
| [T-0397](docs/tasks/P20/T-0397.md) | Parser hardening and fuzzing for the DNS wire path | todo |  | |
| [T-0398](docs/tasks/P20/T-0398.md) | Amplification and reflection measurement (closed lab) | todo |  | |
| [T-0399](docs/tasks/P20/T-0399.md) | Tenant isolation, zone lifecycle in the data plane and takeover prevention | todo |  | |
| [T-0400](docs/tasks/P20/T-0400.md) | DNS observability, performance and capacity benchmarks | todo |  | |
| [T-0401](docs/tasks/P20/T-0401.md) | Independent conformance suite: hickory-client tests and external oracles | todo |  | |
| [T-0402](docs/tasks/P20/T-0402.md) | DNS live acceptance: AC-03 (full), AC-21 and AC-28 on the pilot and the closed lab | todo |  | |
| [T-0403](docs/tasks/P20/T-0403.md) | DNSSEC readiness and automated DS check (cutover safety) | todo |  | |
| [T-0404](docs/tasks/P20/T-0404.md) | Authoritative DNS gate G20 | todo |  | |
| [T-0405](docs/tasks/P21/T-0405.md) | Origin lockdown model: states, secret header enforcement, mTLS selection and allowlist publication | todo |  | |
| [T-0406](docs/tasks/P21/T-0406.md) | Origin lockdown wizard (S-098): stack snippets, verification probes and safe relaxation | todo |  | |
| [T-0407](docs/tasks/P21/T-0407.md) | Continuous origin-exposure monitoring and re-IP guidance | todo |  | |
| [T-0408](docs/tasks/P21/T-0408.md) | Outbound leak detection engine (pure library) and signature catalog | todo |  | |
| [T-0409](docs/tasks/P21/T-0409.md) | Outbound filter in the proxy: modes, buffering window, actions and S-097 | todo |  | |
| [T-0410](docs/tasks/P21/T-0410.md) | Response header policy engine (security headers, disclosure removal, per-site overrides) | todo |  | |
| [T-0411](docs/tasks/P21/T-0411.md) | Cookie and session protection (flag upgrades, scope hardening, fixation signals) | todo |  | |
| [T-0412](docs/tasks/P21/T-0412.md) | Client-side supply-chain visibility: CSP report collector, SRI advisor and third-party script inventory | todo |  | |
| [T-0413](docs/tasks/P21/T-0413.md) | Tenant egress safety in the data plane: SSRF guard, DNS pinning and rebinding verification | todo |  | |
| [T-0414](docs/tasks/P21/T-0414.md) | Bulk-exfiltration and scraping-of-data guard (response volume and record-count anomalies) | todo |  | |
| [T-0415](docs/tasks/P21/T-0415.md) | Origin protection end-to-end tests (AC-10, AC-18, AC-05 headers, AC-17 connect-time) on the pilot and lab | todo |  | |
| [T-0416](docs/tasks/P21/T-0416.md) | Origin protection and outbound gate G21 | todo |  | |
| [T-0417](docs/tasks/P22/T-0417.md) | Admin surface foundation: isolation, session scope, layout shell and navigation | todo |  | |
| [T-0418](docs/tasks/P22/T-0418.md) | Admin overview (S-100): real platform health and attention list | todo |  | |
| [T-0419](docs/tasks/P22/T-0419.md) | Tenants list and tenant detail (S-101, S-102) | todo |  | |
| [T-0420](docs/tasks/P22/T-0420.md) | Users list and user detail (S-103, S-104) | todo |  | |
| [T-0421](docs/tasks/P22/T-0421.md) | Global domains view and domain actions (S-105) | todo |  | |
| [T-0422](docs/tasks/P22/T-0422.md) | Impersonation (S-118): read-only view-as with time box and banner | todo |  | |
| [T-0423](docs/tasks/P22/T-0423.md) | Tenant lifecycle: suspend, delete with grace, data export hold and purge | todo |  | |
| [T-0424](docs/tasks/P22/T-0424.md) | Global jail (S-106) and never-ban list (S-109) management | todo |  | |
| [T-0425](docs/tasks/P22/T-0425.md) | Global rule packs and rollout (S-107) | todo |  | |
| [T-0426](docs/tasks/P22/T-0426.md) | Threat-intel feeds management (S-108) | todo |  | |
| [T-0427](docs/tasks/P22/T-0427.md) | Infrastructure screens: nodes, services, queues, certificates and zones (S-110 to S-113) | todo |  | |
| [T-0428](docs/tasks/P22/T-0428.md) | Abuse reports (S-114) and signup policy (S-115) | todo |  | |
| [T-0429](docs/tasks/P22/T-0429.md) | Plans and quotas editor (S-116) | todo |  | |
| [T-0430](docs/tasks/P22/T-0430.md) | Platform audit (S-117): filters, chain verification and export | todo |  | |
| [T-0431](docs/tasks/P22/T-0431.md) | System settings (S-119): SMTP, branding, legal links, retention defaults and secrets handling | todo |  | |
| [T-0432](docs/tasks/P22/T-0432.md) | Email template management (S-120) with preview in both themes and locales | todo |  | |
| [T-0433](docs/tasks/P22/T-0433.md) | Announcements (S-129), feature flags and maintenance mode (S-121) | todo |  | |
| [T-0434](docs/tasks/P22/T-0434.md) | Platform emergency controls (S-122): safe mode, signup freeze, global challenge | todo |  | |
| [T-0435](docs/tasks/P22/T-0435.md) | Releases and updates (S-123) and backups and restore drills (S-124) | todo |  | |
| [T-0436](docs/tasks/P22/T-0436.md) | Exposure board (S-125) and virtual patches (S-126) admin screens | todo |  | |
| [T-0437](docs/tasks/P22/T-0437.md) | Shield (S-127) and firewall/XDP (S-128) admin screens | todo |  | |
| [T-0438](docs/tasks/P22/T-0438.md) | Support lookup (S-130): Ray ID, IP, domain and user timelines with privacy limits | todo |  | |
| [T-0439](docs/tasks/P22/T-0439.md) | Admin panel security and end-to-end test suite (AC-01 admin isolation, AC-42 operations) | todo |  | |
| [T-0440](docs/tasks/P22/T-0440.md) | Platform admin panel gate G22 | todo |  | |
| [T-0441](docs/tasks/P23/T-0441.md) | Event storage, partition retention and the rollup pipeline v1 | todo |  | |
| [T-0442](docs/tasks/P23/T-0442.md) | Analytics API and the analytics overview (S-070) | todo |  | |
| [T-0443](docs/tasks/P23/T-0443.md) | Geo and ASN analytics (S-071) | todo |  | |
| [T-0444](docs/tasks/P23/T-0444.md) | Top attackers, paths, rules and categories (S-072) with pivots | todo |  | |
| [T-0445](docs/tasks/P23/T-0445.md) | Event explorer and event detail (S-066) | todo |  | |
| [T-0446](docs/tasks/P23/T-0446.md) | Live threat monitor (S-065): SSE event source, backpressure and accessible live regions | todo |  | |
| [T-0447](docs/tasks/P23/T-0447.md) | Report data model, section library and generated runs (S-073) | todo |  | |
| [T-0448](docs/tasks/P23/T-0448.md) | PDF pipeline decision, report builder and scheduling (S-074) | todo |  | |
| [T-0449](docs/tasks/P23/T-0449.md) | Weekly digest and executive summary generation (deterministic, honest language) | todo |  | |
| [T-0450](docs/tasks/P23/T-0450.md) | Data export and portability (events, analytics, configuration) | todo |  | |
| [T-0451](docs/tasks/P23/T-0451.md) | Analytics correctness, scale and accessibility test suite (AC-52) | todo |  | |
| [T-0452](docs/tasks/P23/T-0452.md) | Analytics and reports gate G23 | todo |  | |
| [T-0453](docs/tasks/P24/T-0453.md) | Alert rules (S-076) and notification routing core | todo |  | |
| [T-0454](docs/tasks/P24/T-0454.md) | Integration channels (S-077): email, Slack, Discord, Telegram, Microsoft Teams, PagerDuty | todo |  | |
| [T-0455](docs/tasks/P24/T-0455.md) | Webhook delivery engine: outbox, retries, circuit breaker and idempotency | todo |  | |
| [T-0456](docs/tasks/P24/T-0456.md) | Webhook endpoints, signing secrets and delivery inspector (S-078, S-079) | todo |  | |
| [T-0457](docs/tasks/P24/T-0457.md) | Public API v1: completeness, governance, contract tests and breaking-change detection | todo |  | |
| [T-0458](docs/tasks/P24/T-0458.md) | `hdd-sdk`: Rust client and generated clients | todo |  | |
| [T-0459](docs/tasks/P24/T-0459.md) | Developer documentation: API reference, guides, examples and sandbox "Try it" | todo |  | |
| [T-0460](docs/tasks/P24/T-0460.md) | Log forwarding and SIEM export (HTTPS JSON lines and syslog over TLS) | todo |  | |
| [T-0461](docs/tasks/P24/T-0461.md) | Notifications, webhooks and API end-to-end tests (AC-45, AC-20 alert paths) | todo |  | |
| [T-0462](docs/tasks/P24/T-0462.md) | Notifications, integrations, API and SDK gate G24 | todo |  | |
| [T-0463](docs/tasks/P25/T-0463.md) | `hdd-firewall`: Enforcer trait and nftables, ipset/iptables and no-op backends | todo |  | |
| [T-0464](docs/tasks/P25/T-0464.md) | `hdd-fw-agent`: signed ban stream consumer, reconcile loop, control socket and acknowledgments | todo |  | |
| [T-0465](docs/tasks/P25/T-0465.md) | `hdd-xdp-logic`: pure packet-verdict logic (no_std) with exhaustive tests | todo |  | |
| [T-0466](docs/tasks/P25/T-0466.md) | `hdd-xdp-ebpf`: the kernel program, `aya` and nightly toolchain ADR, and the single `unsafe` crate | todo |  | |
| [T-0467](docs/tasks/P25/T-0467.md) | `hdd-xdp` loader: maps, atomic updates, counters, native/generic probe and the dead-man timer | todo |  | |
| [T-0468](docs/tasks/P25/T-0468.md) | Full L2 tuning and the nftables baseline: NOTRACK, conntrack sizing, ICMP limits and exact undo | todo |  | |
| [T-0469](docs/tasks/P25/T-0469.md) | Host hardening baseline and verification (SSH, services, systemd sandboxing, integrity, updates) | todo |  | |
| [T-0470](docs/tasks/P25/T-0470.md) | Closed-lab flood harness (`hdd-loadgen` lab mode, namespaces, xtask lab) | todo |  | |
| [T-0471](docs/tasks/P25/T-0471.md) | Host defense acceptance: AC-26 (XDP), AC-29 (tuning), kernel ban enforcement and port-scan signals | todo |  | |
| [T-0472](docs/tasks/P25/T-0472.md) | Host defenses gate G25 | todo |  | |
| [T-0473](docs/tasks/P26/T-0473.md) | `hdd-shield` telemetry: collectors, signals and the recorded-trace input mode | todo |  | |
| [T-0474](docs/tasks/P26/T-0474.md) | Shield state machine: hysteresis, dwell times, de-escalation and manual control | todo |  | |
| [T-0475](docs/tasks/P26/T-0475.md) | Escalation actions: tighten, challenge, shed, DNS attack mode, and `skipped(feature_absent)` semantics | todo |  | |
| [T-0476](docs/tasks/P26/T-0476.md) | Upstream mitigation profile, provider activation runbook and the three capacity numbers | todo |  | |
| [T-0477](docs/tasks/P26/T-0477.md) | External heartbeat, incident bundle and timeline | todo |  | |
| [T-0478](docs/tasks/P26/T-0478.md) | Edge failover (L6, Tier 1): standby edge swap of proxied answers, TTL-aware, with rehearsal | todo |  | |
| [T-0479](docs/tasks/P26/T-0479.md) | Shield and survivability acceptance: AC-25, AC-27 and end-to-end escalation drills | todo |  | |
| [T-0480](docs/tasks/P26/T-0480.md) | Shield, escalation and survivability gate G26 | todo |  | |
| [T-0481](docs/tasks/P27/T-0481.md) | `hdd-vuln` feed ingestion: OSV, NVD, CISA KEV, EPSS, RustSec and operator-named advisories | todo |  | |
| [T-0482](docs/tasks/P27/T-0482.md) | Component inventory: model, importers (SBOM, lockfiles, package lists) and ownership | todo |  | |
| [T-0483](docs/tasks/P27/T-0483.md) | Matching engine: purl-based matching, version ranges, CPE low confidence and VEX | todo |  | |
| [T-0484](docs/tasks/P27/T-0484.md) | Exposure board backend, SLA clocks, alerts and the R-11 invariant | todo |  | |
| [T-0485](docs/tasks/P27/T-0485.md) | Virtual-patch lifecycle engine, evidence harness and signed packs (V10) | todo |  | |
| [T-0486](docs/tasks/P27/T-0486.md) | Passive origin fingerprinting and client-side library detection | todo |  | |
| [T-0487](docs/tasks/P27/T-0487.md) | `hdd-scan`: read-only posture scanner with allowlist, consent and rate limits | todo |  | |
| [T-0488](docs/tasks/P27/T-0488.md) | Origin-hardening report generator and remediation library | todo |  | |
| [T-0489](docs/tasks/P27/T-0489.md) | Vulnerability management acceptance: AC-30, AC-31, AC-32 | todo |  | |
| [T-0490](docs/tasks/P27/T-0490.md) | Vulnerability management gate G27 | todo |  | |
| [T-0491](docs/tasks/P28/T-0491.md) | Acceptance runner v1: full catalog, modes, profiles, evidence store and report | todo |  | |
| [T-0492](docs/tasks/P28/T-0492.md) | Safety-envelope self-tests (AC-00): prove the guard rails before using them | todo |  | |
| [T-0493](docs/tasks/P28/T-0493.md) | Vuln-Lab foundation: crate, self-guard, canary databases and release exclusion | todo |  | |
| [T-0494](docs/tasks/P28/T-0494.md) | Vuln-Lab application set A: SQL injection family with direct-exploit proofs | todo |  | |
| [T-0495](docs/tasks/P28/T-0495.md) | Vuln-Lab application set B: other vulnerability classes with direct-exploit proofs | todo |  | |
| [T-0496](docs/tasks/P28/T-0496.md) | Lab topology and oracle harness: HDD in front of the Vuln-Lab with pinned external oracles | todo |  | |
| [T-0497](docs/tasks/P28/T-0497.md) | AC-38: vulnerable-origin proof (direct exploit works, through HDD it fails and the IP is banned) | todo |  | |
| [T-0498](docs/tasks/P28/T-0498.md) | AC-15: resilience and failure-mode scenarios (announced, pilot stage) | todo |  | |
| [T-0499](docs/tasks/P28/T-0499.md) | AC-39: SQL injection matrix, evasion catalog, held-out set and the sqlmap campaign | todo |  | |
| [T-0500](docs/tasks/P28/T-0500.md) | AC-34, AC-08 and AC-51: ban poisoning resistance, persistence, global jail and never-ban | todo |  | |
| [T-0501](docs/tasks/P28/T-0501.md) | AC-11, AC-44 and AC-48: rate limiting, challenge and bots, scanner detection (with lab oracles) | todo |  | |
| [T-0502](docs/tasks/P28/T-0502.md) | AC-40 and AC-41: WCAG 2.2 AA conformance and public-page quality gates | todo |  | |
| [T-0503](docs/tasks/P28/T-0503.md) | Identity, tenant isolation, admin, appeals and audit acceptance: AC-01, AC-19, AC-35, AC-36, AC-42, AC-43, AC-47 | todo |  | |
| [T-0504](docs/tasks/P28/T-0504.md) | AC-37 and AC-46: onboarding live for all feasible modes, and email security | todo |  | |
| [T-0505](docs/tasks/P28/T-0505.md) | AC-12, AC-13 and AC-16: rule dry-run, modes, safe mode, auto-rollback and convergence | todo |  | |
| [T-0506](docs/tasks/P28/T-0506.md) | AC-05, AC-20, AC-22 regression and observability acceptance | todo |  | |
| [T-0507](docs/tasks/P28/T-0507.md) | AC-02 and AC-23: import parity at scale and cutover rehearsal checks | todo |  | |
| [T-0508](docs/tasks/P28/T-0508.md) | AC-06, AC-07, AC-09, AC-49 and AC-50: false-positive baseline, attack-matrix coverage and API/GraphQL/WebSocket protection | todo |  | |
| [T-0509](docs/tasks/P28/T-0509.md) | Regression orchestration: non-destructive subset, destructive subset, flake control and CI integration | todo |  | |
| [T-0510](docs/tasks/P28/T-0510.md) | Acceptance suite and Vuln-Lab gate G28 with acceptance report v1 | todo |  | |
| [T-0511](docs/tasks/P29/T-0511.md) | Performance measurement suite and budgets (AC-24) | todo |  | |
| [T-0512](docs/tasks/P29/T-0512.md) | Soak, capacity model and resource-leak detection | todo |  | |
| [T-0513](docs/tasks/P29/T-0513.md) | Automated chaos suite (network faults, resource faults, time faults) | todo |  | |
| [T-0514](docs/tasks/P29/T-0514.md) | Fuzzing program: target inventory, corpora, nightly campaigns and crash triage | todo |  | |
| [T-0515](docs/tasks/P29/T-0515.md) | Mutation testing, coverage thresholds and test-quality gates | todo |  | |
| [T-0516](docs/tasks/P29/T-0516.md) | Supply-chain controls: dependencies, SBOM, reproducible builds and provenance (AC-33, part 1) | todo |  | |
| [T-0517](docs/tasks/P29/T-0517.md) | Unsafe-code policy, `cargo-geiger` viability ADR and static analysis suite | todo |  | |
| [T-0518](docs/tasks/P29/T-0518.md) | Release signing, artifact pipeline and signed self-update with rollback (AC-33, part 2) | todo |  | |
| [T-0519](docs/tasks/P29/T-0519.md) | HDD self-security review program: STRIDE delta, lab pentest with oracles and disclosure readiness | todo |  | |
| [T-0520](docs/tasks/P29/T-0520.md) | Performance, chaos, fuzz and supply-chain gate G29 | todo |  | |
| [T-0521](docs/tasks/P30/T-0521.md) | Deployment path ADR and the production artifact set (systemd units, container images, installer) | todo |  | |
| [T-0522](docs/tasks/P30/T-0522.md) | `hddctl deploy` v1: full production deployment, idempotent, with dry-run, health checks and rollback | todo |  | |
| [T-0523](docs/tasks/P30/T-0523.md) | Backup, encryption and restore-drill automation (AC-54, part 1) | todo |  | |
| [T-0524](docs/tasks/P30/T-0524.md) | Upgrade and migration discipline: expand/contract, version skew, canary upgrade and rollback tests (AC-54, part 2) | todo |  | |
| [T-0525](docs/tasks/P30/T-0525.md) | Monitoring, alerting and dashboards: provisioning and runbook mapping | todo |  | |
| [T-0526](docs/tasks/P30/T-0526.md) | Key management and rotation: `hddctl rotate-keys` without downtime | todo |  | |
| [T-0527](docs/tasks/P30/T-0527.md) | Operations runbooks, incident response and change management | todo |  | |
| [T-0528](docs/tasks/P30/T-0528.md) | Environment management: dev, lab, pilot and production configuration, drift detection and promotion | todo |  | |
| [T-0529](docs/tasks/P30/T-0529.md) | Disaster-recovery drill: total VPS loss to rebuilt service (AC-54, part 3) | todo |  | |
| [T-0530](docs/tasks/P30/T-0530.md) | Deployment, backup, upgrade and operations gate G30 | todo |  | |
| [T-0531](docs/tasks/P31/T-0531.md) | Documentation completion: user, operator, API, architecture and security docs with freshness tests | todo |  | |
| [T-0532](docs/tasks/P31/T-0532.md) | Legal and compliance pack (templates, data map, retention schedule, subprocessors) | todo |  | |
| [T-0533](docs/tasks/P31/T-0533.md) | Pre-launch hardening review and external-style testing close-out | todo |  | |
| [T-0534](docs/tasks/P31/T-0534.md) | Launch readiness review and claims audit across all surfaces | todo |  | |
| [T-0535](docs/tasks/P31/T-0535.md) | Cutover pack finalization and rehearsal (RUNBOOK-CUTOVER) | todo |  | |
| [T-0536](docs/tasks/P31/T-0536.md) | STOP #2: operator package, confirmations and verification of human steps | todo |  | |
| [T-0537](docs/tasks/P31/T-0537.md) | Supervised cutover execution and the monitor-first period (only after written go-ahead) | todo |  | |
| [T-0538](docs/tasks/P31/T-0538.md) | Production ACME issuance (one event, operator-approved) and certificate verification | todo |  | |
| [T-0539](docs/tasks/P31/T-0539.md) | Post-cutover stabilization: from monitor to block, tuning and sign-off | todo |  | |
| [T-0540](docs/tasks/P31/T-0540.md) | Final report, handoff and Phase P31 gate G31 | todo |  | |
| [T-0541](docs/tasks/P32/T-0541.md) | Tier 2: DNS provider import adapters (read-only) for common providers | todo |  | |
| [T-0542](docs/tasks/P32/T-0542.md) | Tier 2: origin pools, load balancing and active health-based failover between origins | todo |  | |
| [T-0543](docs/tasks/P32/T-0543.md) | Tier 2: tenant-pinned rule-pack versions and staged tenant rollouts | todo |  | |
| [T-0544](docs/tasks/P32/T-0544.md) | Tier 2: opt-in static content cache with purge API | todo |  | |
| [T-0545](docs/tasks/P32/T-0545.md) | Tier 2: antivirus scanning integration for uploads (clamd) | todo |  | |
| [T-0546](docs/tasks/P32/T-0546.md) | Tier 2: alternate ACME CAs and external account binding (EAB) | todo |  | |
| [T-0547](docs/tasks/P32/T-0547.md) | Tier 5: WebAssembly plugin runtime (`wasmtime`) for custom detectors and transformations | todo |  | |
| [T-0548](docs/tasks/P32/T-0548.md) | Tier 3: online DNSSEC signing (ECDSA P-256) with DS workflow and validation oracles | todo |  | |
| [T-0549](docs/tasks/P32/T-0549.md) | Tier 3: HTTP/3 (QUIC) support with `quinn`/`h3` — ADR and implementation | todo |  | |
| [T-0550](docs/tasks/P32/T-0550.md) | Tier 3: HTTP/2 SETTINGS and advanced TLS fingerprinting (JA4 family) for bot scoring | todo |  | |
| [T-0551](docs/tasks/P32/T-0551.md) | Tier 6: ClickHouse (or alternative) analytics backend ADR and optional implementation | todo |  | |
| [T-0552](docs/tasks/P32/T-0552.md) | Tier 4: OpenTelemetry tracing and metrics export | todo |  | |
| [T-0553](docs/tasks/P32/T-0553.md) | Tier 4: health-probed automatic edge failover (DNS-level, multi-edge) | todo |  | |
| [T-0554](docs/tasks/P32/T-0554.md) | Tier 4: multi-node data plane and highly available control plane | todo |  | |
| [T-0555](docs/tasks/P32/T-0555.md) | Tier 4: BGP/RTBH and anycast integration guidance and tooling for ASN operators | todo |  | |
| [T-0556](docs/tasks/P32/T-0556.md) | Tier 6: organization SSO (OIDC and SAML) and SCIM provisioning | todo |  | |
| [T-0557](docs/tasks/P32/T-0557.md) | Tier 6: infrastructure-as-code provider (Terraform/OpenTofu) generated from the API | todo |  | |
| [T-0558](docs/tasks/P32/T-0558.md) | Tier 6: billing and subscription integration (optional) | todo |  | |
| [T-0559](docs/tasks/P32/T-0559.md) | Tier 6: explainable ML-assisted anomaly scoring (offline-trained, bounded influence) | todo |  | |
| [T-0560](docs/tasks/P32/T-0560.md) | Backlog governance: tier index, prioritization process and re-planning for later revisions | todo |  | |
| [T-0561](docs/tasks/P33/T-0561.md) | Runtime profile model, capability matrix and the parity contract | done | docs/evidence/P33/T-0561-*.txt; ADR-0027; docs/LOCAL.md, docs/HOSTING.md | |
| [T-0562](docs/tasks/P33/T-0562.md) | `KvStore`, `Bus` and `Limiter` traits with Redis and in-process backends, and the conformance suite | done | docs/evidence/P33/T-0562-*.txt; ADR-0028; kv module tests | |
| [T-0563](docs/tasks/P33/T-0563.md) | Embedded PostgreSQL manager and `cargo xtask db up` | done | docs/evidence/P33/T-0563-*.txt; ADR-0029; real run on Windows x64 | |
| [T-0564](docs/tasks/P33/T-0564.md) | `hdd-local` supervisor: lifecycle, readiness, crash policy, first run, doctor and self-test | todo |  | |
| [T-0565](docs/tasks/P33/T-0565.md) | Loopback client identity, local ban semantics and the tunnel listener | todo |  | |
| [T-0566](docs/tasks/P33/T-0566.md) | Local certificate authority, trust installation and TLS modes | todo |  | |
| [T-0567](docs/tasks/P33/T-0567.md) | Local control-plane hardening: rebinding, CSRF, Private Network Access, bootstrap and loopback-only proof | todo |  | |
| [T-0568](docs/tasks/P33/T-0568.md) | Local sites, names and the hosts helper; `local_only` onboarding and embedded DNS | todo |  | |
| [T-0569](docs/tasks/P33/T-0569.md) | Packaging, installers, autostart and the cross-platform CI matrix | todo |  | |
| [T-0570](docs/tasks/P33/T-0570.md) | Local-mode product surfaces: first-run setup, runtime page (S-135), mode banner, outbox viewer and docs | todo |  | |
| [T-0571](docs/tasks/P33/T-0571.md) | Hosting profiles H1 to H5 and `hddctl hosting check` | todo |  | |
| [T-0572](docs/tasks/P33/T-0572.md) | 24/7 supervision: systemd watchdog, restart policy, last-known-good snapshot autonomy, disk guard | todo |  | |
| [T-0573](docs/tasks/P33/T-0573.md) | One-command server bootstrap: `deploy/cloud-init.yaml`, hardened base, firewall with SSH-lockout protection, unattended updates | todo |  | |
| [T-0574](docs/tasks/P33/T-0574.md) | 24/7 operations: off-site backups, restore automation, upgrade windows, uptime measurement and runbooks | todo |  | |
| [T-0575](docs/tasks/P33/T-0575.md) | Access gate (S-131): protect sensitive paths before they reach the origin | todo |  | |
| [T-0576](docs/tasks/P33/T-0576.md) | API discovery, inventory and enforcement preview (S-132) | todo |  | |
| [T-0577](docs/tasks/P33/T-0577.md) | Business-flow protection (S-133) | todo |  | |
| [T-0578](docs/tasks/P33/T-0578.md) | Coverage map, completeness audit and the acceptance of AC-55 to AC-58 (S-134) | todo |  | |
| [T-0579](docs/tasks/P34/T-0579.md) | Sentinel doctrine, threat model and runtime decision (ADR) | todo |  | |
| [T-0580](docs/tasks/P34/T-0580.md) | Structural features and the privacy-safe feature extractor | todo |  | |
| [T-0581](docs/tasks/P34/T-0581.md) | `hdd-sentinel` runtime: bounded inference, model registry, hot swap and fail-safe behavior | todo |  | |
| [T-0582](docs/tasks/P34/T-0582.md) | Per-site baselines and poisoning-resistant learning | todo |  | |
| [T-0583](docs/tasks/P34/T-0583.md) | Global attack-shape classifier and the reproducible training pipeline | todo |  | |
| [T-0584](docs/tasks/P34/T-0584.md) | Score integration, influence caps, corroboration and explainable findings | todo |  | |
| [T-0585](docs/tasks/P34/T-0585.md) | Adversarial robustness suite for learned components (AC-59) | todo |  | |
| [T-0586](docs/tasks/P34/T-0586.md) | Sentinel analyst (optional language model): triage, explanations and rule drafts for humans | todo |  | |
| [T-0587](docs/tasks/P34/T-0587.md) | Sentinel screen (S-137), API and operations | todo |  | |
| [T-0588](docs/tasks/P34/T-0588.md) | Signed origin authentication and generated origin verifiers | todo |  | |
| [T-0589](docs/tasks/P34/T-0589.md) | `hdd-tunnel`: outbound-only connector so the origin has no inbound exposure | todo |  | |
| [T-0590](docs/tasks/P34/T-0590.md) | Origin firewall and cloud allowlist generators | todo |  | |
| [T-0591](docs/tasks/P34/T-0591.md) | Continuous bypass verification, origin tripwire and the Bypass Guard screen (S-138) | todo |  | |
| [T-0592](docs/tasks/P34/T-0592.md) | Go-live gate, coverage invariants and the protected-state contract | todo |  | |
| [T-0593](docs/tasks/P34/T-0593.md) | Stack-aware normalization profiles | todo |  | |
| [T-0594](docs/tasks/P34/T-0594.md) | Known-Vulnerability Knowledge Base (VKB) and its screen (S-139) | todo |  | |
| [T-0595](docs/tasks/P34/T-0595.md) | Exploit-signature ingestion, staged rollout and the emergency channel | todo |  | |
| [T-0596](docs/tasks/P34/T-0596.md) | Attack-matrix expansion: ATK-301 to ATK-390 fixtures, detectors and tests | todo |  | |
| [T-0597](docs/tasks/P34/T-0597.md) | Parser-differential rejection and inspection-evasion defenses | todo |  | |
| [T-0598](docs/tasks/P34/T-0598.md) | Deception, cache guard, origin integrity, script integrity and AI-endpoint protections | todo |  | |
| [T-0599](docs/tasks/P34/T-0599.md) | Acceptance AC-59 to AC-62, coverage-map update and gate G34 | todo |  | |
