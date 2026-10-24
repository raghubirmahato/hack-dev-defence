# Open questions for the operator (Appendix E8, verbatim)

Each question has a default used **only for development and pilot** when unanswered; none enables production behavior. Record answers verbatim and dated in `docs/OPERATOR-CONFIRMATIONS.md` and mirror them into `hdd.live.yaml` where applicable.

| Id | Group | Question | Why it matters | Default if unanswered (dev/pilot only) | Blocks | Stored in | Tasks |
| --- | --- | --- | --- | --- | --- | --- | --- |
| Q-001 | Deployment | Do you want HDD for your own domains only (`owner_only`) or as a service for other people (`saas`)? | Changes signup, billing, tenant safety, legal and abuse requirements | `owner_only` | public signup, billing, tenant-safety guards (saas) | `deployment_mode` | T-0001, T-0422, T-0532 |
| Q-002 | Deployment | Which hosting provider, plan, region and uplink speed does the VPS have? | Capacity statements, DDoS options, AUP | unknown (capacity UNVERIFIED) | shield capacity figures | `platform.uplink_mbps`, `upstream_ddos` | T-0476 |
| Q-003 | Deployment | Is a second VPS or a second provider available for a standby edge and a secondary DNS? | DNS survivability and failover | none | cutover gate (secondary DNS), AC-21, AC-28, AC-27 | `secondary_dns`, `standby_edge_ips` | T-0394, T-0478 |
| Q-004 | Deployment | Is there a closed lab machine (or two machines on a private link) for volumetric tests and the Vuln-Lab? | Layer 3/4 and exploit-proof evidence | none | AC-26, AC-29, AC-38, AC-39 lab portions (UNVERIFIED) | `lab` | T-0470, T-0493 |
| Q-005 | Brand and product | What is the product name, logo, primary language(s) and locale(s)? | Branding and i18n | Hack Dev Defence, English | publication of the public site | `HDD_BRAND_NAME`, `i18n` | T-0082, T-0431 |
| Q-006 | Brand and product | Who owns the legal text (Terms, Privacy, AUP, DPA) and who reviews it? | Legal guard blocks public signup until approved | operator counsel | public site publication, open signup | `legal_approved_at` | T-0101, T-0532 |
| Q-007 | Brand and product | Should signup be `disabled`, `invite_only` or `open`? Which email domains are allowed or blocked? Disposable-email policy? | Abuse and friction | `invite_only` | enabling public signup | `HDD_SIGNUP_MODE`, signup policy | T-0107, T-0428 |
| Q-008 | Brand and product | Which plans and limits do you want (domains, seats, rules, retention, API rate)? | Quota enforcement | `unlimited` in `owner_only` | paid tiers | `plans` | T-0146, T-0429 |
| Q-009 | Brand and product | Do you want billing? Which payment provider and jurisdiction? | Optional Tier 6 | none | T-0558 | `billing` | T-0558 |
| Q-010 | Brand and product | Where is the status page hosted (off the VPS is strongly recommended)? | Honest status during outages | local static (flagged) | truthful status during saturation | `status_host`, `HDD_STATUS_FEED_URL` | T-0100 |
| Q-011 | Email | SMTP relay host, port, TLS mode, credentials and the sender address for HDD mail; do you control SPF, DKIM and DMARC for the sending domain? | Verification, reset and alert emails | local SMTP sink only | real email delivery tests, AC-46 | `HDD_SMTP_*`, `HDD_MAIL_FROM` | T-0109, T-0431, T-0504 |
| Q-012 | Email | Operator email for alerts and acceptance mails | Email guard allows only this address in dev | none | alert tests | `operator_email` | T-0461 |
| Q-013 | Security policy | Password breach check mode: `offline_list`, `hibp_range` (egress to the range API) or `off`? | Privacy versus coverage | `offline_list` | enabling range mode needs egress allowlist | `HDD_PASSWORD_BREACH_CHECK` | T-0106 |
| Q-014 | Security policy | Should org owners be able to require MFA for all members? Platform roles always require MFA. | Policy | yes | - | `orgs.require_mfa` | T-0117 |
| Q-015 | Security policy | IP truncation default for tenants and retention defaults (events/audit) | Privacy | truncate off, 30 d / 400 d | - | `orgs.ip_truncation`, retention | T-0145, T-0441 |
| Q-016 | Security policy | Which presets should new domains start with (recommended: Monitor first, then Balanced)? | False-positive control | `monitor_first` | - | `org_settings.defaults` | T-0167 |
| Q-017 | Security policy | Is the origin application known to be vulnerable (legacy CMS, old framework)? Which components and versions? | Shield presets and virtual patches | unknown | exposure board matching (AC-30) | `app_inventory` | T-0482 |
| Q-018 | Admin access | Admin surface exposure: `tunnel_only` (SSH/WireGuard) or `routed_with_cidr`? Which CIDRs? | Highest-value target | `tunnel_only` | routed exposure | `surfaces.admin_exposure`, `admin_cidrs` | T-0417 |
| Q-019 | Admin access | What is the runner's source IP and your workstation IP? (Runner must not be in `admin_cidrs`.) | Runner-IP guard and recovery | detect | live acceptance | `test_runner` | T-0217, T-0492 |
| Q-020 | Admin access | SSH source CIDRs for port 22 | Lockout protection | operator IP only | deploy | `ssh_allow_cidrs` | T-0212, T-0468 |
| Q-021 | Domains | Platform domain and the apex you want to protect first; registrar and DNS provider; who can change NS at the registrar? | Cutover planning | none | P11 deploy; cutover | `platform_domain`, `domain` | T-0207, T-0536 |
| Q-022 | Domains | Which subzones may the pilot delegate (`test_hostname`, `sandbox_hostname`)? Can you add NS records for them? | Pilot | none | STOP #1 | `test_hostname`, `sandbox_hostname` | T-0216 |
| Q-023 | Domains | Is there a DS record at the parent for the apex today (DNSSEC enabled at the current provider)? | Unsigned HDD zone behind a DS causes outage | unknown | cutover (DS check) | `dnssec_state` | T-0403 |
| Q-024 | Domains | Which hostnames are non-HTTP services (mail, SSH, FTP, game servers, VPN) that must stay grey? | Proxy only handles HTTP(S) | none | parity (AC-23) | `non_http_services` | T-0158 |
| Q-025 | Origin | Origin address, port, TLS verification mode, Host header; is it behind a CDN or cloud load balancer? | Origin config and lockdown | none | P11 | `origin.*` | T-0163 |
| Q-026 | Origin | Can you apply an origin firewall allowlist and a secret header or mTLS? Where (nginx, Apache, cloud firewall)? | Lockdown wizard | pending | AC-18, cutover gate | `origin.lockdown_state` | T-0405, T-0406 |
| Q-027 | Origin | Can you place the canary files (and optionally `hdd-canary`) on the origin? | Leak/header tests | none | AC-05 header checks, AC-10 live (UNVERIFIED) | `canary` | T-0210 |
| Q-028 | Origin | Do you have an origin access log path/stream for header verification when the canary echo is not installed? | Alternate evidence | none | - | `origin_access_log` | T-0415 |
| Q-029 | DDoS | Is mitigation always-on or on-demand? Advertised capacity? What happens when exceeded? Mitigation API or support path? | Honest premise (C11.2) | `mode: none` (pilot only) | cutover unless risk accepted in writing | `upstream_ddos` | T-0476 |
| Q-030 | DDoS | Do you own an ASN (RTBH possible)? Do you want BGP integration (Tier 4)? | Optional | no | T-0555 | `asn` | T-0555 |
| Q-031 | DDoS | Heartbeat URL for an external dead-man monitor you run | Learn about saturation | none | shield alerts under saturation | `HDD_HEARTBEAT_URL` | T-0477 |
| Q-032 | DNS | External secondary DNS provider and TSIG key exchange details | Survivability | none | AC-21, cutover gate 2 | `secondary_dns` | T-0394 |
| Q-033 | TLS | ACME CA preference, account email, CAA policy; approve one-time production issuance when ready | Certificates | staging only | production issuance (T-0538) | `acme.*` | T-0376, T-0538 |
| Q-034 | TLS | Is a CT monitoring/search service permitted (egress allowlist)? | CT checks | none | CT signals UNVERIFIED | `egress_allowlist` | T-0201, T-0379 |
| Q-035 | Data | GeoIP/ASN database (license holder) and update method | Geo analytics, country rules | none | country rules (UNVERIFIED) | `HDD_GEOIP_DB`, `HDD_ASN_DB` | T-0347, T-0443 |
| Q-036 | Data | Threat-intel feeds you permit (hosts, licenses) | Reputation | disabled | feeds | `threat_feeds` | T-0348, T-0426 |
| Q-037 | Data | Backup destination (local, SFTP, S3-compatible), `age` recipient public keys, offline key escrow owner | Recovery | local only | DR drill, production | `backup.*` | T-0523 |
| Q-038 | Operations | Who is on call, escalation contacts, maintenance windows, and who authorizes rollback? | Runbooks | operator | cutover | `ops.contacts` | T-0527, T-0536 |
| Q-039 | Operations | Provider acceptable-use confirmation for security testing from the runner (date) | First live test | missing | first live test | `provider_aup_confirmed` | T-0216 |
| Q-040 | Operations | Egress allowlist entries (CA, feeds, SMTP, GeoIP, package mirrors, CT, release host) | Egress guard | minimal | feeds, ACME, mail | `egress_allowlist` | T-0009 |
| Q-041 | Release | Release signing approach (offline key, hardware token, keyless CI) and update channel | Supply chain | offline key | signed upgrades | `release.*` | T-0518 |
| Q-042 | Release | Do you want auto-update (default off) and which channel? | Safety | off, stable | - | `auto_update` | T-0518 |
| Q-043 | Compliance | Jurisdiction, DPO needs, breach-notification contacts, data residency | Legal pack | unknown | legal approval | `compliance.*` | T-0532 |
| Q-044 | Compliance | Public vulnerability disclosure contact and PGP/age key | SECURITY.md, security.txt | none | public launch | `security_contact` | T-0519 |
| Q-045 | UX | Design sign-off reviewers and the date for the P03 review | M1 sign-off | operator | build of affected screens | `design.signoff` | T-0070 |
| Q-046 | UX | Preferred theme default (dark first) and density default | Design system | dark, comfortable | - | `HDD_I18N_DEFAULT_LOCALE`, prefs | T-0029 |
| Q-047 | Scope | Which Tier 2 to 6 items are priorities after M12? | Backlog order | as listed | - | `docs/BACKLOG.md` | T-0560 |
| Q-048 | Runtime | Do you want to run HDD on your own computer (`local`), on a server (`hosted`), or both? Which operating system is your computer? | Build track, which acceptance tiers can run, and whether M5 and M12 apply | both, local first | M5 and M12 apply to hosted only | `runtime.profile` | T-0561 |
| Q-049 | Runtime | For `local`: may HDD install its name-constrained local certificate authority into your user trust store (otherwise HTTP-only on loopback or a browser exception)? | Browser trust for https://*.hdd.localhost | ask during first-run setup | TLS in browsers | `runtime.local.tls` | T-0566 |
| Q-050 | Runtime | For `local`: will you expose it beyond this computer (LAN or an operator-run tunnel)? Which tunnel provider, if any? | Binding, client identity and origin lockdown | no exposure | exposure checks | `runtime.local.tunnel` | T-0565, T-0568 |
| Q-051 | Hosting | For 24/7: which server or provider and region will run HDD, and which hosting profile (H1 to H5) fits? | Hosting check, ports and capacity | H1 single VPS | STOP #1 | `runtime.hosting.profile` | T-0571 |
| Q-052 | Hosting | Does the server's provider allow inbound 53, 80 and 443 and outbound 25 or 587? Is a second server or provider available for H2? | Hosting checks HC-05 to HC-09 and standby edges | unknown | HC items UNVERIFIED | provider notes | T-0571, T-0573 |
| Q-053 | Hosting | Where should backups go (local, SFTP, S3-compatible), who holds the encryption key and the master-key escrow, and who is on call for the 24/7 runbooks? | Backups, restore drills, runbooks | local only | AC-56 remote backup | `HDD_BACKUP_TARGET` | T-0574 |
| Q-054 | Protection scope | Which paths of your sites should sit behind the access gate (admin areas, database tools) and which business flows matter most (login, signup, checkout, OTP, search)? | Gate templates and flow defaults | templates by site platform | AC-57 scenarios | `access_gate_rules`, `business_flows` | T-0575, T-0577 |
| Q-055 | Protection scope | Do you have an OpenAPI or GraphQL description for your APIs? | API discovery and enforcement | learn from traffic | spec import | `api_specs` | T-0576 |
| Q-056 | Bypass | How will each origin be locked down: outbound tunnel, signed origin authentication, or a firewall allowlist (and can the origin host be changed at all)? | The Bypass Guard state and whether `block` mode may be entered (R-34) | signed origin authentication plus firewall instructions | `block` mode for that site | `origin_lockdown` | T-0588 |
| Q-057 | Learned detection | May Sentinel (learned detection) run in `shadow` on your sites, and who approves any promotion to `assist` or `block`? | Sentinel mode per site (R-33) | shadow only | promotion beyond shadow | `sentinel_modes` | T-0584 |
| Q-058 | Learned detection | May the optional analyst (a language model) be used, and if so which provider or local model, knowing evidence fields are redacted? | Analyst triage and rule drafts for humans | off | analyst features | `sentinel_analyst` | T-0586 |

## Decisions the agent must ask for explicitly (E8.1, never assume)

1. Switching any production-facing site from `monitor` to `block` (with the impact summary).
2. Production ACME issuance (one event per approved request).
3. Any `load` profile run and any destructive resilience/chaos test in production stage (with a maintenance window).
4. Opening public signup (`signup.mode: open`).
5. Cutover of the apex (registrar changes) and the rollback decision deadline.
6. Accepting any NO-GO cutover gate item (item-specific, written, dated).
7. Loosening any threshold in E4 or substituting any technology from section 6 (DEVIATIONS entry).
8. Enabling auto-update, auto-failover, or any Tier 2 to 6 feature that changes the attack surface.
9. Sending any email to an address other than `operator_email` during development.
10. Any volumetric test beyond the closed lab, which needs the provider's written permission.

## Blocking level of each question (T-0007 A4)

Added by T-0007 (not part of the verbatim Appendix E8). Levels: **pilot** = blocks the first live pilot (STOP #1, milestone M5) or the live acceptance runs; **cutover** = blocks apex cutover, production issuance or public launch (STOP #2, milestone M12); **feature** = blocks only the named feature or test (its default applies; the item stays UNVERIFIED until answered); **default** = nothing is blocked: the stated default applies until you change it.

| Id | Level |
| --- | --- |
| Q-001 | feature |
| Q-002 | feature |
| Q-003 | cutover |
| Q-004 | feature |
| Q-005 | feature |
| Q-006 | cutover |
| Q-007 | cutover |
| Q-008 | feature |
| Q-009 | feature |
| Q-010 | feature |
| Q-011 | feature |
| Q-012 | feature |
| Q-013 | feature |
| Q-014 | default |
| Q-015 | default |
| Q-016 | default |
| Q-017 | feature |
| Q-018 | default |
| Q-019 | pilot |
| Q-020 | pilot |
| Q-021 | pilot |
| Q-022 | pilot |
| Q-023 | cutover |
| Q-024 | feature |
| Q-025 | pilot |
| Q-026 | cutover |
| Q-027 | pilot |
| Q-028 | feature |
| Q-029 | cutover |
| Q-030 | feature |
| Q-031 | feature |
| Q-032 | cutover |
| Q-033 | cutover |
| Q-034 | feature |
| Q-035 | feature |
| Q-036 | feature |
| Q-037 | cutover |
| Q-038 | cutover |
| Q-039 | pilot |
| Q-040 | pilot |
| Q-041 | cutover |
| Q-042 | feature |
| Q-043 | cutover |
| Q-044 | cutover |
| Q-045 | feature |
| Q-046 | default |
| Q-047 | default |
| Q-048 | pilot |
| Q-049 | feature |
| Q-050 | feature |
| Q-051 | pilot |
| Q-052 | pilot |
| Q-053 | cutover |
| Q-054 | feature |
| Q-055 | feature |
| Q-056 | cutover |
| Q-057 | feature |
| Q-058 | feature |

## Primary persona for the pilot (added by T-0012)

This is not one of the 58 verbatim Appendix E8 questions; it is a UX research question added by T-0012 (REQ-UXR-02). The
answer decides which persona the pilot screens are designed for first and which one the design-sign-off review (Q-045)
judges them against. The numbered register above stays at its 58 verbatim questions, so this question is recorded here
with its own state rather than as a new `Q-nnn` row.

| Question | Default if unanswered (dev/pilot only) | State | Stored in | Task |
| --- | --- | --- | --- | --- |
| Which persona is primary for the pilot: Maya, Dan, Sara, Omar, Vi or Alex? | Maya, the site owner (B1.1) | OPEN: no answer yet, so the default applies for development | `docs/UX/personas/maya.md` and the [persona-journey matrix](UX/persona-journey-matrix.md) | T-0012 |

Recorded by T-0012 on 2026-10-19. When the operator answers, the answer goes verbatim and dated into
`docs/OPERATOR-CONFIRMATIONS.md`, the state here becomes ANSWERED, and the Maya file stops calling her the assumed primary
persona.


## Questions added by T-0017

| Question | Default | State |
| --- | --- | --- |
| Should the monitor-to-block switch use a scheduled switch with typed confirmation? | Scheduled switch with typed confirmation | OPEN |
| What should the default appeal retention period be, and who may read an appeal? | 30 days; the owner and analysts | OPEN |

## Questions added by T-0215 (acceptance runner)

Added 2026-10-20 while implementing the acceptance runner skeleton (T-0215). They do not block the batch; the runner applies the stated defaults and `docs/ACCEPTANCE.md` records them as authored guard rails.

| Question | Default if unanswered (dev/pilot only) | State |
| --- | --- | --- |
| The v5 profile has no numeric `load` caps (only `load_profile_approved`), yet E3.1 rule 4 says `load` has "its own hard caps in the profile". Which caps should the profile carry (rate, burst, duration) and in which key block (`load_caps`?), or should the runner keep its authored 100 req/s / 100 burst / 600 s guard rail? | Authored guard rail: 100 req/s, burst 100, 600 s, sandbox only, with the approval gate unchanged; the values are not profile values | OPEN |
| Section 2.3 gives `burst` no duration. Is the authored 60 s guard rail acceptable, or does the operator want a different bound? | 60 s | OPEN |
| The `functional` profile also covers a port scan of the operator's own VPS (20 pps, TCP top-1000 plus 53/80/443). The HTTP acceptance runner does not scan; that half belongs to `hdd-scan` (T-0487) under E4. Confirm the split. | The scan stays in `hdd-scan`; the runner enforces only the HTTP lane | OPEN |
