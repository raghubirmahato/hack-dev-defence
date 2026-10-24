# FIRST-RESPONSE

The first response of section 9 (task T-0007), kept as the record. Status: **delivered to the operator on 2026-10-19; no answer has been given yet, so every question is OPEN** (the register is `docs/OPERATOR-QUESTIONS.md`, the levels are in `STATUS.md`). Answers are recorded verbatim and dated in `docs/OPERATOR-CONFIRMATIONS.md`.

It has the six items of section 9, in order, and nothing else. It contains no source code; the one pasted block is program output. No secrets or file contents are included and nothing was contacted over the network to prepare it.

## 1. Mission and safety envelope

- **Mission.** Build Hack Dev Defence (HDD): a self-hosted web application firewall, authoritative DNS server and TLS reverse proxy, with a web product around it (public site, sign-up, customer dashboard, per-domain controls, platform admin panel). It runs as `hosted` (a server, 24/7) or `local` (your computer, only while HDD runs) from the same code.
- **Method.** 599 tasks in 35 phases behind gates. Every check ends PASS, FAIL or UNVERIFIED(reason) with pasted output; nothing is marked passed without evidence, and a test is never weakened to get green.
- **Scope of traffic.** Attack-shaped traffic goes only to the hosts in your profile: `test_hostname` (inert shapes, GET/HEAD only) and `sandbox_hostname` (destructive shapes, exact canary paths only). Payloads that could harm an origin are never sent live. Nothing is ever aimed at third parties or at your tenants' domains.
- **Inspect first.** Every live attack-shaped request is first submitted to the dry-run inspector and sent only if it would be blocked.
- **Limits.** Rate profiles with hard caps; a kill-switch file stops every test within one second; no volumetric test over the internet (floods exist only in a closed lab you own); load runs need your separate written approval.
- **No lock-out.** The test runner's IP is never on the never-ban list and every test ban has a short TTL; firewall, SSH and DNS changes carry a timed automatic revert.
- **Data.** Mail goes only to `operator_email`; secrets are never printed, logged or committed; request bodies are never stored beyond a 512-byte redacted snippet.
- **Local profile.** Loopback only, no silent privilege, no trust-root installation without your consent.
- **Honesty.** The product never claims to stop everything: claims are tested, contracted or listed as known limitations (claims policy, section 4).

## 2. Validation of `hdd.live.yaml` (section 8)

`hdd.live.yaml` does not exist, so the validator lists every required field and how to provide it. This is the real output of `hddctl preflight --profile-only` on this builder (exit code 1):

```text
FAIL: cannot read hdd.live.yaml (The system cannot find the file specified. (os error 2)).
Required for runtime.profile: hosted (section 8):
  - operator_email: the address that receives test mail and alerts; it is the only address the agent may mail
  - platform_domain: the apex you own that will host www/app/admin/api/ns/status, for example example.com (registrar access not needed yet)
  - domain: the apex zone you own and want protected first
  - test_hostname: a subdomain of `domain` that mirrors your real site, for example hddtest.<domain> (benign traffic and GET/HEAD attack shapes only)
  - sandbox_hostname: a second subdomain of `domain`, distinct from test_hostname, that forwards only exact canary paths, for example hddsbx.<domain>
  - surfaces.public_host: host for the public site, for example www.<platform_domain>
  - surfaces.app_host: host for the customer app, for example app.<platform_domain>
  - surfaces.admin_host: host for the admin panel, for example admin.<platform_domain>
  - surfaces.api_host: host for the API, for example api.<platform_domain>
  - surfaces.status_host: host for the status page, ideally served from outside this server
  - origin.url: the real origin with scheme, for example https://203.0.113.10
  - origin.tls_server_name: the name the origin certificate is valid for
  - origin.host_header: the Host header the origin expects
  - platform.public_ipv4: the public IPv4 address(es) of the server that will run HDD (at least one IPv4 or IPv6 address)
  - platform.ns_hostnames: the nameserver host names HDD will serve, for example ns1.<platform_domain> and ns2.<platform_domain>
  - platform.edge_cname_zone: zone for <site-id>.edge.<platform_domain> (CNAME modes), for example edge.<platform_domain>
  - platform.acme_cname_zone: zone for DNS-01 delegation targets, for example acme.<platform_domain>
  - acme.email: the account email for the certificate authority
Copy hdd.live.example.yaml to hdd.live.yaml (git-ignored), fill these fields, and run `hddctl preflight --profile-only`.
```

For `runtime.profile: local` only one field is required, `operator_email`, plus `signup` (mode `disabled` or `invite_only`) and `runtime` (section 8.2). Nothing in the file may be a secret value: secret-bearing fields hold the **name** of an environment variable, and a value that looks like a credential is rejected without being echoed. Optional fields that stay empty are reported UNVERIFIED, never filled in. Reachability of the SMTP relay and of your nameserver names is checked only by `hddctl preflight` (without `--profile-only`) and only through the allowlisted egress path, so those checks stay UNVERIFIED until `egress_allowlist` is supplied (Q-040).

## 3. Environment discovery and the build track

Read-only discovery on 2026-10-18 (full table: `docs/ENV.md`, logs with sha256). Builder: Windows 11 Pro, AMD Ryzen 7 7735HS (8 cores, 16 threads), 15.2 GB RAM, D: drive 343 GB free, no virtualization hypervisor, Wi-Fi uplink about 827 Mbit/s, clock in sync, nothing listening on 53/80/443, Chrome present for browser tests.

| Item | Status | What degrades |
| --- | --- | --- |
| Rust 1.98.1 (stable), cargo, clippy, rustfmt, cargo-deny, cargo-audit, cargo-nextest, cargo-machete, dig, delv, openssl, ssh, git | PASS | nothing |
| Docker / compose | UNVERIFIED(`environment_unsupported`) | **Track L**: the embedded PostgreSQL and in-process stores of `hdd-local` replace testcontainers (T-0561 to T-0563); compose-based checks are skipped |
| nftables, iptables, BTF/XDP, kernel version, ethtool | UNVERIFIED(`environment_unsupported`) | kernel firewall and XDP (P25, AC-26, AC-29) need a Linux host; the local profile never uses them |
| nightly toolchain, `bpf-linker` | UNVERIFIED(`tool_unavailable`) | the eBPF crate cannot be built here (P25) |
| cargo-llvm-cov, cargo-mutants, cargo-fuzz, cosign | UNVERIFIED(`tool_unavailable`) | coverage, mutation score, coverage-guided fuzzing and signing are reported UNVERIFIED until installed on a suitable builder |
| tokei, cargo-vet, cargo-geiger | **now installed** (after vetting, 2026-10-18; the discovery table predates this) | `cargo vet` passes only with every third-party crate exempted; importing audit sets is your decision |
| Outbound connectivity, VPS discovery over SSH, runner and lab | UNVERIFIED(`human_step_pending`) / not supplied | nothing outbound has been contacted; needs `egress_allowlist` and an SSH account (Q-020, Q-040) |

**Build-track decision: Track L** (no Docker). Hosted-only checks (authoritative DNS on port 53, kernel enforcement, ACME on a public name, STOP #1 and STOP #2) are UNVERIFIED(`environment_unsupported`) here until a Linux host is supplied. A missing tool never blocks the build; it selects the track and lowers what can be claimed.

## 4. Plan for P00 to P03

Effort is an estimate in working sessions (one session is roughly two to three days of the spec's size bands; the second P00 session finished the tooling tasks T-0005, T-0006, T-0008, T-0009 and the mechanics of T-0010), with low confidence beyond P01. Dates are not predicted.

| Phase | Tasks | Gate and what must hold for it to pass | Estimate | Operator involvement |
| --- | --- | --- | --- | --- |
| P00 Bootstrap and governance | T-0001 to T-0010 (nine verified or green; T-0007 is this message) | **G00** (milestone M0): spec and split with matching checksum; AGENTS.md at most 150 lines; `cargo check` and `cargo xtask verify` green; `hddctl preflight --profile-only` reports honestly; egress guard tests pass; capability matrix generated; this first response delivered and answers recorded or marked open. State today: everything passes except the last item and the commit/tag. Report: `docs/gates/G00.md` | about 1 session left (answers, commit, tag) | confirm answers; say when to commit |
| P01 UX research, personas, IA, journeys | T-0011 to T-0028 (18 documents) | **G01** (light gate): UX charter, personas, information architecture, journeys, states, accessibility and i18n plans, security-UX review and the review pack exist in `docs/UX/` and link to each other; `xtask ux check` reports zero orphan screens or journeys; every open decision has a default and an owner | 5 to 7 sessions | none |
| P02 Design system | T-0029 to T-0052 (24: tokens, components, gallery) | **G02**: contrast check, token build and CSS budgets pass; every component renders in the static gallery in both themes; the axe oracle reports no serious or critical findings; keyboard maps documented; you have seen screenshots | 12 to 16 sessions | see screenshots |
| P03 Screen prototypes | T-0053 to T-0070 (18: 143 screens in every required state) | **G03** (milestone M1): all 143 screens have prototype pages in all required states; heuristic and accessibility reviews recorded fixes; claims-lint passes; you reviewed screenshots and recorded sign-off or a list of changes (UNVERIFIED until then, which blocks only the build of the affected screens) | 14 to 18 sessions | **design sign-off (M1)** |

Because P00 to P03 contain no live component, nothing in them needs your servers. Right after G00 the foundation slice DS0 continues with T-0561 to T-0563 (runtime profile model, store traits, embedded database), which is what makes the local walking skeleton (DS1) possible.

## 5. Human-gated steps to expect

| Step | When (milestone) | What you will be asked |
| --- | --- | --- |
| Answer this message; say when to commit and tag G00 | now (M0) | the questions of item 6; permission to commit |
| M1 design sign-off | end of P03 | review prototype screenshots; sign off or list changes |
| M3 SMTP details | before the real-mail tests of P06 | relay host, port, TLS mode, credentials as variable names, sender address, SPF/DKIM/DMARC control (Q-011); until then a local SMTP sink is used |
| STOP #1 | M5 (P11 walking skeleton) | canary files on the origin, pilot subzone NS/A delegation, your hosting provider's acceptable-use confirmation for security testing from the runner (dated) |
| STOP #2 | M12 (P31) | registrar preparation, origin firewall and secret header (or tunnel), secondary DNS, provider DDoS contract details, DS-check inputs |
| Production ACME approval | before the first real certificate (T-0538) | one explicit approval per issuance request |
| `load` run | only if you want performance qualification | separate written approval for that run and a maintenance window |
| Cutover | after STOP #2 | explicit written go-ahead and the rollback decision deadline; never automatic |
| Other approvals when reached (E8.1) | as they arise | `monitor` to `block` for a production site, open signup, accepting a NO-GO gate item, loosening an E4 value, auto-update or auto-failover, mail to any address other than `operator_email` |

## 6. Questions, grouped, each with what it blocks

Please answer by id (for example `Q-048: both, local first`). Questions you skip keep the stated default, which is used for development and the pilot only and never enables production behavior. Later questions go into the register rather than into new interruptions.

### 6a. DDoS-readiness questions (Part C, C11.2; stored in `upstream_ddos`)

1. Which hosting provider and plan; is its DDoS mitigation always-on or on-demand; what is the advertised capacity; what exactly happens when it is exceeded (for example a null-route for N minutes)? What is the server uplink speed? (Q-002, Q-029)
2. Is there a mitigation API, a support escalation path, or a separate scrubbing service that can front the server (reverse proxy or tunnel)? (Q-029, Q-031)
3. Do you own an ASN (RTBH over BGP is possible only then)? Can a second provider host a secondary DNS and a standby edge? (Q-030, Q-003, Q-032)

Decision rule: `upstream_ddos.mode: none` is allowed for the pilot only; for apex cutover it is NO-GO unless you record `risk_acceptance_volumetric: true` in chat with the date. Capacity is never inferred from lab numbers. **Blocks:** shield capacity figures (T-0476, T-0477), the cutover gate, AC-21/AC-27/AC-28; the pilot reports DDoS readiness NOT READY.

### 6b. Origin-inventory questions (Part C, C12.2; stored in `app_inventory`)

1. Which components run on the origin: CMS and plugins, frameworks, language runtime, web server, database, container base images, third-party scripts? Versions, and whether each is internet-facing. (Q-017)
2. Can you provide a CycloneDX or SPDX SBOM, a lockfile (`Cargo.lock`, `package-lock.json`, `composer.lock`, `requirements.txt`) or a package list? (Q-017)
3. Who receives patch-SLA alerts? (`app_inventory.origin_owner_contact`)

Sources used later by the vulnerability pipeline are your list, imported SBOMs/lockfiles and passive read-only fingerprints of your own origin; unknown versions stay unknown. **Blocks:** real matching in AC-30 and the exposure-board cutover gate (T-0482).

### 6c. Product, deployment and policy questions (Appendix E8)

Each line: id, question, default if unanswered, then **level** and the tasks it blocks. Levels: **pilot** = blocks the first live pilot (STOP #1, milestone M5) or the live acceptance runs (11 questions); **cutover** = blocks apex cutover, production issuance or public launch (STOP #2, milestone M12) (15); **feature** = blocks only the named feature or test (its default applies; the item stays UNVERIFIED until answered) (26); **default** = nothing is blocked: the stated default applies until you change it (6).

**Deployment**

- **Q-001** Do you want HDD for your own domains only (`owner_only`) or as a service for other people (`saas`)? Default: `owner_only`. Blocks (feature): public signup, billing, tenant-safety guards (saas) [tasks T-0001, T-0422, T-0532].
- **Q-002** Which hosting provider, plan, region and uplink speed does the VPS have? Default: unknown (capacity UNVERIFIED). Blocks (feature): shield capacity figures [tasks T-0476].
- **Q-003** Is a second VPS or a second provider available for a standby edge and a secondary DNS? Default: none. Blocks (cutover): cutover gate (secondary DNS), AC-21, AC-28, AC-27 [tasks T-0394, T-0478].
- **Q-004** Is there a closed lab machine (or two machines on a private link) for volumetric tests and the Vuln-Lab? Default: none. Blocks (feature): AC-26, AC-29, AC-38, AC-39 lab portions (UNVERIFIED) [tasks T-0470, T-0493].

**Brand and product**

- **Q-005** What is the product name, logo, primary language(s) and locale(s)? Default: Hack Dev Defence, English. Blocks (feature): publication of the public site [tasks T-0082, T-0431].
- **Q-006** Who owns the legal text (Terms, Privacy, AUP, DPA) and who reviews it? Default: operator counsel. Blocks (cutover): public site publication, open signup [tasks T-0101, T-0532].
- **Q-007** Should signup be `disabled`, `invite_only` or `open`? Which email domains are allowed or blocked? Disposable-email policy? Default: `invite_only`. Blocks (cutover): enabling public signup [tasks T-0107, T-0428].
- **Q-008** Which plans and limits do you want (domains, seats, rules, retention, API rate)? Default: `unlimited` in `owner_only`. Blocks (feature): paid tiers [tasks T-0146, T-0429].
- **Q-009** Do you want billing? Which payment provider and jurisdiction? Default: none. Blocks (feature): T-0558 [tasks T-0558].
- **Q-010** Where is the status page hosted (off the VPS is strongly recommended)? Default: local static (flagged). Blocks (feature): truthful status during saturation [tasks T-0100].

**Email**

- **Q-011** SMTP relay host, port, TLS mode, credentials and the sender address for HDD mail; do you control SPF, DKIM and DMARC for the sending domain? Default: local SMTP sink only. Blocks (feature): real email delivery tests, AC-46 [tasks T-0109, T-0431, T-0504].
- **Q-012** Operator email for alerts and acceptance mails Default: none. Blocks (feature): alert tests [tasks T-0461].

**Security policy**

- **Q-013** Password breach check mode: `offline_list`, `hibp_range` (egress to the range API) or `off`? Default: `offline_list`. Blocks (feature): enabling range mode needs egress allowlist [tasks T-0106].
- **Q-014** Should org owners be able to require MFA for all members? Platform roles always require MFA. Default: yes. Blocks (default): - [tasks T-0117].
- **Q-015** IP truncation default for tenants and retention defaults (events/audit) Default: truncate off, 30 d / 400 d. Blocks (default): - [tasks T-0145, T-0441].
- **Q-016** Which presets should new domains start with (recommended: Monitor first, then Balanced)? Default: `monitor_first`. Blocks (default): - [tasks T-0167].
- **Q-017** Is the origin application known to be vulnerable (legacy CMS, old framework)? Which components and versions? Default: unknown. Blocks (feature): exposure board matching (AC-30) [tasks T-0482].

**Admin access**

- **Q-018** Admin surface exposure: `tunnel_only` (SSH/WireGuard) or `routed_with_cidr`? Which CIDRs? Default: `tunnel_only`. Blocks (default): routed exposure [tasks T-0417].
- **Q-019** What is the runner's source IP and your workstation IP? (Runner must not be in `admin_cidrs`.) Default: detect. Blocks (pilot): live acceptance [tasks T-0217, T-0492].
- **Q-020** SSH source CIDRs for port 22 Default: operator IP only. Blocks (pilot): deploy [tasks T-0212, T-0468].

**Domains**

- **Q-021** Platform domain and the apex you want to protect first; registrar and DNS provider; who can change NS at the registrar? Default: none. Blocks (pilot): P11 deploy; cutover [tasks T-0207, T-0536].
- **Q-022** Which subzones may the pilot delegate (`test_hostname`, `sandbox_hostname`)? Can you add NS records for them? Default: none. Blocks (pilot): STOP #1 [tasks T-0216].
- **Q-023** Is there a DS record at the parent for the apex today (DNSSEC enabled at the current provider)? Default: unknown. Blocks (cutover): cutover (DS check) [tasks T-0403].
- **Q-024** Which hostnames are non-HTTP services (mail, SSH, FTP, game servers, VPN) that must stay grey? Default: none. Blocks (feature): parity (AC-23) [tasks T-0158].

**Origin**

- **Q-025** Origin address, port, TLS verification mode, Host header; is it behind a CDN or cloud load balancer? Default: none. Blocks (pilot): P11 [tasks T-0163].
- **Q-026** Can you apply an origin firewall allowlist and a secret header or mTLS? Where (nginx, Apache, cloud firewall)? Default: pending. Blocks (cutover): AC-18, cutover gate [tasks T-0405, T-0406].
- **Q-027** Can you place the canary files (and optionally `hdd-canary`) on the origin? Default: none. Blocks (pilot): AC-05 header checks, AC-10 live (UNVERIFIED) [tasks T-0210].
- **Q-028** Do you have an origin access log path/stream for header verification when the canary echo is not installed? Default: none. Blocks (feature): - [tasks T-0415].

**DDoS**

- **Q-029** Is mitigation always-on or on-demand? Advertised capacity? What happens when exceeded? Mitigation API or support path? Default: `mode: none` (pilot only). Blocks (cutover): cutover unless risk accepted in writing [tasks T-0476].
- **Q-030** Do you own an ASN (RTBH possible)? Do you want BGP integration (Tier 4)? Default: no. Blocks (feature): T-0555 [tasks T-0555].
- **Q-031** Heartbeat URL for an external dead-man monitor you run Default: none. Blocks (feature): shield alerts under saturation [tasks T-0477].

**DNS**

- **Q-032** External secondary DNS provider and TSIG key exchange details Default: none. Blocks (cutover): AC-21, cutover gate 2 [tasks T-0394].

**TLS**

- **Q-033** ACME CA preference, account email, CAA policy; approve one-time production issuance when ready Default: staging only. Blocks (cutover): production issuance (T-0538) [tasks T-0376, T-0538].
- **Q-034** Is a CT monitoring/search service permitted (egress allowlist)? Default: none. Blocks (feature): CT signals UNVERIFIED [tasks T-0201, T-0379].

**Data**

- **Q-035** GeoIP/ASN database (license holder) and update method Default: none. Blocks (feature): country rules (UNVERIFIED) [tasks T-0347, T-0443].
- **Q-036** Threat-intel feeds you permit (hosts, licenses) Default: disabled. Blocks (feature): feeds [tasks T-0348, T-0426].
- **Q-037** Backup destination (local, SFTP, S3-compatible), `age` recipient public keys, offline key escrow owner Default: local only. Blocks (cutover): DR drill, production [tasks T-0523].

**Operations**

- **Q-038** Who is on call, escalation contacts, maintenance windows, and who authorizes rollback? Default: operator. Blocks (cutover): cutover [tasks T-0527, T-0536].
- **Q-039** Provider acceptable-use confirmation for security testing from the runner (date) Default: missing. Blocks (pilot): first live test [tasks T-0216].
- **Q-040** Egress allowlist entries (CA, feeds, SMTP, GeoIP, package mirrors, CT, release host) Default: minimal. Blocks (pilot): feeds, ACME, mail [tasks T-0009].

**Release**

- **Q-041** Release signing approach (offline key, hardware token, keyless CI) and update channel Default: offline key. Blocks (cutover): signed upgrades [tasks T-0518].
- **Q-042** Do you want auto-update (default off) and which channel? Default: off, stable. Blocks (feature): - [tasks T-0518].

**Compliance**

- **Q-043** Jurisdiction, DPO needs, breach-notification contacts, data residency Default: unknown. Blocks (cutover): legal approval [tasks T-0532].
- **Q-044** Public vulnerability disclosure contact and PGP/age key Default: none. Blocks (cutover): public launch [tasks T-0519].

**UX**

- **Q-045** Design sign-off reviewers and the date for the P03 review Default: operator. Blocks (feature): build of affected screens [tasks T-0070].
- **Q-046** Preferred theme default (dark first) and density default Default: dark, comfortable. Blocks (default): - [tasks T-0029].

**Scope**

- **Q-047** Which Tier 2 to 6 items are priorities after M12? Default: as listed. Blocks (default): - [tasks T-0560].

**Runtime**

- **Q-048** Do you want to run HDD on your own computer (`local`), on a server (`hosted`), or both? Which operating system is your computer? Default: both, local first. Blocks (pilot): M5 and M12 apply to hosted only [tasks T-0561].
- **Q-049** For `local`: may HDD install its name-constrained local certificate authority into your user trust store (otherwise HTTP-only on loopback or a browser exception)? Default: ask during first-run setup. Blocks (feature): TLS in browsers [tasks T-0566].
- **Q-050** For `local`: will you expose it beyond this computer (LAN or an operator-run tunnel)? Which tunnel provider, if any? Default: no exposure. Blocks (feature): exposure checks [tasks T-0565, T-0568].

**Hosting**

- **Q-051** For 24/7: which server or provider and region will run HDD, and which hosting profile (H1 to H5) fits? Default: H1 single VPS. Blocks (pilot): STOP #1 [tasks T-0571].
- **Q-052** Does the server's provider allow inbound 53, 80 and 443 and outbound 25 or 587? Is a second server or provider available for H2? Default: unknown. Blocks (pilot): HC items UNVERIFIED [tasks T-0571, T-0573].
- **Q-053** Where should backups go (local, SFTP, S3-compatible), who holds the encryption key and the master-key escrow, and who is on call for the 24/7 runbooks? Default: local only. Blocks (cutover): AC-56 remote backup [tasks T-0574].

**Protection scope**

- **Q-054** Which paths of your sites should sit behind the access gate (admin areas, database tools) and which business flows matter most (login, signup, checkout, OTP, search)? Default: templates by site platform. Blocks (feature): AC-57 scenarios [tasks T-0575, T-0577].
- **Q-055** Do you have an OpenAPI or GraphQL description for your APIs? Default: learn from traffic. Blocks (feature): spec import [tasks T-0576].

**Bypass**

- **Q-056** How will each origin be locked down: outbound tunnel, signed origin authentication, or a firewall allowlist (and can the origin host be changed at all)? Default: signed origin authentication plus firewall instructions. Blocks (cutover): `block` mode for that site [tasks T-0588].

**Learned detection**

- **Q-057** May Sentinel (learned detection) run in `shadow` on your sites, and who approves any promotion to `assist` or `block`? Default: shadow only. Blocks (feature): promotion beyond shadow [tasks T-0584].
- **Q-058** May the optional analyst (a language model) be used, and if so which provider or local model, knowing evidence fields are redacted? Default: off. Blocks (feature): analyst features [tasks T-0586].

### 6d. What each unanswered item blocks (section 9 table)

| Unanswered or missing | Blocks |
| --- | --- |
| Runtime profile choice (local, hosted, or both) (Q-048) | the build track, the acceptance tiers that can run, and which of M5 and M12 apply |
| Hosting provider and profile (H1 to H5) for 24/7 operation (Q-051, Q-052) | STOP #1 at M5 and any uptime statement |
| Required profile fields (hosted) | P00 preflight and everything live (P11 deploy) |
| Provider AUP confirmation (Q-039) | the first live test |
| `egress_allowlist` entries (Q-040) | feeds, propagation checks, ACME, SMTP, GeoIP download |
| SMTP details (Q-011) | real email delivery tests in P06 (a local SMTP sink is used until then) |
| Brand and legal ownership (Q-005, Q-006) | publication of the public site (P05 can be built, not published) |
| `signup.mode: open` approval (Q-007) | enabling public signup |
| `upstream_ddos` details (Q-029) | cutover only; the pilot reports NOT READY |
| `secondary_dns` (Q-032) | cutover gate, AC-21, AC-28 |
| Lab machine (Q-004) | AC-26, AC-29, AC-38, AC-39 lab portions (UNVERIFIED `capability_not_supplied`) |
| `platform.uplink_mbps` (Q-002) | shield capacity figures (UNVERIFIED) |
| Inventory or SBOM (Q-017) | real matching in AC-30 and the exposure-board cutover gate |
| GeoIP database (Q-035) | country rules and geo analytics (UNVERIFIED) |

### 6e. Two new questions from P00

- May a commit be created (and the pre-commit secret-scan hook installed with `cargo xtask hooks install`, which sets `core.hooksPath`) so that the tag `gate-G00` can be set?
- Which published `cargo vet` audit sets, if any, may be imported? Each import is a trust decision; without any, every third-party crate stays on the exemption list.
