#![allow(clippy::expect_used, clippy::unwrap_used, reason = "tests")]

use std::fs;
use std::path::{Path, PathBuf};

use super::*;

struct Repo(PathBuf);

impl Repo {
    fn new(name: &str) -> Repo {
        let dir = std::env::temp_dir().join(format!("hdd-xtask-ux-{}-{name}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(dir.join("docs").join("UX").join("decisions")).expect("mkdir");
        Repo(dir)
    }

    fn put(&self, rel: &str, text: &str) {
        let p = self.0.join(rel);
        if let Some(parent) = p.parent() {
            fs::create_dir_all(parent).expect("mkdir");
        }
        fs::write(p, text).expect("write");
    }

    fn root(&self) -> &Path {
        &self.0
    }
}

impl Drop for Repo {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn messages(f: &[Finding]) -> String {
    f.iter()
        .map(ToString::to_string)
        .collect::<Vec<_>>()
        .join("\n")
}

const PRINCIPLES: [&str; 7] = [
    "Calm, honest, expert",
    "Show state, not decoration",
    "Progressive disclosure",
    "Safe by design",
    "Fast and light",
    "Accessible by construction",
    "Dark first, light equal",
];

fn good_charter() -> String {
    let mut s = String::from(
        "# Charter\n\n## Principles\n\n| # | Principle | We will | We will not | Enforced by |\n| --- | --- | --- | --- | --- |\n",
    );
    for (i, p) in PRINCIPLES.iter().enumerate() {
        s.push_str(&format!(
            "| {} | {p} | show the number | hide the number | claims-lint |\n",
            i + 1
        ));
    }
    s.push_str(
        "\n## Honesty tests\n\n1. Does it show real data?\n2. Does it state its limits?\n3. Is anything claimed that was not tested?\n4. Is the safe option the default?\n5. Can the user undo it?\n",
    );
    s
}

const MEASURE_NAMES: [&str; 6] = [
    "Time to first domain in monitor mode",
    "Completion rate of the add-domain wizard",
    "Support-worthy errors per 100 sessions",
    "False-positive appeal rate",
    "Time to unban",
    "Accessibility defects open",
];

fn good_measures() -> String {
    let mut s = String::from(
        "# Measures\n\n## Measures\n\n| Measure | Definition | Data source | Privacy treatment |\n| --- | --- | --- | --- |\n",
    );
    for m in MEASURE_NAMES {
        s.push_str(&format!(
            "| {m} | how it is counted | local counter | no personal data |\n"
        ));
    }
    s
}

fn good_decision(n: u32) -> String {
    format!(
        "# UXD-{n:03}: a decision\n\nStatus: accepted\nDate: 2026-10-19\n\n## Context\n\nwhy\n\n## Decision\n\nwhat\n\n## Consequences\n\nso\n"
    )
}

/// The seven persona documents of B1.1 to B1.7 (T-0012).
const STEMS: [&str; 7] = ["maya", "dan", "sara", "omar", "vi", "alex", "adversary"];

/// Ten registry ids the adversarial fixture maps its abuse stories to.
const ABUSE_ATK_IDS: [&str; 10] = [
    "ATK-001", "ATK-002", "ATK-003", "ATK-004", "ATK-005", "ATK-006", "ATK-007", "ATK-008",
    "ATK-009", "ATK-010",
];

/// Criteria of the B11.11 table as the fixture spec lists them (F-5).
fn b11_11_fixture() -> BTreeSet<String> {
    [
        "1.1.1", "1.3.x", "1.4.3", "1.4.4", "1.4.10", "1.4.11", "2.1.x", "2.4.3", "2.4.7", "3.3.4",
        "3.3.7", "3.3.8", "4.1.2",
    ]
    .iter()
    .map(|criterion| (*criterion).to_owned())
    .collect()
}

/// Journeys each fixture persona names in its `Journeys and screens` list; the fixture spec declares the same ids in
/// `Key journeys` (F-7), except for the adversary (B1.7 has no `Key journeys` row and is exempt).
fn persona_journeys(stem: &str) -> &'static [&'static str] {
    match stem {
        "maya" => &["J-01", "J-02"],
        "dan" => &["J-03"],
        "sara" => &["J-04"],
        "omar" => &["J-05"],
        "vi" => &["J-06"],
        "alex" => &["J-07"],
        _ => &["J-01"],
    }
}

/// One structural persona document that satisfies A1 and A3.
fn good_persona(stem: &str) -> String {
    let mut s = format!(
        "# {stem}\n\n{stem} is a fictional composite, not a real person; source spec B1.1.\n\n\
         ## Context of use\n\n| Aspect | Detail |\n| --- | --- |\n\
         | Device | a laptop |\n| Connectivity | home broadband |\n| Interruptions | phone calls |\n\
         | Vocabulary | plain words |\n| First check of the day | blocked requests |\n\n\
         ## Scenarios\n\n"
    );
    for n in 1..=3 {
        s.push_str(&format!(
            "### {n}. A scenario\n\nWhen Monday comes, I want to see it, so I can decide.\n\
             Measurable outcome: the AC-37 flow is recorded.\n\n"
        ));
    }
    let journeys: Vec<String> = persona_journeys(stem)
        .iter()
        .map(|journey| {
            let number: usize = journey
                .get(2..)
                .and_then(|digits| digits.parse().ok())
                .unwrap_or(0);
            format!("[{journey}](../../SPEC.md#j-{number:02}-journey-{number})")
        })
        .collect();
    s.push_str(&format!(
        "## Anti-goals\n\n- Jargon.\n\n\
         ## Accessibility\n\nMapped to B11.11 criteria: 1.4.4 and 2.1.1.\n\n\
         ## Journeys and screens\n\n- Journeys: {}.\n\
         - Screens: [S-042](../../SPEC.md#s-042-add-domain-wizard).\n",
        journeys.join(", ")
    ));
    if stem == "adversary" {
        s.push_str(
            "\n## Abuse stories\n\n| # | Story | ATK | Design response |\n| --- | --- | --- | --- |\n",
        );
        for (i, id) in ABUSE_ATK_IDS.iter().enumerate() {
            s.push_str(&format!(
                "| {} | an abuse story | {id} | the request is blocked |\n",
                i + 1
            ));
        }
    }
    s
}

/// A matrix that links every journey J-01 to J-34 to a persona; the first seven rows link the persona that owns the
/// journey in the fixture spec (F-7), the rest link Maya.
fn good_matrix() -> String {
    let mut s = String::from(
        "# Persona-journey matrix\n\nQuestion: [which persona is primary for the pilot?](../OPERATOR-QUESTIONS.md#primary-persona-for-the-pilot-added-by-t-0012).\n\n| Journey | Title | Personas | Notes |\n| --- | --- | --- | --- |\n",
    );
    let owners: [(&str, &str, &str); 13] = [
        ("J-01", "Maya", "maya"),
        ("J-02", "Maya", "maya"),
        ("J-03", "Dan", "dan"),
        ("J-04", "Sara", "sara"),
        ("J-05", "Omar", "omar"),
        ("J-06", "Vi", "vi"),
        ("J-07", "Alex", "alex"),
        ("J-13", "Maya", "maya"),
        ("J-14", "Maya", "maya"),
        ("J-15", "Maya", "maya"),
        ("J-16", "Maya", "maya"),
        ("J-17", "Maya", "maya"),
        ("J-18", "Sara", "sara"),
    ];
    for n in 1..=34 {
        let id = format!("J-{n:02}");
        let (name, stem) = owners
            .iter()
            .find(|(journey, _, _)| *journey == id)
            .map(|(_, name, stem)| (*name, *stem))
            .unwrap_or(("Maya", "maya"));
        s.push_str(&format!(
            "| {id} | Journey {n} | [{name}](personas/{stem}.md) | none |\n"
        ));
    }
    s
}

/// The primary-persona question, recorded OPEN with default Maya (A5).
fn good_register() -> String {
    String::from(
        "# Open questions for the operator\n\n## Primary persona for the pilot (added by T-0012)\n\n\
         | Question | Default if unanswered (dev/pilot only) | State | Stored in | Task |\n\
         | --- | --- | --- | --- | --- |\n\
         | Which persona is primary for the pilot? | Maya, the site owner (B1.1) | OPEN: no answer yet; the default applies for development | `docs/UX/personas/maya.md` | T-0012 |\n\n## Questions added by T-0017\n\n| Question | Default | State |\n| --- | --- | --- |\n| Should the monitor-to-block switch use a scheduled switch with typed confirmation? | Scheduled switch with typed confirmation | OPEN |\n| What should the default appeal retention period be, and who may read an appeal? | 30 days; the owner and analysts | OPEN |\n",
    )
}

/// A tiny master specification with the C5 registry rows and the headings the fixtures link to.
fn fake_spec() -> String {
    let mut s = String::from(
        "<!-- PART:C2 -->\n## C5. Attack coverage matrix (390 classes)\n\n\
         | ID | Attack | Vectors | Detection | Act | PL | Ref |\n\
         | --- | --- | --- | --- | --- | --- | --- |\n",
    );
    for id in ABUSE_ATK_IDS {
        s.push_str(&format!(
            "| {id} | an attack | all | a detector | BB | 1 | CWE-89 |\n"
        ));
    }
    s.push_str(
        "\n<!-- PART:B11 -->\n### B11.11 Accessibility contract (summary)\n\n\
         | Criterion | Rule in HDD |\n| --- | --- |\n\
         | 1.1.1 / 1.3.x | text alternatives and structure |\n\
         | 1.4.3 / 1.4.11 | contrast |\n\
         | 1.4.4 / 1.4.10 | resize and reflow |\n\
         | 2.1.x | keyboard |\n\
         | 2.4.3 / 2.4.7 | focus |\n\
         | 3.3.4 | confirmation |\n\
         | 3.3.7 | redundant entry |\n\
         | 3.3.8 | accessible authentication |\n\
         | 4.1.2 | names and roles |\n\
         \n### B11.8 Component inventory\n\n\
         | Component | Contract (summary) |\n| --- | --- |\n\
         | Button / IconButton | Variants primary, secondary and danger. |\n\
         | Link | Underlined in prose. |\n\
         | TextInput / Textarea | Visible label always. |\n\
         | PasswordInput | A show and hide toggle. |\n\
         | OTPInput | A single input with a numeric keyboard. |\n\
         | Select / Combobox / MultiSelect | Native select for simple cases. |\n\
         | Checkbox / Radio / Switch | Native inputs with a text state. |\n\
         | TagInput (IP/CIDR/hostnames) | Validates on commit. |\n\
         | CopyField / CodeBlock | Read-only monospace with a copy button. |\n\
         | FileDropzone | A button-first upload. |\n\
         | FormField / ErrorSummary | Focus moves to the summary. |\n\
         | Card / StatCard | A label and a value. |\n\
         | Badge / StatusDot / SeverityPill | Always an icon and text. |\n\
         | Tooltip / Popover | Description only. |\n\
         | Menu / Dropdown | A menu pattern with roving focus. |\n\
         | Modal / Drawer / ConfirmDialog | A dialog with a focus trap. |\n\
         | Toast | A polite live region. |\n\
         | Banner / Alert | Info, success, warning and danger. |\n\
         | Tabs | Roving tabindex and labelled panels. |\n\
         | Breadcrumbs | A labelled navigation landmark. |\n\
         | Pagination (cursor) | Previous and next with counts. |\n\
         | DataTable | A semantic table with sortable headers. |\n\
         | KeyValueList | Description list semantics. |\n\
         | Timeline | An ordered list with timestamps. |\n\
         | Stepper / Wizard | Ordered steps with a current step. |\n\
         | Skeleton / Spinner / ProgressBar | Explicit loading states. |\n\
         | EmptyState / ErrorState | An explanation and a next action. |\n\
         | CommandPalette | A dialog with a result list. |\n\
         | ThemeToggle / LocaleSwitcher / DensityToggle | Persisted display choices. |\n\
         | NotificationBell | A count in text for screen readers. |\n\
         | RayIDChip | A monospace copyable identifier. |\n\
         | IPChip | An address with a text country code. |\n\
         | CountdownBadge | A remaining time with static text. |\n\
         | PayloadViewer | Redacted evidence with a marked span. |\n\
         | ReadinessRing | A ring with a textual score. |\n\
         | CloudToggle | A proxy toggle with explicit text. |\n\
         | NameserverCard | Two copy fields and a status poller. |\n\
         | VerificationPoller | A server-driven status with a manual check. |\n\
         | LiveFeed (SSE) | A list with a pause control. |\n\
         | ChartKit | Server-rendered SVG with a data table alternative. |\n\
         | WorldMap | A map with a ranked list alternative. |\n\
         | RuleBuilder | Rows of condition fields. |\n\
         | DiffViewer | Side-by-side and unified changes. |\n\
         | MarkdownRender | Sanitised Markdown. |\n\
         | Avatar | Decorative initials. |\n\
         | Kbd | Keyboard key styling. |\n\
         \n### B12.1 Screen table\n\n\
         | ID | Name | Purpose and key content |\n| --- | --- | --- |\n\
         **Public surface**\n\n\
         | S-001 | Landing | A value statement and one action. |\n\
         | S-002 | Features | What the product does. |\n\
         | S-003 | How it works | What is and is not protected. |\n\
         | S-004 | Pricing | Plans and limits. |\n\
         | S-005 | Docs | The documentation index. |\n\
         | S-006 | Docs article | A quickstart page. |\n\
         | S-007 | API reference | The API description. |\n\
         | S-008 | Status | Component status. |\n\
         | S-009 | Contact | The contact form. |\n\
         | S-010 to S-013 | Legal pages | Operator-supplied legal text. |\n\
         | S-014 | Security | The security page. |\n\
         **Authentication and onboarding**\n\n\
         | S-020 | Sign up | An account form. |\n\
         | S-021 | Check your email | The neutral waiting page. |\n\
         | S-022 | Verify email | The confirm button. |\n\
         | S-023 | Log in | Email and password. |\n\
         | S-024 | MFA prompt | The six-digit code. |\n\
         | S-026 | Passkey prompt | The passkey choice. |\n\
         | S-027 | Forgot password | The email form. |\n\
         | S-028 | Reset password | The new password form. |\n\
         | S-029 | Accept invite | Organisation and role. |\n\
         | S-030 | MFA enrol | The QR code and manual key. |\n\
         | S-031 | Recovery codes | The ten codes. |\n\
         | S-034 | Account locked | The lockout page. |\n\
         | S-035 | Onboarding wizard | The first-run tasks. |\n\
         **Customer app: overview and domains**\n\n\
         | S-040 | Org overview | The organisation summary. |\n\
         | S-041 | Domains | The domain list. |\n\
         | S-042 | Add-domain wizard | The eight setup steps. |\n\
         | S-043 | Domain overview | One domain summary. |\n\
         | S-044 | Protection readiness | The readiness checklist. |\n\
         | S-045 | DNS records | The record table. |\n\
         | S-046 | DNS record editor | A type-specific form. |\n\
         | S-047 | DNS import and parity | A source and target diff. |\n\
         | S-048 | DNS change history | The change timeline. |\n\
         | S-051 | Certificates | Certificates and renewal. |\n\
         **DNS, TLS, origin**\n\n\
         | S-050 | TLS | Certificates and mode. |\n\
         | S-052 | Origin | The origin address and health. |\n\
         | S-070 | Analytics | Traffic charts. |\n\
         | S-071 | Geo and ASN | Map with ranked table; ASN table. |\n\
         | S-072 | Top attackers and paths | Top IPs with ban state, paths, rules, categories. |\n\
         **Security center**\n\n\
         | S-054 | Security overview | The protection state. |\n\
         | S-055 | WAF settings | The mode selector. |\n\
         | S-056 | Attack categories | A category matrix. |\n\
         | S-057 | Vulnerable-Origin Shield | The shield settings. |\n\
         | S-058 | Rules | The rule list. |\n\
         | S-059 | Rule builder | The condition editor. |\n\
         | S-060 | Rule dry-run | The replay summary. |\n\
         | S-061 | Rate limiting | The rate limit presets. |\n\
         | S-062 | Bots and challenge | The bot policy. |\n\
         | S-063 | Access lists | The address lists. |\n\
         | S-064 | Exceptions | Scoped exclusions. |\n\
         **Events, bans, appeals, analytics**\n\n\
         | S-065 | Live threat monitor | The live event feed. |\n\
         | S-066 | Event detail | The request decision. |\n\
         | S-067 | IP jail | The active bans. |\n\
         | S-068 | Ban detail | The offence history. |\n\
         | S-069 | Appeals inbox | The appeal list. |\n\
         | S-073 | Reports | The report list. |\n\
         **Reports, notifications, integrations, team**\n\n\
         | S-076 | Alert rules | The alert configuration. |\n\
         | S-078 | Webhooks | Endpoints and secret rotation. |\n\
         | S-079 | Webhook deliveries | Attempts and redeliver. |\n\
         | S-146 | Appeal received | Confirmation with reference. |\n\
         | S-080 | API keys | The key lifecycle. |\n\
         | S-081 | Team members | The member list. |\n\
         | S-084 | Audit log | The audited actions. |\n\
         | S-086 | Org settings | The organisation settings. |\n\
         | S-092 | Config revisions | The revision timeline. |\n\
         | S-093 | Emergency controls (domain) | The domain emergency actions. |\n\
         | S-094 | Decommission domain | The removal wizard. |\n\
         | S-098 | Origin lockdown wizard | The lockdown steps. |\n\
         | S-099 | DNS propagation checker | The resolver matrix. |\n\
         | S-131 | Access gate | The gate rules. |\n\
         | S-134 | Coverage map | Standards and limits. |\n\
         | S-138 | Bypass Guard | The lockdown state. |\n\
         | S-139 | Known vulnerabilities | Matching known issues. |\n\
         **Visitor-facing pages served by the data plane**\n\n\
         | S-140 | Block page | The visitor block page. |\n\
         | S-145 | Appeal form | The appeal form. |\n\
         | S-073 | Reports | The report list. |\n\
         | S-074 | Report builder and schedule | The report schedule. |\n\
         | S-082 | Invitations | Pending invitations. |\n\
         | S-083 | Roles and permissions | The role reference. |\n\
         | S-090 | Data and privacy | Export and deletion. |\n\
         | S-101 | Tenants | The tenant list. |\n\
         **Platform admin surface**\n\n\
         | S-100 | Admin overview | Platform KPIs, service health, queue depth, attack summary, attention list. |\n\
         | S-102 | Tenant detail | One tenant. |\n\
         | S-106 | Global jail | Platform bans. |\n\
         | S-109 | Never-ban and allowlists | The never-ban list. |\n\
         | S-110 | Infra nodes | Nodes and heartbeats. |\n\
         | S-111 | Services and queues | Service health. |\n\
         | S-114 | Abuse reports | Abuse triage. |\n\
         | S-121 | Feature flags and maintenance | Flags and maintenance. |\n\
         | S-122 | Emergency controls | Safe mode and freeze. |\n\
         | S-126 | Virtual patches | Lifecycle, expiry, debt. |\n\
         | S-127 | DDoS readiness and shield | State machine, signals, upstream details, three capacity numbers. |\n\
         \n### B4.2 Permission catalog\n\n\
         | Permission ID | Description |\n| --- | --- |\n\
         | PERM-org.read | View the organisation. |\n\
         | PERM-domain.read | View domains. |\n\
         | PERM-account.self | Manage your own account. |\n\
         | PERM-waf.read | View the WAF configuration. |\n\
         | PERM-platform.tenant.read | View tenants. |\n\
         | PERM-platform.tenant.write | Edit tenants. |\n\
         | PERM-platform.tenant.suspend | Suspend tenants. |\n\
         | PERM-platform.abuse.write | Triage abuse. |\n\
         | PERM-platform.jail.write | Global bans. |\n\
         | PERM-platform.infra.read | View infrastructure. |\n\
         | PERM-platform.emergency | Emergency controls. |\n\
         | PERM-platform.flags.write | Flags and maintenance. |\n\
         \n### B6.1 Conventions\n\n\
         - Rate limit classes: `auth` (strict), `read`, `write`, `export`, `stream`, `public`. Responses carry headers.\n\
         \n### B2.3 Navigation model\n\n\
         - **Top bar**: org switcher, domain switcher, global search / command palette (Ctrl/Cmd+K), notification bell, theme toggle, help menu, user menu.\n\
         - **Keyboard shortcuts** (discoverable with `?`): `g o` overview, `g d` domains, `g e` events, `g b` bans, `/` search, `c` copy focused value, `Esc` close.\n\
         \n### B7. Error catalog\n\n\
         | Code | HTTP | Title | Notes |\n| --- | --- | --- | --- |\n\
         | ERR-AUTH-002 | 401 | Email or password is incorrect | Identical for unknown email. |\n\
         | ERR-AUTH-004 | 429 | Too many attempts | |\n\
         | ERR-AUTH-009 | 400 | Link is invalid or has expired | |\n\
         | ERR-PERM-002 | 404 | Not found | |\n\
         | ERR-SYS-001 | 503 | Service temporarily unavailable | |\n\
         | ERR-VAL-001 | 422 | Invalid request body | |\n\
         \n### B8. Audit event taxonomy\n\n\
         | Event | Fields | Notes |\n| --- | --- | --- |\n\
         | AUD-auth.signup | user, org | Account created. |\n\
         | AUD-auth.email_verified | user | Email confirmed. |\n\
         | AUD-auth.login_success | user | Signed in. |\n\
         | AUD-auth.login_failure | user | Rejected credentials. |\n\
         | AUD-auth.password_reset_requested | user | Reset requested. |\n\
         | AUD-auth.password_reset_completed | user | Reset completed. |\n\
         | AUD-domain.created | domain | Domain created. |\n\
         | AUD-domain.activated | domain | Domain activated. |\n\
         | AUD-dns.parity_acknowledged | domain | Parity acknowledged. |\n\
         | AUD-waf.mode_changed | site | Mode changed. |\n\
         | AUD-waf.rule_created | rule | Rule created. |\n\
         | AUD-ratelimit.rule_changed | rule | Rate limit changed. |\n\
         | AUD-notify.channel_created | channel | Alert channel created. |\n\
         | AUD-webhook.created | webhook | Webhook created. |\n\
         | AUD-appeal.submitted | appeal | Appeal submitted. |\n\
         | AUD-appeal.resolved | appeal | Appeal resolved. |\n\
         | AUD-origin.lockdown_applied | site | Lockdown marked applied. |\n\
         | AUD-bypass.probe_run | site | Verification probe executed. |\n\
         | AUD-ban.created | site | Ban created. |\n\
         | AUD-member.invited | member | Invited. |\n\
         | AUD-apikey.created | key | Created. |\n\
         | AUD-report.run | report | Run. |\n\
         | AUD-platform.tenant_plan_changed | tenant | Plan changed. |\n\
         | AUD-platform.support_lookup | tenant | Support lookup. |\n\
         | AUD-ban.global_created | ip | Global ban created. |\n\
         | AUD-platform.never_ban_changed | cidr | Never-ban changed. |\n\
         | AUD-platform.emergency_used | action | Emergency used. |\n\
         | AUD-platform.flag_changed | flag | Flag changed. |\n\
         | AUD-domain.decommissioned | domain | Decommissioned. |\n\
         | AUD-auth.data_export_requested | user | Export requested. |\n\
         | AUD-waf.under_attack_on | site | Under attack on. |\n\
         | AUD-auth.stepup | user | Step-up. |\n\
         \n### J-01 Visitor discovers HDD and reads honest claims\n\
         Persona Maya. Steps: (1) lands on S-001 and reads the value statement; (2) opens S-003; (3) opens a docs quickstart; (4) clicks 'Create account'. Success: reaches S-020 in three clicks. Check: AC-40, AC-41, claims-lint.\n\
         \n### J-02 Visitor signs up and verifies email\n\
         Persona Maya. Steps: S-020, S-021, S-022, S-035. Success: account active. Check: AC-35, AC-46.\n\
         \n### J-03 New user enrolls MFA\n\
         Persona any. Steps: S-030, S-031. Success: MFA active. Check: AC-35.\n\
         \n### J-04 Returning user logs in\n\
         Steps: S-023, S-024, S-026, S-034. Success: signed in. Check: AC-35.\n\
         \n### J-05 User resets a forgotten password\n\
         Steps: S-027, S-028. Success: password changed. Check: AC-35, AC-46.\n\
         \n### J-06 User accepts a team invite\n\
         Steps: S-029. Success: membership created. Check: AC-35, AC-36.\n\
         \n### J-08 Owner adds a domain using full nameserver delegation\n\
         Steps: S-042. Success: domain active. Check: AC-37.\n\
         \n### J-07 Owner completes the onboarding checklist\n\
         Persona Maya. Steps: S-035, S-040. Success: first domain started. Check: AC-37.\n\
         \n### J-08 Owner adds a domain using full nameserver delegation\n\
         Steps (S-042): S-042. Success: domain active. Check: AC-37, AC-02, AC-03.\n\
         \n### J-09 Owner adds a domain using CNAME (partial) setup\n\
         Steps: as J-08. Success: www proxied. Check: AC-37.\n\
         \n### J-10 Owner attaches an apex via A/ALIAS or only a subdomain\n\
         Steps: wizard. Check: AC-37.\n\
         \n### J-11 Owner verifies ownership\n\
         Steps: S-042. Check: AC-37.\n\
         \n### J-12 Owner configures and tests the origin\n\
         Steps: S-052. Check: AC-17, AC-37.\n\
         \n### J-13 Owner imports existing DNS and resolves parity warnings\n\
         Steps: S-047. Success: parity clean. Check: AC-02.\n\
         \n### J-14 Owner edits DNS and toggles orange/grey\n\
         Steps: S-045, S-046, S-048. Check: AC-03.\n\
         \n### J-15 Owner issues TLS and enables HSTS\n\
         Steps: S-050, S-051. Check: AC-04.\n\
         \n### J-16 Owner enables protection in monitor mode, reviews, switches to block\n\
         Steps: S-054, S-065, S-066, S-064. Check: AC-06, AC-13.\n\
         \n### J-17 Owner enables the Vulnerable-Origin Shield\n\
         Steps: S-057. Check: AC-38, AC-39.\n\
         \n### J-18 Analyst investigates an attack\n\
         Steps: S-065, S-066. Check: AC-07, AC-08.\n\
         \n### J-19 Owner builds a custom rule\n\
         Steps: S-059, S-060. Success: the rule is saved. Check: AC-12, AC-13.\n\
         \n### J-20 Owner configures rate limits for login\n\
         Steps: S-061. Success: the limit is applied. Check: AC-11.\n\
         \n### J-21 Owner configures alerts and webhooks\n\
         Steps: S-076, S-078, S-079. Success: the channel is tested. Check: AC-45.\n\
         \n### J-22 Blocked visitor files an appeal\n\
         Steps: S-140, S-145, S-146. Success: the appeal is received. Check: AC-43.\n\
         \n### J-23 Owner handles an appeal\n\
         Steps: S-069. Success: the appeal is resolved. Check: AC-43.\n\
         \n### J-24 Owner locks down the origin\n\
         Steps: S-098. Success: the lockdown is applied. Check: AC-18.\n\
         \n<!-- PART:B1 -->\n# PART B: PRODUCT DEFINITION\n\n\
         ### B1.1 A source persona\n\n| Attribute | Detail |\n| --- | --- |\n| Key journeys | J-01, J-02 |\n\n\
         ### B1.2 A second persona\n\n| Key journeys | J-03 |\n\n\
         ### B1.3 A third persona\n\n| Key journeys | J-04 |\n\n\
         ### B1.4 A fourth persona\n\n| Key journeys | J-05 |\n\n\
         ### B1.5 A fifth persona\n\n| Key journeys | J-06 |\n\n\
         ### B1.6 A sixth persona\n\n| Key journeys | J-07 |\n\n\
         ### B1.7 A seventh persona\n\
         ### J-01 Journey 1\n### J-02 Journey 2\n### J-03 Journey 3\n### J-04 Journey 4\n\
         ### J-05 Journey 5\n### J-06 Journey 6\n### J-07 Journey 7\n\
         #### S-042 Add-domain wizard\n",
    );
    s.push_str(
        "\n### J-25 Owner views Protection Readiness and fixes items\n\
         Steps: S-044. Check: AC-53.\n\
         \n### J-26 Owner invites teammates and assigns roles\n\
         Steps: S-081, S-082, S-083. Check: AC-36.\n\
         \n### J-27 Developer creates an API key and uses the API\n\
         Steps: S-080. Check: AC-35, AC-45.\n\
         \n### J-28 Owner exports reports and audit logs\n\
         Steps: S-073, S-074, S-084. Check: AC-47.\n\
         \n### J-29 Platform admin onboards and manages tenants\n\
         Steps: S-101, S-102. Check: AC-42.\n\
         \n### J-30 Platform admin investigates abuse and global bans\n\
         Steps: S-114, S-106, S-109. Check: AC-51.\n\
         \n### J-31 Platform admin toggles safe mode, maintenance, checks infra\n\
         Steps: S-110, S-111, S-122, S-121. Check: AC-13, AC-42.\n\
         \n### J-32 Owner removes a domain safely\n\
         Steps: S-094. Check: AC-37.\n\
         \n### J-33 User exports data or deletes the account\n\
         Steps: S-090. Check: AC-47.\n\
         \n### J-34 Incident: attack spike\n\
         Steps: S-054, S-093. Check: AC-44, AC-27.\n\
         \n<!-- PHASE:P00 -->\n\
         ## PHASE P00: Fixture phase (T-0001 to T-0004) · milestone M0 · gate G00\n\n\
         ### T-0001 · First fixture task\n\
         `P00` `[DOC]` · deps: none · size: S · owner: docs\n\
         The first fixture task.\n\
         \n### T-0002 · Second fixture task\n\
         `P00` `[DOC]` · deps: T-0001 · size: S · owner: docs\n\
         The second fixture task.\n\
         \n### T-0003 · Third fixture task\n\
         `P00` `[DOC]` · deps: T-0001 · size: S · owner: docs\n\
         The third fixture task.\n\
         \n### T-0004 · Fourth fixture task\n\
         `P00` `[DOC]` · deps: T-0003 · size: S · owner: docs\n\
         The fourth fixture task.\n",
    );
    s.push_str(content::fixtures::b13_spec_section());
    s.push_str(&responsive::fixtures::spec_section());
    s.push_str(&dataviz::fixtures::spec_section());
    s.push_str(&onboarding::fixtures::spec_section());
    s.push_str(&security_ux::fixtures::spec_section());
    s.push_str(&errors::fixtures::spec_section());
    s.push_str(&i18n_plan::fixtures::spec_section());
    s
}

/// Write the fixture master specification and its checksum.
fn put_spec(r: &Repo, spec: &str) {
    r.put("docs/SPEC.md", spec);
    r.put(
        "docs/SPEC.sha256",
        &format!(
            "{}  docs/SPEC.md\n",
            crate::util::sha256_hex(spec.as_bytes())
        ),
    );
}

/// Topic names of the T-0013 pattern fixture; each heading gives a `topic-...` anchor for the requirements.
const TOPIC_NAMES: [&str; 12] = [
    "Onboarding",
    "DNS import",
    "Proxy toggles",
    "WAF modes",
    "Event logs",
    "Rule builders",
    "Bans",
    "Analytics",
    "API keys",
    "Team management",
    "Appeals",
    "Notifications",
];

/// The anchor a `## Topic: <name>` heading of `patterns_fixture` offers.
fn fixture_anchor(name: &str) -> String {
    format!("topic-{}", slug(name))
}

/// A pattern review fixture that satisfies T-0013 A1, A2 and A5 (twelve topics, first principles, UNVERIFIED status).
fn patterns_fixture() -> String {
    let mut s = String::from(
        "# Pattern review\n\n\
         Status: UNVERIFIED(capability_not_supplied) - the fixture has no fetched source.\n\n\
         ## Review questions\n\n- How does a console present onboarding?\n\n",
    );
    for name in TOPIC_NAMES {
        s.push_str(&format!(
            "## Topic: {name}\n\n\
             Source: first principles\n\n\
             Problem: The owner does not know which record changes.\n\n\
             Common solutions: A wizard scans the records first.\n\n\
             Pitfalls: The import drops a mail record.\n\n\
             Accessibility and clarity pitfalls: Color-only status, jargon, destructive action without preview, hidden self-lockout risk.\n\n"
        ));
    }
    s.push_str(
        "## Non-goals\n\n- Copying another product's wording.\n\n\
         ## Honesty-test review\n\n\
         | # | Honesty test | Answer | Reason |\n| --- | --- | --- | --- |\n\
         | 1 | Real data only | Yes | The fixture shows no data. |\n\
         | 2 | Limits stated | Yes | The status line names the limitation. |\n\
         | 3 | Claims backed | Yes | Every row links a topic. |\n\
         | 4 | Safe option first | Yes | The fixture keeps the safe option first. |\n\
         | 5 | Undo stated | Yes | The fixture asks for an undo path. |\n",
    );
    s
}

/// A design requirements fixture with DR-01 to DR-20 (T-0013 A4).
fn design_requirements_fixture() -> String {
    let mut s = String::from(
        "# Design requirements\n\n## Requirements\n\n\
         | DR | Requirement | Rationale | Pattern topic | Screens and components |\n\
         | --- | --- | --- | --- | --- |\n",
    );
    let targets = [
        "S-042, Stepper",
        "S-042, ConfirmDialog",
        "S-045, DataTable",
        "S-054, StatusDot",
        "S-054, Banner",
        "S-065, LiveFeed",
        "S-066, PayloadViewer",
        "S-067, CountdownBadge",
        "S-067, IPChip",
        "S-058, RuleBuilder",
        "S-059, RuleBuilder",
        "S-073, ChartKit",
        "S-080, CopyField",
        "S-081, DataTable",
        "S-086, ConfirmDialog",
        "S-092, DiffViewer",
        "S-093, ConfirmDialog",
        "S-094, ConfirmDialog",
        "S-131, PasswordInput",
        "S-140, Button",
    ];
    for number in 1..=DESIGN_REQUIREMENTS {
        let topic = TOPIC_NAMES[(number - 1) % TOPIC_NAMES.len()];
        let target = targets[(number - 1) % targets.len()];
        s.push_str(&format!(
            "| DR-{number:02} | Requirement {number} states the change before it happens. | Rationale {number} keeps the owner in control. | [{topic}](PATTERNS.md#{}) | {target} |\n",
            fixture_anchor(topic)
        ));
    }
    s
}

/// One `[[route]]` entry of the T-0014 fixture.
fn route_entry(
    pattern: &str,
    screen: &str,
    surface: &str,
    permission: &str,
    methods: &[&str],
    class: &str,
) -> String {
    let methods = methods
        .iter()
        .map(|method| format!("\"{method}\""))
        .collect::<Vec<_>>()
        .join(", ");
    format!(
        "[[route]]\npattern = \"{pattern}\"\nscreen = \"{screen}\"\nsurface = \"{surface}\"\npermission = \"{permission}\"\nmethods = [{methods}]\nrate_limit_class = \"{class}\"\n\n"
    )
}

/// A route table fixture that covers every screen of `fake_spec`: shared screens get their two B2.2 paths and visitor
/// screens are marked by the data-plane note (T-0014 A1).
fn routes_fixture() -> String {
    let screens = screen_ids(&fake_spec());
    let mut s = String::from("# Route table fixture for the ux-docs tests.\n\n");
    let mut data_plane: Vec<String> = Vec::new();
    for screen in &screens {
        if DATA_PLANE_SCREENS.contains(&screen.as_str()) {
            data_plane.push(screen.clone());
            continue;
        }
        let copies = if SHARED_SCREENS.contains(&screen.as_str()) {
            2
        } else {
            1
        };
        for copy in 0..copies {
            let suffix = if copies == 2 {
                format!("-{}", if copy == 0 { "a" } else { "b" })
            } else {
                String::new()
            };
            s.push_str(&route_entry(
                &format!("/page-{}{suffix}", screen.to_lowercase()),
                screen,
                "public",
                "public",
                &["GET"],
                "public",
            ));
        }
    }
    if !data_plane.is_empty() {
        let note = data_plane.join(", ");
        s.push_str(&format!(
            "[[route]]\npattern = \"/{{path}}\"\nscreen = \"data-plane\"\nsurface = \"data-plane\"\npermission = \"public\"\nmethods = [\"GET\", \"HEAD\"]\nrate_limit_class = \"public\"\nnote = \"Data-plane responses: {note}.\"\n\n\
             [[route]]\npattern = \"/{{path}}\"\nscreen = \"data-plane\"\nsurface = \"data-plane\"\npermission = \"public\"\nmethods = [\"POST\", \"PUT\", \"PATCH\", \"DELETE\"]\nrate_limit_class = \"write\"\nnote = \"Data-plane responses for mutating methods: {note}.\"\n"
        ));
    }
    s.push_str(&route_entry(
        "/fixture-domain-settings",
        "support",
        "public",
        "public",
        &["GET"],
        "public",
    ));
    s
}

/// An information architecture fixture with every section T-0014 requires.
fn ia_fixture() -> String {
    String::from(
        "# Information architecture (fixture)\n\n\
         ## Surfaces and hosts\n\nSix surfaces are listed in the fixture spec.\n\n\
         ## URL rules\n\n\
         - Every path segment is lowercase.\n  Test: an uppercase letter fails the route check.\n\
         - Words are separated by hyphens.\n  Test: an underscore outside a placeholder fails the check.\n\
         - No trailing slash except the root.\n  Test: a trailing slash fails the check.\n\
         - Identifiers are prefixed and stable.\n  Test: the identifier regex matches the worked example.\n\
         - No email and no secret appears in a path.\n  Test: an email placeholder fails the check.\n\
         - Query parameters carry filters and deep links only.\n  Test: a question mark in a pattern fails the check.\n\
         - Canonical redirects are permanent and single hop.\n  Test: each redirect has one source and one target.\n\
         - The reserved prefix is the only underscore in a pattern.\n  Test: the underscore rule exempts the reserved prefix.\n\n\
         ## Identifier format\n\n\
         Regex: `^(org|dom|usr|rule|ban|evt|whk|key|cert|rpt|inv|apl)_[a-z2-7]{26}$`\n\n\
         Example: `org_ab2cd3ef4gh5jk6mn7pq2rs3tu`\n\n\
         ## Deep linking\n\nTabs, wizard steps and filters live in the query string.\n\n\
         ## Redirects\n\nA return URL must be a same-origin path; a slug change redirects for 30 days.\n\n\
         ## Not found and forbidden\n\nA cross-tenant resource answers 404 with the not-found page.\n\n\
         ## Titles and headings\n\nOne h1 per page; the title names the screen, domain and organisation.\n\n\
         ## Token routes\n\n\
         - `/verify-email/{token}`\n- `/reset-password/{token}`\n- `/invite/{token}`\n\
         - `/.well-known/acme-challenge/{token}`\n- `/.well-known/hdd-verification/{token}`\n\n\
         ## Permission rule\n\nThe permission of a route is the permission of the screen's primary data-source endpoint.\n\n\
         ## Assumptions\n\nWhere the specification is silent, the conservative choice is recorded here.\n",
    )
}

/// The spec registries and IA token list the fixture route checks use.
fn fixture_route_sets() -> (
    BTreeSet<String>,
    BTreeSet<String>,
    BTreeSet<String>,
    BTreeSet<String>,
) {
    let spec = fake_spec();
    (
        screen_ids(&spec),
        permission_ids(&spec),
        rate_limit_classes(&spec),
        token_route_patterns(&ia_fixture()),
    )
}

fn routes_messages(text: &str) -> String {
    let (screens, permissions, classes, tokens) = fixture_route_sets();
    messages(&routes_findings5(
        text,
        &screens,
        &permissions,
        &classes,
        &tokens,
    ))
}

/// The five-argument form the T-0014 tests use; the F-10 tests pass the exception map explicitly.
fn routes_findings5(
    text: &str,
    screens: &BTreeSet<String>,
    permissions: &BTreeSet<String>,
    classes: &BTreeSet<String>,
    tokens: &BTreeSet<String>,
) -> Vec<Finding> {
    routes_findings(
        text,
        screens,
        permissions,
        classes,
        tokens,
        &BTreeMap::new(),
    )
}

fn good_tree(r: &Repo) {
    r.put("docs/UX/CHARTER.md", &good_charter());
    r.put("docs/UX/MEASURES.md", &good_measures());
    for n in 1..=3 {
        r.put(
            &format!("docs/UX/decisions/UXD-{n:03}.md"),
            &good_decision(n),
        );
    }
    r.put(
        "AGENTS.md",
        "# Agents\n\nSee [the charter](docs/UX/CHARTER.md).\n",
    );
    for stem in STEMS {
        r.put(&format!("docs/UX/personas/{stem}.md"), &good_persona(stem));
    }
    r.put("docs/UX/persona-journey-matrix.md", &good_matrix());
    r.put("docs/OPERATOR-QUESTIONS.md", &good_register());
    r.put("docs/UX/PATTERNS.md", &patterns_fixture());
    r.put(
        "docs/UX/design-requirements.md",
        &design_requirements_fixture(),
    );
    r.put("docs/UX/IA.md", &ia_fixture());
    r.put("docs/UX/routes.toml", &routes_fixture());
    r.put("docs/UX/NAVIGATION.md", &navigation_fixture());
    for journey in &FIXTURE_JOURNEYS {
        let mut text = journey_fixture(journey);
        if journey.id == "J-25" {
            // T-0026 step 2: the J-25 readiness table must agree with the fixture readiness model.
            text = onboarding::fixtures::journey_j25(&text);
        }
        r.put(&format!("docs/UX/journeys/{}.md", journey.id), &text);
    }
    r.put("docs/UX/spec-patches.md", &spec_patches_fixture());
    r.put(
        "docs/UX/journey-dependencies.md",
        &journey_dependencies_fixture(),
    );
    r.put("docs/UX/CONTENT.md", &content::fixtures::content());
    r.put("docs/UX/glossary.md", &content::fixtures::glossary());
    r.put("i18n/glossary.md", &content::fixtures::glossary());
    r.put("i18n/en/copy-deck.ftl", content::fixtures::copy_deck());
    for (path, text) in a11y::fixtures::documents() {
        r.put(&path, &text);
    }
    for (path, text) in responsive::fixtures::documents() {
        r.put(&path, &text);
    }
    for (path, text) in dataviz::fixtures::documents() {
        r.put(&path, &text);
    }
    for (path, text) in onboarding::fixtures::documents() {
        r.put(&path, &text);
    }
    for (path, text) in security_ux::fixtures::documents() {
        r.put(&path, &text);
    }
    for (path, text) in errors::fixtures::documents() {
        r.put(&path, &text);
    }
    for (path, text) in i18n_plan::fixtures::documents() {
        r.put(&path, &text);
    }
    put_spec(r, &fake_spec());
}

/// A navigation fixture that satisfies T-0015 A1 to A5 against `routes_fixture`.
fn navigation_fixture() -> String {
    String::from(
        "# Navigation model (fixture)\n\n\
         ## Navigation elements\n\n\
         ```text\n+------------------------------+\n| Org sidebar | main content   |\n+------------------------------+\n```\n\n\
         | Element | Route | Permission | Keyboard | ARIA role | Notes |\n\
         | --- | --- | --- | --- | --- | --- |\n\
         | Sidebar · Overview | /page-s-040 | public | Tab, Enter | navigation | Current item carries aria-current. |\n\
         | Sidebar · Domains | /page-s-041 | public | Tab, Enter | navigation | |\n\
         | Sidebar · Live events | /page-s-065-a | public | Tab, Enter | navigation | |\n\
         | Sidebar · Bans | /page-s-067-a | public | Tab, Enter | navigation | |\n\
         | Sidebar · Analytics | /page-s-070-a | public | Tab, Enter | navigation | |\n\
         | Sidebar · Reports | /page-s-073 | public | Tab, Enter | navigation | |\n\
         | Sidebar · Notifications | /page-s-076 | public | Tab, Enter | navigation | |\n\
         | Sidebar · Integrations | /page-s-080 | public | Tab, Enter | navigation | |\n\
         | Sidebar · Team | /page-s-081 | public | Tab, Enter | navigation | |\n\
         | Sidebar · API keys | /page-s-080 | public | Tab, Enter | navigation | |\n\
         | Sidebar · Audit log | /page-s-084 | public | Tab, Enter | navigation | |\n\
         | Sidebar · Plan and usage | /page-s-086 | public | Tab, Enter | navigation | |\n\
         | Sidebar · Settings | /page-s-086 | public | Tab, Enter | navigation | |\n\
         | Tab · Overview | /page-s-043 | public | Arrow keys, Home, End | tab | The tab list is one stop in the tab order. |\n\
         | Tab · DNS | /page-s-045 | public | Arrow keys, Home, End | tab | |\n\
         | Tab · SSL/TLS | /page-s-050 | public | Arrow keys, Home, End | tab | |\n\
         | Tab · Security | /page-s-054 | public | Arrow keys, Home, End | tab | |\n\
         | Tab · Origin | /page-s-052 | public | Arrow keys, Home, End | tab | |\n\
         | Tab · Events | /page-s-065-a | public | Arrow keys, Home, End | tab | |\n\
         | Tab · Bans | /page-s-067-a | public | Arrow keys, Home, End | tab | |\n\
         | Tab · Analytics | /page-s-070-a | public | Arrow keys, Home, End | tab | |\n\
         | Tab · Settings | /fixture-domain-settings | public | Arrow keys, Home, End | tab | |\n\
         | Top bar · Org switcher | - | - | Enter opens, arrow keys move | button | Opened by keyboard; hover is not required. |\n\
         | Top bar · Domain switcher | - | - | Enter opens, type-ahead | combobox | |\n\
         | Top bar · Search / command palette | - | - | Ctrl/Cmd+K | button | |\n\
         | Top bar · Notification bell | - | - | Tab, Enter | button | |\n\
         | Top bar · Theme toggle | - | - | Tab, Enter | button | |\n\
         | Top bar · Help menu | - | - | Tab, Enter | menu | |\n\
         | Top bar · User menu | - | - | Tab, Enter | menu | |\n\n\
         ## Org and domain switchers\n\nType-ahead matches on the name; recent items are listed first; an empty state offers creating an organisation or adding a domain.\n\n\
         ## Breadcrumbs\n\nAt most four levels, with the middle levels collapsed into a menu on narrow screens and the current page carrying aria-current=\"page\".\n\n\
         ## Command palette and shortcuts\n\n\
         ```text\n+-----------------------------------+\n| Search or run a command          |\n+-----------------------------------+\n```\n\n\
         | Keys | Action | Scope |\n| --- | --- | --- |\n\
         | `g o` | Go to Overview | Global |\n\
         | `g d` | Go to Domains | Global |\n\
         | `g e` | Go to Events | Global |\n\
         | `g b` | Go to Bans | Global |\n\
         | `/` | Focus search | Global |\n\
         | `c` | Copy the focused value | Global |\n\
         | `Esc` | Close the current overlay | Global |\n\
         | `?` | Open the shortcut list | Global |\n\
         | `Ctrl/Cmd+K` | Open the command palette | Global |\n\n\
         ### Reserved by browsers and assistive technology\n\n\
         | Keys | Why it is reserved |\n| --- | --- |\n\
         | Ctrl/Cmd+R | Reload |\n| Ctrl/Cmd+T | New tab |\n| Ctrl/Cmd+W | Close tab |\n\
         | Ctrl/Cmd+N | New window |\n| Ctrl/Cmd+P | Print |\n| Ctrl/Cmd+F | Find |\n\
         | Ctrl/Cmd+L | Address bar |\n| Ctrl/Cmd+D | Bookmark |\n| F5 | Reload |\n\
         | F6 | Address bar |\n| Ctrl/Cmd+Plus | Zoom in |\n| Shift+Tab | Reverse focus |\n\n\
         The shortcut map is a convenience, never the only path; every function is reachable from a control in the elements table. Single-letter shortcuts do not fire while a text field has focus; the shortcut list has a switch that turns them off.\n\n\
         ## Documented conflicts\n\n\
         | Keys | Owner of the default | Effect | Mitigation |\n\
         | --- | --- | --- | --- |\n\
         | `Ctrl/Cmd+K` | The browser address or search bar. | The browser may open its own search instead of the palette. | The Search / command palette button opens the palette; shortcuts can be turned off in preferences. |\n\
         | `/` | The browser quick find. | The search field may not receive focus. | The Search / command palette button opens the search; shortcuts can be turned off in preferences. |\n\
         | `g`, `c`, `?` | The screen reader browse mode. | The keys reach the page only in focus mode. | The Sidebar · Domains item and the copy control give the same functions; shortcuts can be turned off in preferences. |\n\n\
         ## Restricted items\n\n\
         | State | When | Display | Example |\n| --- | --- | --- | --- |\n\
         | permission-hidden | The role has no concept of the feature. | Hidden from the sidebar and the palette. | An analyst never sees platform administration. |\n\
         | plan-limited | The feature exists but the plan lacks it. | Shown with a short explanation and the upgrade path. | Audit export on a lower plan. |\n\n\
         ## Admin surface\n\nA persistent platform-admin band, an accent that works without colour, and its own sidebar; the band is a text label as well.\n\n\
         ```text\n+== Platform admin ================+\n| Tenants | Users | Runtime       |\n+==================================+\n```\n\n\
         ## Focus management\n\n\
         ### Full page loads\n\nFocus moves to the new h1 or the first heading; the title is announced through the document title and the heading.\n\n\
         ### Partial swaps\n\nAfter an HTMX swap focus moves to the changed region and a polite live region announces the change; scroll position is preserved.\n\n\
         ## Mobile\n\n\
         ### 360 px\n\nThe sidebar becomes a drawer opened by a labelled button; the domain tabs scroll horizontally; breadcrumbs collapse to one parent.\n\n\
         ### 480 px\n\nThe drawer stays; the top bar gains the search field; the domain tabs keep the horizontal scroll.\n\n\
         ### 768 px\n\nThe sidebar is an overlay drawer; the breadcrumbs show two levels; the domain tabs wrap.\n\n\
         ```text\n+----------------------------------+\n| [menu] Site name   [bell] [user]|\n+----------------------------------+\n```\n\n\
         ## Review checklist\n\n- Does every element have a keyboard path and a role? Yes (T-0138).\n- Is focus handled on full loads and swaps? Yes (T-0151).\n",
    )
}

/// Pattern to permission map of the fixture route table, for the navigation cross-check.
fn fixture_route_permissions() -> BTreeMap<String, String> {
    let file: RoutesFile = toml::from_str(&routes_fixture()).expect("fixture routes parse");
    file.route
        .iter()
        .map(|route| (route.pattern.clone(), route.permission.clone()))
        .collect()
}

/// Findings of the fixture navigation text against the fixture route table and the fixture spec B2.3 shortcuts.
fn navigation_messages(text: &str) -> String {
    messages(&navigation_findings(
        text,
        &fixture_route_permissions(),
        &shortcut_list(&fake_spec()),
    ))
}

/// One fixture journey: its steps and, for J-08/J-09, the cutover-safety rows.
struct FixtureJourney {
    id: &'static str,
    title: &'static str,
    persona: &'static str,
    screens: &'static [&'static str],
    actions: &'static [&'static str],
    acs: &'static str,
    atk: &'static str,
    auds: &'static str,
    cutover: bool,
    measures: bool,
}

const SAFEGUARD_ACTIONS: [&str; 8] = [
    "Changes the DNS record after the preview.",
    "Changes the DNS record after the preview.",
    "Changes the DNS record after the preview.",
    "Changes the DNS record after the preview.",
    "Changes the DNS record after the preview.",
    "Changes the DNS record after the preview.",
    "Changes the DNS record after the preview.",
    "Changes the DNS record after the preview.",
];

const FIXTURE_JOURNEYS: [FixtureJourney; 34] = [
    FixtureJourney {
        id: "J-01",
        title: "Visitor discovers HDD and reads honest claims",
        persona: "Maya",
        screens: &[
            "S-001", "S-001", "S-003", "S-003", "S-006", "S-006", "S-006", "S-020",
        ],
        actions: &[],
        acs: "AC-40, AC-41",
        atk: "ATK-001",
        auds: "AUD-auth.signup",
        cutover: false,
        measures: false,
    },
    FixtureJourney {
        id: "J-02",
        title: "Visitor signs up and verifies email",
        persona: "Maya",
        screens: &[
            "S-020", "S-021", "S-021", "S-022", "S-022", "S-022", "S-022", "S-035",
        ],
        actions: &[],
        acs: "AC-35, AC-46",
        atk: "ATK-002",
        auds: "AUD-auth.signup, AUD-auth.email_verified",
        cutover: false,
        measures: false,
    },
    FixtureJourney {
        id: "J-03",
        title: "New user enrolls MFA",
        persona: "Dan",
        screens: &[
            "S-030", "S-030", "S-030", "S-031", "S-031", "S-031", "S-030", "S-031",
        ],
        actions: &[],
        acs: "AC-35",
        atk: "ATK-003",
        auds: "AUD-auth.login_success",
        cutover: false,
        measures: false,
    },
    FixtureJourney {
        id: "J-04",
        title: "Returning user logs in",
        persona: "Sara",
        screens: &[
            "S-023", "S-023", "S-024", "S-024", "S-026", "S-026", "S-023", "S-034",
        ],
        actions: &[],
        acs: "AC-35",
        atk: "ATK-004",
        auds: "AUD-auth.login_success, AUD-auth.login_failure",
        cutover: false,
        measures: false,
    },
    FixtureJourney {
        id: "J-05",
        title: "User resets a forgotten password",
        persona: "Omar",
        screens: &[
            "S-027", "S-027", "S-027", "S-028", "S-028", "S-028", "S-027", "S-028",
        ],
        actions: &[],
        acs: "AC-35, AC-46",
        atk: "ATK-005",
        auds: "AUD-auth.password_reset_requested, AUD-auth.password_reset_completed",
        cutover: false,
        measures: false,
    },
    FixtureJourney {
        id: "J-06",
        title: "User accepts a team invite",
        persona: "Vi",
        screens: &[
            "S-029", "S-029", "S-020", "S-020", "S-023", "S-023", "S-029", "S-029",
        ],
        actions: &[],
        acs: "AC-35, AC-36",
        atk: "ATK-006",
        auds: "AUD-auth.signup, AUD-auth.login_success",
        cutover: false,
        measures: false,
    },
    FixtureJourney {
        id: "J-07",
        title: "Owner completes the onboarding checklist",
        persona: "Alex",
        screens: &[
            "S-035", "S-035", "S-035", "S-040", "S-040", "S-040", "S-040", "S-040",
        ],
        actions: &[],
        acs: "AC-37",
        atk: "ATK-007",
        auds: "AUD-auth.signup",
        cutover: false,
        measures: false,
    },
    FixtureJourney {
        id: "J-08",
        title: "Owner adds a domain using full nameserver delegation",
        persona: "Maya",
        screens: &[
            "S-042", "S-042", "S-042", "S-042", "S-042", "S-042", "S-042", "S-042", "S-042",
            "S-042", "S-099", "S-043",
        ],
        actions: &[
            "Enters the domain in the add-domain wizard.",
            "Reviews the DNS scan of the existing zone.",
            "Chooses the HDD nameservers.",
            "Reviews the imported records and proxy toggles.",
            "Proves ownership with a DNS TXT record.",
            "Configures the origin and tests connectivity.",
            "Reviews the TLS pre-issuance plan.",
            "Chooses the monitor preset.",
            "Copies the two nameservers and waits for delegation.",
            "Reads the go-live checklist and the rollback instructions.",
            "Checks DNS propagation.",
            "Confirms the domain is active.",
        ],
        acs: "AC-37, AC-02, AC-03",
        atk: "ATK-008",
        auds: "AUD-auth.signup",
        cutover: true,
        measures: true,
    },
    FixtureJourney {
        id: "J-09",
        title: "Owner adds a domain using CNAME (partial) setup",
        persona: "Maya",
        screens: &[
            "S-042", "S-042", "S-042", "S-042", "S-042", "S-042", "S-042", "S-042", "S-042",
            "S-042", "S-099", "S-043",
        ],
        actions: &[
            "Enters the domain in the add-domain wizard.",
            "Reviews the DNS scan of the existing zone.",
            "Keeps the DNS provider and points www with a CNAME.",
            "Reviews the proxy toggles and the verification record.",
            "Proves ownership with a DNS TXT record.",
            "Configures the origin and tests connectivity.",
            "Reviews the TLS pre-issuance plan and the optional CNAME.",
            "Chooses the monitor preset.",
            "Copies the CNAME and waits for resolution.",
            "Reads the go-live checklist and the rollback instructions.",
            "Checks DNS propagation.",
            "Confirms the domain is active.",
        ],
        acs: "AC-37",
        atk: "ATK-009",
        auds: "AUD-auth.signup",
        cutover: true,
        measures: true,
    },
    FixtureJourney {
        id: "J-10",
        title: "Owner attaches an apex via A/ALIAS or only a subdomain",
        persona: "Maya",
        screens: &[
            "S-042", "S-042", "S-042", "S-042", "S-042", "S-042", "S-042", "S-042",
        ],
        actions: &[],
        acs: "AC-37",
        atk: "ATK-010",
        auds: "AUD-auth.signup",
        cutover: false,
        measures: false,
    },
    FixtureJourney {
        id: "J-11",
        title: "Owner verifies ownership",
        persona: "Maya",
        screens: &[
            "S-042", "S-042", "S-042", "S-042", "S-042", "S-042", "S-042", "S-042",
        ],
        actions: &[],
        acs: "AC-37",
        atk: "ATK-005",
        auds: "AUD-auth.signup",
        cutover: false,
        measures: false,
    },
    FixtureJourney {
        id: "J-12",
        title: "Owner configures and tests the origin",
        persona: "Maya",
        screens: &[
            "S-052", "S-052", "S-052", "S-052", "S-052", "S-052", "S-052", "S-043",
        ],
        actions: &[],
        acs: "AC-17, AC-37",
        atk: "ATK-006",
        auds: "AUD-auth.signup",
        cutover: false,
        measures: false,
    },
    FixtureJourney {
        id: "J-13",
        title: "Owner imports existing DNS and resolves parity warnings",
        persona: "Maya",
        screens: &[
            "S-047", "S-047", "S-047", "S-047", "S-042", "S-042", "S-099", "S-043",
        ],
        actions: &SAFEGUARD_ACTIONS,
        acs: "AC-02",
        atk: "ATK-008",
        auds: "AUD-dns.parity_acknowledged",
        cutover: false,
        measures: false,
    },
    FixtureJourney {
        id: "J-14",
        title: "Owner edits DNS and toggles orange/grey",
        persona: "Maya",
        screens: &[
            "S-045", "S-045", "S-046", "S-046", "S-046", "S-045", "S-048", "S-045",
        ],
        actions: &SAFEGUARD_ACTIONS,
        acs: "AC-03",
        atk: "ATK-009",
        auds: "AUD-dns.parity_acknowledged",
        cutover: false,
        measures: false,
    },
    FixtureJourney {
        id: "J-15",
        title: "Owner issues TLS and enables HSTS",
        persona: "Maya",
        screens: &[
            "S-050", "S-050", "S-051", "S-051", "S-051", "S-050", "S-051", "S-043",
        ],
        actions: &SAFEGUARD_ACTIONS,
        acs: "AC-04",
        atk: "ATK-010",
        auds: "AUD-auth.signup",
        cutover: false,
        measures: false,
    },
    FixtureJourney {
        id: "J-16",
        title: "Owner enables protection in monitor mode, reviews, switches to block",
        persona: "Maya",
        screens: &[
            "S-054", "S-054", "S-065", "S-066", "S-064", "S-054", "S-055", "S-054",
        ],
        actions: &SAFEGUARD_ACTIONS,
        acs: "AC-06, AC-13",
        atk: "ATK-007",
        auds: "AUD-waf.mode_changed",
        cutover: false,
        measures: false,
    },
    FixtureJourney {
        id: "J-17",
        title: "Owner enables the Vulnerable-Origin Shield",
        persona: "Maya",
        screens: &[
            "S-057", "S-057", "S-057", "S-054", "S-057", "S-057", "S-057", "S-054",
        ],
        actions: &SAFEGUARD_ACTIONS,
        acs: "AC-38, AC-39",
        atk: "ATK-006",
        auds: "AUD-waf.mode_changed",
        cutover: false,
        measures: false,
    },
    FixtureJourney {
        id: "J-18",
        title: "Analyst investigates an attack",
        persona: "Sara",
        screens: &[
            "S-065", "S-065", "S-066", "S-066", "S-067", "S-065", "S-066", "S-064",
        ],
        actions: &SAFEGUARD_ACTIONS,
        acs: "AC-07, AC-08",
        atk: "ATK-005",
        auds: "AUD-ban.created",
        cutover: false,
        measures: false,
    },
    FixtureJourney {
        id: "J-19",
        title: "Owner builds a custom rule",
        persona: "Maya",
        screens: &[
            "S-059", "S-059", "S-060", "S-060", "S-059", "S-059", "S-060", "S-059",
        ],
        actions: &SAFEGUARD_ACTIONS,
        acs: "AC-12, AC-13",
        atk: "ATK-006",
        auds: "AUD-waf.rule_created",
        cutover: false,
        measures: false,
    },
    FixtureJourney {
        id: "J-20",
        title: "Owner configures rate limits for login",
        persona: "Maya",
        screens: &[
            "S-061", "S-061", "S-061", "S-061", "S-061", "S-061", "S-061", "S-061",
        ],
        actions: &SAFEGUARD_ACTIONS,
        acs: "AC-11",
        atk: "ATK-007",
        auds: "AUD-ratelimit.rule_changed",
        cutover: false,
        measures: false,
    },
    FixtureJourney {
        id: "J-21",
        title: "Owner configures alerts and webhooks",
        persona: "Maya",
        screens: &[
            "S-076", "S-076", "S-078", "S-078", "S-079", "S-079", "S-076", "S-078",
        ],
        actions: &SAFEGUARD_ACTIONS,
        acs: "AC-45",
        atk: "ATK-008",
        auds: "AUD-webhook.created",
        cutover: false,
        measures: false,
    },
    FixtureJourney {
        id: "J-22",
        title: "Blocked visitor files an appeal",
        persona: "Maya",
        screens: &[
            "S-140", "S-140", "S-145", "S-145", "S-145", "S-146", "S-146", "S-140",
        ],
        actions: &SAFEGUARD_ACTIONS,
        acs: "AC-43",
        atk: "ATK-009",
        auds: "AUD-appeal.submitted",
        cutover: false,
        measures: false,
    },
    FixtureJourney {
        id: "J-23",
        title: "Owner handles an appeal",
        persona: "Maya",
        screens: &[
            "S-069", "S-069", "S-069", "S-069", "S-069", "S-069", "S-069", "S-069",
        ],
        actions: &SAFEGUARD_ACTIONS,
        acs: "AC-43",
        atk: "ATK-010",
        auds: "AUD-appeal.resolved",
        cutover: false,
        measures: false,
    },
    FixtureJourney {
        id: "J-24",
        title: "Owner locks down the origin",
        persona: "Maya",
        screens: &[
            "S-098", "S-098", "S-098", "S-098", "S-098", "S-098", "S-098", "S-098",
        ],
        actions: &SAFEGUARD_ACTIONS,
        acs: "AC-18",
        atk: "ATK-006",
        auds: "AUD-origin.lockdown_applied",
        cutover: false,
        measures: false,
    },
    FixtureJourney {
        id: "J-25",
        title: "Owner views Protection Readiness and fixes items",
        persona: "Maya",
        screens: &[
            "S-044", "S-044", "S-044", "S-044", "S-044", "S-044", "S-044", "S-044",
        ],
        actions: &SAFEGUARD_ACTIONS,
        acs: "AC-53",
        atk: "ATK-001",
        auds: "AUD-domain.activated",
        cutover: false,
        measures: false,
    },
    FixtureJourney {
        id: "J-26",
        title: "Owner invites teammates and assigns roles",
        persona: "Maya",
        screens: &[
            "S-081", "S-081", "S-082", "S-082", "S-083", "S-083", "S-081", "S-081",
        ],
        actions: &SAFEGUARD_ACTIONS,
        acs: "AC-36",
        atk: "ATK-001",
        auds: "AUD-member.invited",
        cutover: false,
        measures: false,
    },
    FixtureJourney {
        id: "J-27",
        title: "Developer creates an API key and uses the API",
        persona: "Maya",
        screens: &[
            "S-080", "S-080", "S-080", "S-080", "S-080", "S-080", "S-080", "S-080",
        ],
        actions: &SAFEGUARD_ACTIONS,
        acs: "AC-35, AC-45",
        atk: "ATK-001",
        auds: "AUD-apikey.created",
        cutover: false,
        measures: false,
    },
    FixtureJourney {
        id: "J-28",
        title: "Owner exports reports and audit logs",
        persona: "Maya",
        screens: &[
            "S-073", "S-073", "S-074", "S-074", "S-084", "S-084", "S-073", "S-084",
        ],
        actions: &SAFEGUARD_ACTIONS,
        acs: "AC-47",
        atk: "ATK-001",
        auds: "AUD-report.run",
        cutover: false,
        measures: false,
    },
    FixtureJourney {
        id: "J-29",
        title: "Platform admin onboards and manages tenants",
        persona: "Maya",
        screens: &[
            "S-101", "S-101", "S-102", "S-102", "S-101", "S-102", "S-101", "S-102",
        ],
        actions: &SAFEGUARD_ACTIONS,
        acs: "AC-42",
        atk: "ATK-001",
        auds: "AUD-platform.tenant_plan_changed",
        cutover: false,
        measures: false,
    },
    FixtureJourney {
        id: "J-30",
        title: "Platform admin investigates abuse and global bans",
        persona: "Maya",
        screens: &[
            "S-114", "S-114", "S-106", "S-106", "S-109", "S-109", "S-114", "S-106",
        ],
        actions: &SAFEGUARD_ACTIONS,
        acs: "AC-51",
        atk: "ATK-001",
        auds: "AUD-ban.global_created",
        cutover: false,
        measures: false,
    },
    FixtureJourney {
        id: "J-31",
        title: "Platform admin toggles safe mode, maintenance, checks infra",
        persona: "Maya",
        screens: &[
            "S-110", "S-110", "S-111", "S-111", "S-122", "S-122", "S-121", "S-121",
        ],
        actions: &SAFEGUARD_ACTIONS,
        acs: "AC-13, AC-42",
        atk: "ATK-001",
        auds: "AUD-platform.emergency_used",
        cutover: false,
        measures: false,
    },
    FixtureJourney {
        id: "J-32",
        title: "Owner removes a domain safely",
        persona: "Maya",
        screens: &[
            "S-094", "S-094", "S-094", "S-094", "S-094", "S-094", "S-094", "S-094",
        ],
        actions: &SAFEGUARD_ACTIONS,
        acs: "AC-37",
        atk: "ATK-001",
        auds: "AUD-domain.decommissioned",
        cutover: false,
        measures: false,
    },
    FixtureJourney {
        id: "J-33",
        title: "User exports data or deletes the account",
        persona: "Maya",
        screens: &[
            "S-090", "S-090", "S-090", "S-090", "S-090", "S-090", "S-090", "S-090",
        ],
        actions: &SAFEGUARD_ACTIONS,
        acs: "AC-47",
        atk: "ATK-001",
        auds: "AUD-auth.data_export_requested",
        cutover: false,
        measures: false,
    },
    FixtureJourney {
        id: "J-34",
        title: "Incident: attack spike",
        persona: "Maya",
        screens: &[
            "S-054", "S-054", "S-093", "S-093", "S-067", "S-067", "S-054", "S-054",
        ],
        actions: &SAFEGUARD_ACTIONS,
        acs: "AC-44, AC-27",
        atk: "ATK-001",
        auds: "AUD-waf.under_attack_on",
        cutover: false,
        measures: false,
    },
];

fn journey_fixture(journey: &FixtureJourney) -> String {
    let mut s = format!(
        "# {} {}\n\nPersona: [{}](../personas/{}.md). Emotional state is a design aid, not a measured value.\n\nTrigger: the situation described by the specification.\n\n## Steps\n\n| Step | User action | System response | Screen | Data collected | Error path | Emotional state | Copy key | Metric |\n| --- | --- | --- | --- | --- | --- | --- | --- | --- |\n",
        journey.id,
        journey.title,
        journey.persona,
        journey.persona.to_lowercase()
    );
    let mut previous: Option<&str> = None;
    let mut changing: Vec<usize> = Vec::new();
    let mut cutover_steps: Vec<usize> = Vec::new();
    let keywords = [
        "dns",
        "nameserver",
        "delegation",
        "proxy",
        "routing",
        "zone",
        "cname",
    ];
    for (index, screen) in journey.screens.iter().enumerate() {
        if previous != Some(*screen) {
            changing.push(index + 1);
        }
        previous = Some(*screen);
        let action = journey
            .actions
            .get(index)
            .copied()
            .unwrap_or("Submits the sign-in form and reads the error.");
        if journey.cutover
            && keywords
                .iter()
                .any(|keyword| action.to_lowercase().contains(keyword))
        {
            cutover_steps.push(index + 1);
        }
        s.push_str(&format!(
            "| {} | {} | The form shows a generic error for an unknown email. | {} | none | ERR-AUTH-002: Wrong password or unknown email is rejected with the same error. | calm | {}-step{}-title | - |\n",
            index + 1, action, screen, journey.id.to_lowercase(), index + 1
        ));
    }
    s.push_str("\n## Trust moments\n\n| Step | What the user must believe | Evidence we show |\n| --- | --- | --- |\n| 1 | The number is real. | The measured value and its window. |\n| 2 | The limit is stated. | The known-limitations note. |\n");
    s.push_str(&format!("\n## Security considerations\n\n| Step | Risk | Control | ATK |\n| --- | --- | --- | --- |\n| 1 | A probe learns whether the account exists. | Uniform response and a rate limit. | {} |\n| 2 | A token is guessed. | A single-use token with a short TTL. | {} |\n", journey.atk, journey.atk));
    let numeric: u32 = journey.id.trim_start_matches("J-").parse().unwrap_or(0);
    if (16..=21).contains(&numeric) {
        s.push_str(&format!("| 3 | A probe reaches an unguarded endpoint. | The guard rejects the request. | {} |\n", journey.atk));
    }
    s.push_str("\n## Accessibility considerations\n\n| Step | Focus target | Announcement | Keyboard |\n| --- | --- | --- | --- |\n");
    for step in &changing {
        s.push_str(&format!(
            "| {step} | The new h1 | The screen name | Tab and Enter |\n"
        ));
    }
    if numeric >= 13 {
        s.push_str("\n## Safeguards\n\n| Step | Risky action | Safeguard | Kind | Copy key | Exact copy |\n| --- | --- | --- | --- | --- | --- |\n");
        let kinds = ["preview", "confirmation", "undo", "time box"];
        for step in 1..=journey.screens.len() {
            let kind = kinds.get(step % kinds.len()).copied().unwrap_or("preview");
            let risky = match (journey.id, step) {
                ("J-16", 1) => "Switching the protection mode.",
                ("J-16", 2) => "Reviewing the self-lockout warning.",
                ("J-18", 1) => "Banning the address.",
                ("J-18", 2) => "Unbanning an address.",
                ("J-31", 1) => "Enabling platform safe mode.",
                _ => "Changes the live setting.",
            };
            s.push_str(&format!("| {step} | {risky} | The preview shows the change before it applies. | {kind} | {}-step{}-copy | Review step {} of {} before it applies; the history keeps the previous value for undo. |\n", journey.id.to_lowercase(), step, step, journey.id));
        }
        s.push_str("\n## What could go wrong\n\n| Step | What goes wrong | Recovery action |\n| --- | --- | --- |\n| 1 | The change applies before the preview is read. | The history shows the previous value and offers undo. |\n| 2 | A record is saved with the wrong type. | The change history restores the previous record. |\n| 3 | The user leaves before confirming. | The unsaved change is discarded and nothing moves. |\n");
    }
    if numeric == 16 || numeric == 17 {
        s.push_str("\n## Decision support\n\n- The would-block count for the last 24 hours.\n- Three example events with the rule that matched.\n- The would-block share of all requests.\n- The false-positive review from the last week.\n- The honest warning about shared IPs and collateral risk.\n");
    }
    if numeric == 19 {
        s.push_str("\n## Rule builder error taxonomy\n\n| Class | Example | Message copy key | Exact copy |\n| --- | --- | --- | --- |\n| syntax | `= 1 OR` | rule-syntax-bracket | Close the bracket before you save; the example shows the open position. |\n| syntax | `field ==` | rule-syntax-operator | Use one operator from the list; the example shows the accepted operator. |\n| semantic | `header is not a field` | rule-semantic-field | Pick a field from the list; the example shows a supported request field. |\n| semantic | `ban without scope` | rule-semantic-scope | Give the rule a scope before you save; the example shows a path and a method. |\n| performance | `every request with a regex` | rule-performance-regex | Narrow the match before you save; the example shows a cheaper condition. |\n| performance | `no path scope` | rule-performance-scope | Add a path scope before you save; the example shows a narrow path. |\n");
    }
    if numeric == 22 {
        s.push_str("\n## Abuse cases\n\n| Abuse case | Defense | ATK |\n| --- | --- | --- |\n| A bot files appeals for many Ray IDs. | Rate limit per address and Ray ID, proof-of-work and a neutral receipt. | ATK-001 |\n| An appeal for another site's visitor. | The form only accepts a Ray ID that resolves on the serving site. | ATK-002 |\n| A script fills the note with a payload. | The note is length-capped, stored as text and never rendered as markup. | ATK-003 |\n| An appeal is used to probe whether a ban exists. | The receipt is identical for a known and an unknown Ray ID. | ATK-004 |\n| A visitor files repeatedly to exhaust the queue. | One open appeal per Ray ID and a per-address daily cap. | ATK-005 |\n");
    }
    if numeric == 23 {
        s.push_str("\n## Owner outcomes\n\n- Unban the address now and record the reason in the audit log.\n- Allowlist the address for N days with an expiry shown before the save.\n- Create a scoped exception with an expiry when the rule is a false positive.\n- Decline the appeal with a reason and send a neutral message to the visitor.\n");
    }
    if numeric == 24 {
        s.push_str("\n## Stacks\n\nThese are conceptual steps for each stack, never a real command line.\n\n| Stack | Concept | What the page shows |\n| --- | --- | --- |\n| ufw | Allow only the HDD edge addresses to the origin. | The allowlist and the current status. |\n| iptables | Restrict the origin ports to the HDD edge addresses. | The rule summary and the revert step. |\n| nftables | Restrict the origin ports with a named table. | The table summary and the revert step. |\n| cloud security group | Allow the HDD edge addresses and deny the rest. | The group diff and the revert step. |\n| nginx or apache | Reject requests without the secret header. | The snippet and the verification result. |\n");
        s.push_str("\n## Verification probes\n\n| Probe | What it proves | What it cannot prove |\n| --- | --- | --- |\n| A direct request to the origin address. | The origin still answers without the proxy. | Whether the owner's own network is allowed. |\n| A request with a wrong secret header. | The verifier rejects a wrong secret. | The strength of the secret itself. |\n| A request from the proxy path. | The configured path still reaches the origin. | Every edge address in every region. |\n| A repeated probe after the change. | The state stays applied over time. | A later manual change at the provider. |\n");
    }
    if numeric >= 25 {
        s.push_str("\n## Stress cases\n\n| Case | What changes | What stays usable |\n| --- | --- | --- |\n| low bandwidth | The page loads its text before its images. | The checklist and its actions stay reachable. |\n| small screen | The table stacks into one column. | The same action stays in the tab order. |\n| keyboard only | No pointer is needed for any action. | Tab and Enter reach every control. |\n");
    }
    if numeric == 25 {
        s.push_str("\n## Readiness score\n\n| Check | Weight | Status values | Why it matters | Fix link |\n| --- | --- | --- | --- | --- |\n| Traffic flows through HDD | 20 | Pass, Fail | Traffic must reach HDD before protection applies. | S-044 |\n| Certificate valid | 15 | Pass, Partial, Fail | An invalid certificate stops HTTPS for visitors. | S-044 |\n| Origin lockdown | 20 | Pass, Partial, Fail, Unknown | A direct origin path bypasses the proxy. | S-044 |\n| WAF in block mode | 25 | Pass, Partial, Fail | Monitor mode records but does not stop attacks. | S-044 |\n| Abuse controls | 10 | Pass, Fail | Rate limits slow down automated abuse. | S-044 |\n| Operations ready | 10 | Pass, Partial, Unknown | Alerts and backups keep the site recoverable. | S-044 |\n\n## Honesty footnote\n\nS-044 places the exact footnote \"Measures configuration completeness, not security.\" below the readiness ring and repeats it above the checklist.\n");
    }
    if numeric == 27 {
        s.push_str("\n## API key lifecycle\n\n| Stage | What happens | Control |\n| --- | --- | --- |\n| create | The owner names the key and picks its scopes. | The role still limits every scope the key asks for. |\n| secret reveal once | The secret appears on the page exactly one time. | The page tells the reader to store it before leaving. |\n| rotation | A new key replaces the old one, then the old one is revoked. | The list shows both keys until the old one is revoked. |\n| expiry | The key stops working at the chosen date. | The list shows the expiry date and a warning before it. |\n| restrict by IP | The key is refused from any other address. | The key page lists the allowed address ranges. |\n| revoke | The key is deleted and its secret stops working. | The audit row records who revoked the key. |\n");
    }
    if (29..=31).contains(&numeric) {
        s.push_str("\n## Admin controls\n\n| Action | Permission | Audit event | Reason required | Step-up |\n| --- | --- | --- | --- | --- |\n");
        match numeric {
            29 => s.push_str("| View a tenant | PERM-platform.tenant.read | AUD-platform.support_lookup | no | no |\n| Change a plan | PERM-platform.tenant.write | AUD-platform.tenant_plan_changed | yes | yes |\n| Suspend a tenant | PERM-platform.tenant.suspend | AUD-platform.tenant_plan_changed | yes | yes |\n"),
            30 => s.push_str("| Triage an abuse report | PERM-platform.abuse.write | No B8 event records abuse triage yet | yes | no |\n| Add a global ban | PERM-platform.jail.write | AUD-ban.global_created | yes | yes |\n| Change the never-ban list | PERM-platform.jail.write | AUD-platform.never_ban_changed | yes | yes |\n"),
            _ => s.push_str("| Read infrastructure health | PERM-platform.infra.read | AUD-platform.support_lookup | no | no |\n| Use an emergency control | PERM-platform.emergency | AUD-platform.emergency_used | typed | yes |\n| Change a feature flag | PERM-platform.flags.write | AUD-platform.flag_changed | yes | yes |\n"),
        }
    }
    if numeric == 33 {
        s.push_str("\n## Timelines\n\nThe export and the deletion are configurable defaults; the page shows the value that this deployment uses.\n\n| Request | Timeline | User sees |\n| --- | --- | --- |\n| Data export | Within 24 hours by default, configurable up to 7 days. | The page states the request time and the delivery address. |\n| Data deletion | After a grace period of 30 days by default, configurable. | The page states the grace period and how to cancel. |\n");
    }
    if numeric == 34 {
        s.push_str("\n## Incident timeline\n\n| Phase | Trigger | Who acts | Screen | De-escalation |\n| --- | --- | --- | --- | --- |\n| Detection | The alert rule fires on an attack spike. | The alert channel tells Sara and Omar. | S-054 | A reviewer checks the traffic before any mode change. |\n| Under-attack mode | The owner or an analyst decides the traffic is hostile. | The owner enables under attack with a typed confirmation. | S-093 | The mode expires at the stated time unless it is renewed. |\n| Analyst actions | The campaign IPs and ASNs are identified. | Sara bans the campaign or creates an exception for a false positive. | S-067 | Every ban carries a short TTL and an undo path. |\n| De-escalation | The calm window passes without a new spike. | The owner turns under attack off and records the outcome. | S-054 | The timeline keeps the mode change and the reason. |\n\n## Retrospective report outline\n\n1. Summary of the incident window.\n2. Detection path and time to first alert.\n3. Traffic evidence with redacted examples.\n4. Actions taken and who authorised them.\n5. False positives and appeals during the window.\n6. What the protection covered.\n7. What it did not cover and why.\n8. Configuration changes made during the incident.\n9. Follow-up items with owners and dates.\n");
    }
    if journey.cutover {
        s.push_str("\n## Cutover safety\n\n| Step | What could break the live site | Guard | Undo |\n| --- | --- | --- | --- |\n");
        for step in &cutover_steps {
            s.push_str(&format!("| {step} | The live site could lose its delegation or proxy route. | Preview and the parity check run before the change. | Undo with the instant return path of R-19 and the rollback instructions. |\n"));
        }
    }
    if journey.measures {
        s.push_str(&format!("\n## Instrumentation\n\n- `AUD-auth.signup` supplies the counter for {}.\n- Time to first domain in monitor mode reads `AUD-domain.created` and `AUD-domain.activated` for {}.\n- Completion rate of the add-domain wizard reads the stored wizard step for {}.\n", journey.id, journey.id, journey.id));
    } else {
        s.push_str(&format!(
            "\n## Instrumentation\n\n- `{}` supplies the counter.\n",
            journey.auds
        ));
    }
    let mut question = String::new();
    if journey.id == "J-16" {
        question.push_str("\n\nQuestion: Should the monitor-to-block switch use a scheduled switch with typed confirmation? See OPERATOR-QUESTIONS.md.");
    }
    if journey.id == "J-23" {
        question.push_str("\n\nQuestion: What should the default appeal retention period be, and who may read an appeal? See OPERATOR-QUESTIONS.md.");
    }
    s.push_str(&format!("\n## Success and checks\n\nSuccess: the specification success criterion holds. Checks: {}.{}\n\n## Missing screens\n\n{}\n", journey.acs, question, if journey.cutover { "S-149." } else { "None." }));
    s
}

fn spec_patches_fixture() -> String {
    String::from(
        "# Proposed specification screens\n\nThe ids below are proposals, not screens of B12.1.\n\n| Proposed screen | Needed by | Reason | Status |\n| --- | --- | --- | --- |\n| S-149 | J-08 | The domain settings page has no screen id in B12.1. | proposed |\n",
    )
}

/// The dependency edges of the fixture journey graph; every edge points to a lower journey number.
const FIXTURE_EDGES: [(&str, &str); 33] = [
    ("J-02", "J-01"),
    ("J-03", "J-02"),
    ("J-04", "J-02"),
    ("J-05", "J-04"),
    ("J-06", "J-02"),
    ("J-07", "J-04"),
    ("J-08", "J-07"),
    ("J-09", "J-07"),
    ("J-10", "J-08"),
    ("J-11", "J-08"),
    ("J-12", "J-08"),
    ("J-13", "J-08"),
    ("J-14", "J-13"),
    ("J-15", "J-12"),
    ("J-16", "J-15"),
    ("J-17", "J-16"),
    ("J-18", "J-16"),
    ("J-19", "J-18"),
    ("J-20", "J-18"),
    ("J-21", "J-18"),
    ("J-22", "J-16"),
    ("J-23", "J-22"),
    ("J-24", "J-16"),
    ("J-25", "J-24"),
    ("J-26", "J-04"),
    ("J-27", "J-04"),
    ("J-28", "J-18"),
    ("J-29", "J-02"),
    ("J-30", "J-29"),
    ("J-31", "J-29"),
    ("J-32", "J-08"),
    ("J-33", "J-04"),
    ("J-34", "J-18"),
];

/// A complete `docs/UX/journey-dependencies.md` for the fixture tree.
fn journey_dependencies_fixture() -> String {
    let mut s = String::from(
        "# Journey dependencies\n\nRule: a journey depends only on a lower-numbered journey, unless its `Why` cell says so as an exception.\n\n## Dependency table\n\n| Journey | Needs | Why |\n| --- | --- | --- |\n",
    );
    for n in 1..=34 {
        let id = format!("J-{n:02}");
        let needs: Vec<&str> = FIXTURE_EDGES
            .iter()
            .filter(|(journey, _)| *journey == id)
            .map(|(_, need)| *need)
            .collect();
        let needs = if needs.is_empty() {
            "none".to_owned()
        } else {
            needs.join(", ")
        };
        s.push_str(&format!(
            "| {id} | {needs} | The journey is ordered after its prerequisites. |\n"
        ));
    }
    s.push_str("\n## Graph\n\nA text graph; no diagram tool is required.\n\n");
    for (journey, need) in FIXTURE_EDGES {
        s.push_str(&format!("{journey} -> {need}\n"));
    }
    s.push_str("\n## Task dependencies\n\n| Journey dependency | Prerequisite task | Dependent task | Basis | Why the order agrees |\n| --- | --- | --- | --- | --- |\n| J-02 needs J-01 | T-0001 | T-0002 | direct | T-0002 names T-0001 in its deps line. |\n| J-08 needs J-07 | T-0001 | T-0004 | earlier | T-0001 comes earlier in the stable order than T-0004. |\n| J-23 needs J-22 | T-0002 | T-0002 | none | The same task T-0002 delivers both journeys, so the spec names no task dependency. |\n");
    s
}

/// Owned inputs of the fixture `JourneyContext`.
struct JourneyParts {
    titles: BTreeMap<String, String>,
    personas: BTreeMap<String, BTreeSet<String>>,
    screens: BTreeSet<String>,
    mentions: BTreeMap<String, BTreeSet<String>>,
    acs: BTreeMap<String, BTreeSet<String>>,
    errors: BTreeMap<String, u16>,
    error_text: BTreeMap<String, String>,
    screen_names: BTreeMap<String, String>,
    atks: BTreeSet<String>,
    audits: BTreeSet<String>,
    permissions: BTreeSet<String>,
    patches: BTreeSet<String>,
}

fn journey_parts() -> JourneyParts {
    let spec = fake_spec();
    let mut mentions = BTreeMap::new();
    let mut acs = BTreeMap::new();
    for id in JOURNEYS_IN_SCOPE {
        let body = spec_section(&spec, id)
            .iter()
            .map(|(_, line)| *line)
            .collect::<Vec<_>>()
            .join("\n");
        mentions.insert(id.to_owned(), tokens_in(&body, r"S-\d{3}"));
        acs.insert(id.to_owned(), tokens_in(&body, r"AC-\d{2}"));
    }
    JourneyParts {
        titles: journey_headings(&spec),
        personas: matrix_personas(&good_matrix()),
        screens: screen_ids(&spec),
        mentions,
        acs,
        errors: error_catalog(&spec),
        error_text: error_descriptions(&spec),
        screen_names: screen_names(&spec),
        atks: attack_registry(&spec),
        audits: audit_ids(&spec),
        permissions: permission_ids(&spec),
        patches: proposed_screens(&spec_patches_fixture()),
    }
}

fn journey_messages(text: &str, id: &str) -> String {
    let parts = journey_parts();
    let ctx = JourneyContext {
        titles: &parts.titles,
        personas: &parts.personas,
        screens: &parts.screens,
        mentions: &parts.mentions,
        acs: &parts.acs,
        errors: &parts.errors,
        atks: &parts.atks,
        error_text: &parts.error_text,
        screen_names: &parts.screen_names,
        audits: &parts.audits,
        patches: &parts.patches,
    };
    messages(&journey_findings(text, id, &ctx))
}

/// Findings of one persona text, for the negative tests.
fn persona_messages(stem: &str, text: &str) -> String {
    messages(&persona_findings(stem, text, Some(&b11_11_fixture())))
}

fn matrix_messages(text: &str) -> String {
    messages(&matrix_findings(text))
}

// ---------------------------------------------------------------------------------------------- slugs

#[test]
fn slugs_follow_the_github_rule() {
    assert_eq!(slug("Honesty tests"), "honesty-tests");
    assert_eq!(
        slug("Honesty tests (five questions)"),
        "honesty-tests-five-questions"
    );
    assert_eq!(slug("A/B: dark-first & light"), "ab-dark-first--light");
    assert_eq!(slug("  Trim me  "), "trim-me");
}

// ---------------------------------------------------------------------------------------------- links

#[test]
fn a_link_to_a_file_that_exists_passes_and_a_missing_one_names_file_and_line() {
    let r = Repo::new("links1");
    r.put("docs/UX/A.md", "# A\n");
    let text = "# T\n\nok [a](A.md) and bad [b](B.md)\n";
    let f = broken_links(r.root(), Path::new("docs/UX/T.md"), text);
    assert_eq!(f.len(), 1, "{}", messages(&f));
    let m = messages(&f);
    assert!(m.contains("docs/UX/T.md:3"), "{m}");
    assert!(m.contains("B.md"), "{m}");
}

#[test]
fn external_mailto_and_bare_anchor_links_are_not_file_links() {
    let r = Repo::new("links2");
    let text = "# Top\n\n[w](https://example.test/x) [m](mailto:a@example.test) [s](#top)\n";
    let f = broken_links(r.root(), Path::new("docs/UX/T.md"), text);
    assert!(f.is_empty(), "{}", messages(&f));
}

#[test]
fn an_anchor_must_name_a_real_heading_in_the_same_or_the_target_file() {
    let r = Repo::new("links3");
    r.put(
        "docs/UX/A.md",
        "# A\n\n## Second part\n\n```\n# not a heading\n```\n",
    );
    let text = "# Top\n\n[ok](#top) [bad](#nope) [ok2](A.md#second-part) [bad2](A.md#third) [bad3](A.md#not-a-heading)\n";
    let f = broken_links(r.root(), Path::new("docs/UX/T.md"), text);
    let m = messages(&f);
    assert_eq!(f.len(), 3, "{m}");
    assert!(m.contains("#nope") && m.contains("#third") && m.contains("#not-a-heading"));
}

#[test]
fn links_in_code_blocks_and_code_spans_are_examples_not_links() {
    let r = Repo::new("links4");
    let text = "# T\n\n`[x](missing.md)`\n\n```\n[y](missing2.md)\n```\n";
    let f = broken_links(r.root(), Path::new("docs/UX/T.md"), text);
    assert!(f.is_empty(), "{}", messages(&f));
}

#[test]
fn titles_directories_parent_paths_and_escapes_are_handled() {
    let r = Repo::new("links5");
    r.put("docs/other.md", "# O\n");
    r.put("docs/UX/sub/x.md", "# X\n");
    let ok = "[t](sub/x.md \"a title\") [d](sub) [p](../other.md) [sp](sub/x.md#x)\n";
    assert!(
        broken_links(r.root(), Path::new("docs/UX/T.md"), ok).is_empty(),
        "valid forms must pass"
    );
    let out = "[e](../../../../etc/passwd)\n";
    let f = broken_links(r.root(), Path::new("docs/UX/T.md"), out);
    assert_eq!(f.len(), 1);
    assert!(messages(&f).contains("outside the repository"));
}

#[test]
fn a_file_link_with_a_line_fragment_on_a_non_markdown_file_checks_only_the_file() {
    let r = Repo::new("links6");
    r.put("crates/a.rs", "fn a() {}\n");
    let f = broken_links(
        r.root(),
        Path::new("docs/UX/T.md"),
        "[c](../../crates/a.rs#L10)\n",
    );
    assert!(f.is_empty(), "{}", messages(&f));
}

// ---------------------------------------------------------------------------------------------- charter

#[test]
fn a_complete_charter_passes() {
    let f = charter_findings(&good_charter());
    assert!(f.is_empty(), "{}", messages(&f));
}

#[test]
fn a_principle_without_an_enforcement_mechanism_fails_a1() {
    let c = good_charter().replacen("| claims-lint |", "|  |", 1);
    let m = messages(&charter_findings(&c));
    assert!(
        m.contains("Enforced by") && m.contains("Calm, honest, expert"),
        "{m}"
    );
}

#[test]
fn six_principles_instead_of_seven_fail() {
    let c = good_charter().replace(
        "| 7 | Dark first, light equal | show the number | hide the number | claims-lint |\n",
        "",
    );
    let m = messages(&charter_findings(&c));
    assert!(m.contains("seven"), "{m}");
}

#[test]
fn honesty_tests_must_be_five_questions_a3() {
    let four = good_charter().replace("5. Can the user undo it?\n", "");
    assert!(messages(&charter_findings(&four)).contains("five"));
    let statement = good_charter().replace("Can the user undo it?", "The user can undo it.");
    let m = messages(&charter_findings(&statement));
    assert!(m.contains("yes/no question"), "{m}");
}

#[test]
fn a_charter_over_four_printed_pages_fails_a5() {
    let mut c = good_charter();
    c.push_str(&"word ".repeat(CHARTER_WORD_BUDGET));
    let m = messages(&charter_findings(&c));
    assert!(m.contains("four printed pages"), "{m}");
    let mut at_budget = good_charter();
    let have = at_budget.split_whitespace().count();
    at_budget.push_str(&"word ".repeat(CHARTER_WORD_BUDGET - have));
    assert!(charter_findings(&at_budget).is_empty());
}

// ---------------------------------------------------------------------------------------------- measures

#[test]
fn complete_measures_pass() {
    let f = measures_findings(&good_measures());
    assert!(f.is_empty(), "{}", messages(&f));
}

#[test]
fn a_measure_without_source_or_privacy_treatment_fails_a2() {
    let m = good_measures().replacen(
        "| local counter | no personal data |",
        "|  | no personal data |",
        1,
    );
    assert!(messages(&measures_findings(&m)).contains("Data source"));
    let m = good_measures().replacen(
        "| local counter | no personal data |",
        "| local counter |  |",
        1,
    );
    assert!(messages(&measures_findings(&m)).contains("Privacy treatment"));
}

#[test]
fn every_measure_the_task_names_must_be_present() {
    let m = good_measures().replace("Time to unban", "Something else");
    let out = messages(&measures_findings(&m));
    assert!(out.contains("Time to unban"), "{out}");
}

// ---------------------------------------------------------------------------------------------- decisions

#[test]
fn a_decision_record_needs_status_date_and_the_three_sections() {
    assert!(decision_findings("UXD-001", &good_decision(1)).is_empty());
    let no_status = good_decision(1).replace("Status: accepted\n", "");
    assert!(messages(&decision_findings("UXD-001", &no_status)).contains("Status"));
    let no_cons = good_decision(1).replace("## Consequences", "## Notes");
    assert!(messages(&decision_findings("UXD-001", &no_cons)).contains("Consequences"));
    let wrong_id = good_decision(2);
    assert!(messages(&decision_findings("UXD-001", &wrong_id)).contains("UXD-001"));
    let bad_status = good_decision(1).replace("accepted", "maybe");
    assert!(messages(&decision_findings("UXD-001", &bad_status)).contains("Status"));
}

// ---------------------------------------------------------------------------------------------- whole tree

#[test]
fn a_complete_tree_passes_and_each_missing_document_is_named() {
    let r = Repo::new("tree");
    good_tree(&r);
    let f = check(r.root());
    assert!(f.is_empty(), "{}", messages(&f));

    fs::remove_file(r.root().join("docs/UX/CHARTER.md")).unwrap();
    let m = messages(&check(r.root()));
    assert!(m.contains("docs/UX/CHARTER.md"), "{m}");

    good_tree(&r);
    fs::remove_file(r.root().join("docs/UX/decisions/UXD-002.md")).unwrap();
    let m = messages(&check(r.root()));
    assert!(m.contains("UXD-002"), "{m}");
}

#[test]
fn a_broken_link_in_any_ux_document_or_agents_md_fails_the_tree() {
    let r = Repo::new("tree2");
    good_tree(&r);
    r.put("docs/UX/EXTRA.md", "# E\n\n[gone](GONE.md)\n");
    r.put("AGENTS.md", "# Agents\n\n[gone](docs/UX/NOPE.md)\n");
    let m = messages(&check(r.root()));
    assert!(m.contains("GONE.md") && m.contains("NOPE.md"), "{m}");
}

#[test]
fn the_shipped_ux_documents_pass() {
    let root = crate::util::repo_root().expect("root");
    let f = check(&root);
    assert!(f.is_empty(), "{}", messages(&f));
}

// ---------------------------------------------------------------------------------------------- personas (T-0012)

#[test]
fn a_complete_persona_passes() {
    let criteria = b11_11_fixture();
    assert!(
        persona_findings("maya", &good_persona("maya"), Some(&criteria)).is_empty(),
        "{}",
        messages(&persona_findings(
            "maya",
            &good_persona("maya"),
            Some(&criteria)
        ))
    );
}

#[test]
fn a_persona_header_must_say_it_is_a_fictional_composite() {
    let text = good_persona("maya").replace(
        "is a fictional composite, not a real person; source spec B1.1.",
        "is described in the specification.",
    );
    let m = persona_messages("maya", &text);
    assert!(m.contains("fictional composite"), "{m}");
}

#[test]
fn a_persona_needs_the_five_context_of_use_rows() {
    let text = good_persona("maya").replace("| Device | a laptop |\n", "");
    let m = persona_messages("maya", &text);
    assert!(m.contains("Device"), "{m}");
    let missing = good_persona("maya").replace("## Context of use", "## Background");
    assert!(persona_messages("maya", &missing).contains("Context of use"));
}

#[test]
fn a_persona_with_two_scenarios_fails_a1() {
    let text = good_persona("maya").replace(
        "### 3. A scenario\n\nWhen Monday comes, I want to see it, so I can decide.\nMeasurable outcome: the AC-37 flow is recorded.\n\n",
        "",
    );
    let m = persona_messages("maya", &text);
    assert!(m.contains("three scenarios"), "{m}");
}

#[test]
fn a_scenario_without_a_measurable_outcome_fails_a1() {
    let no_outcome = good_persona("maya").replacen(
        "Measurable outcome: the AC-37 flow is recorded.",
        "It should feel calm.",
        1,
    );
    let m = persona_messages("maya", &no_outcome);
    assert!(m.contains("measurable outcome"), "{m}");
    // An outcome that names no number, acceptance check, audit event or metric is not measurable.
    let vague = good_persona("maya").replacen(
        "Measurable outcome: the AC-37 flow is recorded.",
        "Measurable outcome: it is easier.",
        1,
    );
    let m = persona_messages("maya", &vague);
    assert!(m.contains("measurable outcome"), "{m}");
    // An audit event is a measurable outcome.
    let audit = good_persona("maya").replacen(
        "Measurable outcome: the AC-37 flow is recorded.",
        "Measurable outcome: `AUD-domain.activated` is written.",
        1,
    );
    assert!(persona_findings("maya", &audit, Some(&b11_11_fixture())).is_empty());
}

#[test]
fn a_persona_without_anti_goals_fails() {
    let text = good_persona("maya").replace(
        "## Anti-goals\n\n- Jargon.\n\n",
        "## Notes\n\n- Jargon.\n\n",
    );
    assert!(persona_messages("maya", &text).contains("Anti-goals"));
}

#[test]
fn accessibility_must_be_present_and_mapped_to_b11_11() {
    let missing = good_persona("maya").replace("## Accessibility", "## Notes");
    assert!(persona_messages("maya", &missing).contains("Accessibility"));
    let unmapped = good_persona("maya").replace(
        "Mapped to B11.11 criteria: 1.4.4 and 2.1.1.",
        "Accessibility is respected.",
    );
    let m = persona_messages("maya", &unmapped);
    assert!(m.contains("B11.11"), "{m}");
    let one_criterion = good_persona("maya").replace(
        "Mapped to B11.11 criteria: 1.4.4 and 2.1.1.",
        "Mapped to B11.11 criterion 2.1.1.",
    );
    let m = persona_messages("maya", &one_criterion);
    assert!(m.contains("criteria"), "{m}");
}

#[test]
fn a_persona_must_cross_link_journeys_and_screens() {
    let without_section = good_persona("maya").replace("## Journeys and screens", "## Notes");
    assert!(
        persona_messages("maya", &without_section).contains("Journeys and screens"),
        "{}",
        persona_messages("maya", &without_section)
    );
    let only_journeys = good_persona("maya").replace(
        "- Screens: [S-042](../../SPEC.md#s-042-add-domain-wizard).\n",
        "",
    );
    let m = persona_messages("maya", &only_journeys);
    assert!(m.contains("screen"), "{m}");
}

#[test]
fn the_adversary_needs_ten_abuse_stories_mapped_to_the_registry() {
    let registry: BTreeSet<String> = ABUSE_ATK_IDS.iter().map(|id| (*id).to_owned()).collect();
    assert!(
        adversary_findings(&good_persona("adversary"), Some(&registry)).is_empty(),
        "{}",
        messages(&adversary_findings(
            &good_persona("adversary"),
            Some(&registry)
        ))
    );
    let nine = good_persona("adversary").replace(
        "| 10 | an abuse story | ATK-010 | the request is blocked |\n",
        "",
    );
    let m = messages(&adversary_findings(&nine, Some(&registry)));
    assert!(m.contains("ten"), "{m}");
    let unknown = good_persona("adversary").replace("ATK-010", "ATK-999");
    let m = messages(&adversary_findings(&unknown, Some(&registry)));
    assert!(
        m.contains("ATK-999") && m.contains("coverage matrix"),
        "{m}"
    );
}

#[test]
fn the_attack_registry_is_read_from_the_matrix_rows() {
    let ids = attack_registry(
        "| ATK-001 | an attack |\nprose mentioning ATK-999\n| ATK-390 | another attack |\n",
    );
    assert!(ids.contains("ATK-001") && ids.contains("ATK-390"));
    assert!(
        !ids.contains("ATK-999"),
        "only table rows are registry entries: {ids:?}"
    );
}

// ---------------------------------------------------------------------------------------------- matrix (A2) and question (A5)

#[test]
fn every_journey_must_be_in_the_matrix() {
    let text = good_matrix().replace(
        "| J-07 | Journey 7 | [Alex](personas/alex.md) | none |\n",
        "",
    );
    let m = matrix_messages(&text);
    assert!(m.contains("J-07") && m.contains("not linked"), "{m}");
}

#[test]
fn a_matrix_row_must_link_a_persona_file() {
    let text = good_matrix().replacen("[Maya](personas/maya.md)", "Maya", 1);
    let m = matrix_messages(&text);
    assert!(m.contains("links to no persona"), "{m}");
    let unknown = good_matrix().replacen(
        "[Maya](personas/maya.md)",
        "[Nobody](personas/nobody.md)",
        1,
    );
    let m = matrix_messages(&unknown);
    assert!(m.contains("nobody.md"), "{m}");
}

#[test]
fn a_matrix_row_must_not_invent_a_journey() {
    let text = good_matrix().replace(
        "| J-34 | Journey 34 | [Maya](personas/maya.md) | none |\n",
        "| J-34 | Journey 34 | [Maya](personas/maya.md) | none |\n| J-35 | Not a journey | [Maya](personas/maya.md) | none |\n",
    );
    let m = matrix_messages(&text);
    assert!(m.contains("J-35") && m.contains("not a journey"), "{m}");
}

#[test]
fn the_primary_persona_question_must_be_recorded_open_with_maya_as_default() {
    assert!(
        primary_persona_findings(&good_register()).is_empty(),
        "{}",
        messages(&primary_persona_findings(&good_register()))
    );
    let absent = good_register().replace(
        "| Which persona is primary for the pilot? | Maya, the site owner (B1.1) | OPEN: no answer yet; the default applies for development | `docs/UX/personas/maya.md` | T-0012 |\n",
        "",
    );
    assert!(messages(&primary_persona_findings(&absent)).contains("primary-persona"));
    let closed = good_register().replace("OPEN: no answer yet", "ANSWERED");
    assert!(messages(&primary_persona_findings(&closed)).contains("OPEN"));
    let no_default = good_register().replace("Maya, the site owner (B1.1)", "no default");
    assert!(messages(&primary_persona_findings(&no_default)).contains("Maya"));
}

#[test]
fn the_primary_persona_question_is_linked_from_the_matrix_or_maya() {
    let r = Repo::new("tree-question-link");
    good_tree(&r);
    assert!(check(r.root()).is_empty(), "{}", messages(&check(r.root())));
    let matrix = good_matrix().replace(
        "Question: [which persona is primary for the pilot?](../OPERATOR-QUESTIONS.md#primary-persona-for-the-pilot-added-by-t-0012).\n\n",
        "",
    );
    r.put("docs/UX/persona-journey-matrix.md", &matrix);
    let m = messages(&check(r.root()));
    assert!(m.contains("primary-persona"), "{m}");
}

#[test]
fn every_persona_file_is_required_and_named() {
    let r = Repo::new("tree-personas");
    good_tree(&r);
    assert!(check(r.root()).is_empty(), "{}", messages(&check(r.root())));
    fs::remove_file(r.root().join("docs/UX/personas/omar.md")).unwrap();
    let m = messages(&check(r.root()));
    assert!(m.contains("personas/omar.md"), "{m}");
    // the attack registry comes from the master specification, which must be readable and current
    fs::remove_file(r.root().join("docs/SPEC.sha256")).unwrap();
    let m = messages(&check(r.root()));
    assert!(m.contains("attack coverage matrix"), "{m}");
}

// ---------------------------------------------------------------------------------------------- encoding (T-0012 review F-3)

#[test]
fn a_mojibake_sequence_in_a_persona_or_matrix_document_fails() {
    let clean = "# Maya\n\nA dash - and a comma, and a colon: all plain.\n";
    assert!(
        mojibake_findings("docs/UX/personas/maya.md", clean).is_empty(),
        "plain UTF-8 text must pass"
    );
    let bad = "# Maya\n\nAn em dash â€” written after re-encoding.\n";
    let m = messages(&mojibake_findings("docs/UX/personas/maya.md", bad));
    assert!(
        m.contains("mojibake") && m.contains("personas/maya.md"),
        "{m}"
    );
    let atilde = "A broken sequence Ã© in the text.\n";
    let m = messages(&mojibake_findings(
        "docs/UX/persona-journey-matrix.md",
        atilde,
    ));
    assert!(m.contains("mojibake"), "{m}");
}

#[test]
fn a_mojibake_sequence_in_a_shipped_persona_or_the_matrix_fails_the_tree() {
    let r = Repo::new("tree-mojibake");
    good_tree(&r);
    assert!(check(r.root()).is_empty(), "{}", messages(&check(r.root())));
    let matrix = format!("{}\nA broken dash: â€” in the matrix.\n", good_matrix());
    r.put("docs/UX/persona-journey-matrix.md", &matrix);
    let m = messages(&check(r.root()));
    assert!(m.contains("mojibake"), "{m}");
}

// ---------------------------------------------------------------------------------------------- F-4 (review round 2)

#[test]
fn f4_identifier_digits_do_not_make_an_outcome_measurable() {
    for outcome in [
        "see J-02",
        "see S-040",
        "see ATK-001",
        "see T-0012",
        "see Q-059",
        "see B1.1",
        "it works well",
    ] {
        assert!(
            !is_measurable(outcome),
            "`{outcome}` must not be measurable"
        );
    }
}

#[test]
fn f4_units_comparators_and_registry_ids_are_measurable() {
    for outcome in [
        "within 3 minutes",
        "AUD-domain.activated is written",
        "AC-37 passes",
        "10 of 10 attempts",
        "5 clicks",
        "100%",
        "at most 2",
        "under 10 s",
        "within 1 day",
        "zero",
        "0 errors",
    ] {
        assert!(is_measurable(outcome), "`{outcome}` must be measurable");
    }
}

// ---------------------------------------------------------------------------------------------- F-5 (review round 2)

#[test]
fn f5_b11_11_criteria_are_read_from_the_spec_table() {
    let spec = fake_spec();
    let criteria = b11_11_criteria(&spec);
    for criterion in ["1.1.1", "1.3.x", "1.4.4", "2.1.x", "3.3.7", "4.1.2"] {
        assert!(
            criteria.contains(criterion),
            "`{criterion}` missing: {criteria:?}"
        );
    }
    assert!(!criteria.contains("9.9.9"));
}

#[test]
fn f5_a_criterion_counts_only_when_the_b11_11_table_covers_it() {
    let criteria = b11_11_fixture();
    assert!(criterion_is_covered("1.4.4", &criteria));
    assert!(
        criterion_is_covered("2.1.1", &criteria),
        "the 2.1.x entry covers 2.1.1"
    );
    assert!(!criterion_is_covered("9.9.9", &criteria));
}

#[test]
fn f5_an_uncovered_criterion_is_reported_and_does_not_count() {
    let uncovered = good_persona("maya").replace(
        "Mapped to B11.11 criteria: 1.4.4 and 2.1.1.",
        "Mapped to B11.11 criteria: 1.4.4 and 9.9.9; assistive technology: screen magnification.",
    );
    let m = persona_messages("maya", &uncovered);
    assert!(m.contains("9.9.9") && m.contains("not a criterion"), "{m}");
}

#[test]
fn f5_fewer_than_two_covered_criteria_fails() {
    let one = good_persona("maya").replace(
        "Mapped to B11.11 criteria: 1.4.4 and 2.1.1.",
        "Mapped to B11.11 criterion 1.4.4 only.",
    );
    let m = persona_messages("maya", &one);
    assert!(m.contains("at least two"), "{m}");
}

// ---------------------------------------------------------------------------------------------- minor item (review round 2)

#[test]
fn the_primary_persona_row_must_sit_in_the_named_section() {
    let register = "# Open questions for the operator\n\n\
        | Id | Group | Question | Default if unanswered (dev/pilot only) | State | Stored in | Task |\n\
        | --- | --- | --- | --- | --- | --- | --- |\n\
        | Q-999 | UX | Which primary persona do we start from? | Dan | ANSWERED | nowhere | none |\n\n\
        ## Primary persona for the pilot (added by T-0012)\n\n\
        | Question | Default if unanswered (dev/pilot only) | State | Stored in | Task |\n\
        | --- | --- | --- | --- | --- |\n\
        | Which persona is primary for the pilot? | Maya, the site owner (B1.1) | OPEN: no answer yet | `docs/UX/personas/maya.md` | T-0012 |\n";
    let f = primary_persona_findings(register);
    assert!(f.is_empty(), "{}", messages(&f));
}

// ---------------------------------------------------------------------------------------------- F-6/F-7 (review round 3)

#[test]
fn f6_key_journeys_expand_slash_and_range_forms() {
    let spec = "### B1.4 Omar, the platform operator\n\n\
        | Attribute | Detail |\n| --- | --- |\n\
        | Key journeys | J-29 to J-31, J-08/J-09 |\n";
    let ids = key_journeys(spec, "B1.4");
    let want: BTreeSet<String> = ["J-08", "J-09", "J-29", "J-30", "J-31"]
        .iter()
        .map(|journey| (*journey).to_owned())
        .collect();
    assert_eq!(ids, want);
    // the fixture spec declares the journeys its persona files list (F-7)
    assert_eq!(
        key_journeys(&fake_spec(), "B1.1"),
        ["J-01", "J-02"]
            .iter()
            .map(|journey| (*journey).to_owned())
            .collect::<BTreeSet<String>>()
    );
    // B1.7 (the adversary) has no `Key journeys` row and is exempt
    assert!(key_journeys(&fake_spec(), "B1.7").is_empty());
}

#[test]
fn f6_a_declared_key_journey_missing_from_the_matrix_row_fails() {
    let r = Repo::new("f6-matrix");
    good_tree(&r);
    assert!(check(r.root()).is_empty(), "{}", messages(&check(r.root())));
    // the spec declares J-02 for Maya, but its matrix row no longer links her
    let matrix = good_matrix().replace(
        "| J-02 | Journey 2 | [Maya](personas/maya.md) | none |",
        "| J-02 | Journey 2 | [Dan](personas/dan.md) | none |",
    );
    r.put("docs/UX/persona-journey-matrix.md", &matrix);
    let m = messages(&check(r.root()));
    assert!(m.contains("maya") && m.contains("J-02"), "{m}");
}

#[test]
fn f6_a_persona_journey_missing_from_the_matrix_row_fails() {
    let r = Repo::new("f6-persona-list");
    good_tree(&r);
    // maya.md lists J-03 as well, but the J-03 row links Dan only
    let maya = good_persona("maya").replace(
        "- Journeys: [J-01](../../SPEC.md#j-01-journey-1), [J-02](../../SPEC.md#j-02-journey-2).",
        "- Journeys: [J-01](../../SPEC.md#j-01-journey-1), [J-02](../../SPEC.md#j-02-journey-2), [J-03](../../SPEC.md#j-03-journey-3).",
    );
    r.put("docs/UX/personas/maya.md", &maya);
    let m = messages(&check(r.root()));
    assert!(m.contains("maya") && m.contains("J-03"), "{m}");
}

#[test]
fn f6_a_declared_key_journey_missing_from_the_persona_file_fails() {
    let r = Repo::new("f6-file");
    good_tree(&r);
    // the spec declares J-03 for Maya too, but maya.md does not list it
    let spec = fake_spec().replace(
        "| Key journeys | J-01, J-02 |",
        "| Key journeys | J-01, J-02, J-03 |",
    );
    put_spec(&r, &spec);
    let m = messages(&check(r.root()));
    assert!(m.contains("maya") && m.contains("J-03"), "{m}");
}

// ---------------------------------------------------------------------------------------------- T-0013 (pattern review and design requirements)

fn design_findings(text: &str) -> Vec<Finding> {
    let spec = fake_spec();
    design_requirement_findings(
        text,
        Some(&patterns_fixture()),
        Some(&screen_ids(&spec)),
        Some(&component_names(&spec)),
    )
}

fn design_messages(text: &str) -> String {
    messages(&design_findings(text))
}

#[test]
fn t13_a_complete_patterns_document_passes() {
    let f = patterns_findings(&patterns_fixture());
    assert!(f.is_empty(), "{}", messages(&f));
}

#[test]
fn t13_fewer_than_twelve_topics_fail() {
    let text = patterns_fixture().replace("## Topic: Notifications\n\n", "## Notes\n\n");
    let m = messages(&patterns_findings(&text));
    assert!(m.contains("12"), "{m}");
}

#[test]
fn t13_a_topic_missing_a_labeled_part_fails() {
    let text = patterns_fixture().replacen("Pitfalls: The import drops a mail record.\n\n", "", 1);
    let m = messages(&patterns_findings(&text));
    assert!(m.contains("Pitfalls"), "{m}");
}

#[test]
fn t13_a_source_outside_the_allowed_values_fails() {
    let text = patterns_fixture().replacen("Source: first principles", "Source: a vendor blog", 1);
    let m = messages(&patterns_findings(&text));
    assert!(m.contains("Source"), "{m}");
}

#[test]
fn t13_the_status_line_must_be_valid() {
    let missing = patterns_fixture().replace(
        "Status: UNVERIFIED(capability_not_supplied) - the fixture has no fetched source.\n\n",
        "",
    );
    assert!(messages(&patterns_findings(&missing)).contains("Status"));
    let draft = patterns_fixture().replace(
        "Status: UNVERIFIED(capability_not_supplied) - the fixture has no fetched source.",
        "Status: DRAFT",
    );
    assert!(messages(&patterns_findings(&draft)).contains("Status"));
    let empty_reason = patterns_fixture().replace(
        "Status: UNVERIFIED(capability_not_supplied) - the fixture has no fetched source.",
        "Status: UNVERIFIED()",
    );
    assert!(messages(&patterns_findings(&empty_reason)).contains("Status"));
}

#[test]
fn t13_pass_is_rejected_when_every_topic_is_first_principles() {
    let text = patterns_fixture().replace(
        "Status: UNVERIFIED(capability_not_supplied) - the fixture has no fetched source.",
        "Status: PASS",
    );
    let m = messages(&patterns_findings(&text));
    assert!(m.contains("UNVERIFIED"), "{m}");
}

#[test]
fn t13_pass_is_accepted_when_a_topic_has_a_fetched_source() {
    let text = patterns_fixture()
        .replace(
            "Status: UNVERIFIED(capability_not_supplied) - the fixture has no fetched source.",
            "Status: PASS",
        )
        .replacen(
            "Source: first principles",
            "Source: allowlisted public documentation",
            1,
        );
    let f = patterns_findings(&text);
    assert!(f.is_empty(), "{}", messages(&f));
}

#[test]
fn t13_screen_ids_expand_ranges_and_components_are_read() {
    let spec = fake_spec();
    let screens = screen_ids(&spec);
    for id in ["S-010", "S-011", "S-012", "S-013", "S-042", "S-145"] {
        assert!(screens.contains(id), "`{id}` missing: {screens:?}");
    }
    assert!(!screens.contains("S-999"));
    let components = component_names(&spec);
    for name in [
        "Button",
        "IconButton",
        "ConfirmDialog",
        "DataTable",
        "RuleBuilder",
    ] {
        assert!(
            components.contains(name),
            "`{name}` missing: {components:?}"
        );
    }
    assert!(!components.contains("Component"));
}

#[test]
fn t13_a_complete_design_requirements_document_passes() {
    let f = design_requirement_findings(
        &design_requirements_fixture(),
        Some(&patterns_fixture()),
        Some(&screen_ids(&fake_spec())),
        Some(&component_names(&fake_spec())),
    );
    assert!(f.is_empty(), "{}", messages(&f));
}

#[test]
fn t13_missing_design_requirements_are_reported() {
    let text = design_requirements_fixture()
        .lines()
        .filter(|line| !line.starts_with("| DR-07 |"))
        .collect::<Vec<_>>()
        .join("\n");
    let m = design_messages(&text);
    assert!(m.contains("DR-07"), "{m}");
}

#[test]
fn t13_a_repeated_design_requirement_is_reported() {
    let text = design_requirements_fixture().replace("| DR-08 |", "| DR-07 |");
    let m = design_messages(&text);
    assert!(m.contains("DR-07") && m.contains("more than once"), "{m}");
}

#[test]
fn t13_a_requirement_without_a_screen_or_component_fails() {
    let text = design_requirements_fixture().replacen("| S-042, Stepper |", "| none |", 1);
    let m = design_messages(&text);
    assert!(m.contains("DR-01") && m.contains("screen"), "{m}");
}

#[test]
fn t13_an_unknown_screen_id_fails() {
    let text = design_requirements_fixture().replace("S-042, Stepper", "S-999, Stepper");
    let m = design_messages(&text);
    assert!(m.contains("S-999"), "{m}");
}

#[test]
fn t13_a_link_to_a_missing_pattern_anchor_fails() {
    let text = design_requirements_fixture().replace(
        "PATTERNS.md#topic-onboarding",
        "PATTERNS.md#topic-nonexistent",
    );
    let m = design_messages(&text);
    assert!(m.contains("topic-nonexistent"), "{m}");
}

#[test]
fn t13_an_empty_rationale_fails() {
    let text = design_requirements_fixture().replacen(
        "| Rationale 1 keeps the owner in control. |",
        "|  |",
        1,
    );
    let m = design_messages(&text);
    assert!(m.contains("rationale"), "{m}");
}

#[test]
fn t13_a_copied_long_sentence_fails() {
    let long =
        "The review keeps every claim tied to a topic and to a screen so the reader can check it";
    let a = format!("# A\n\n{long}.\n\nA short shared line.\n");
    let b = format!("# B\n\n{long}.\n\nA short shared line.\n");
    let m = messages(&self_copy_findings(&[
        ("docs/UX/A.md", &a),
        ("docs/UX/B.md", &b),
    ]));
    assert!(m.contains("more than 12 words"), "{m}");
    let c = "# C\n\nA short shared line.\n";
    let d = "# D\n\nA short shared line.\n";
    assert!(self_copy_findings(&[("docs/UX/C.md", c), ("docs/UX/D.md", d)]).is_empty());
}

#[test]
fn t13_missing_patterns_or_design_documents_are_named() {
    let r = Repo::new("tree-t13");
    good_tree(&r);
    assert!(check(r.root()).is_empty(), "{}", messages(&check(r.root())));
    fs::remove_file(r.root().join("docs/UX/PATTERNS.md")).unwrap();
    let m = messages(&check(r.root()));
    assert!(m.contains("PATTERNS.md"), "{m}");
    good_tree(&r);
    fs::remove_file(r.root().join("docs/UX/design-requirements.md")).unwrap();
    let m = messages(&check(r.root()));
    assert!(m.contains("design-requirements.md"), "{m}");
}

// ---------------------------------------------------------------------------------------------- F-8/F-9 (review round 2)

#[test]
fn f8_a_component_must_be_a_whole_token() {
    let spec = fake_spec();
    let screens = screen_ids(&spec);
    let components = component_names(&spec);
    let findings = |target: &str| {
        let text = design_requirements_fixture().replace("| S-045, DataTable |", target);
        design_requirement_findings(
            &text,
            Some(&patterns_fixture()),
            Some(&screens),
            Some(&components),
        )
    };
    for invented in ["| DataTableOfDoom |", "| Linked |"] {
        let f = findings(invented);
        let m = messages(&f);
        assert!(
            m.contains("DR-03") && m.contains("component"),
            "{invented}: {m}"
        );
    }
    for accepted in [
        "| DataTable |",
        "| `DataTable` |",
        "| S-045, inventedword |",
    ] {
        let f = findings(accepted);
        assert!(f.is_empty(), "{accepted}: {}", messages(&f));
    }
}

#[test]
fn f9_a_complete_honesty_test_review_passes() {
    let f = patterns_findings(&patterns_fixture());
    assert!(f.is_empty(), "{}", messages(&f));
}

#[test]
fn f9_four_rows_fail() {
    let text = patterns_fixture().replace(
        "| 5 | Undo stated | Yes | The fixture asks for an undo path. |\n",
        "",
    );
    let m = messages(&patterns_findings(&text));
    assert!(m.contains("five"), "{m}");
}

#[test]
fn f9_an_answer_must_be_yes_or_no() {
    let text = patterns_fixture().replacen("| Yes |", "| Maybe |", 1);
    let m = messages(&patterns_findings(&text));
    assert!(m.contains("Yes or No"), "{m}");
}

#[test]
fn f9_an_empty_reason_fails() {
    let text = patterns_fixture().replace("| The fixture shows no data. |", "|  |");
    let m = messages(&patterns_findings(&text));
    assert!(m.contains("Reason"), "{m}");
}

#[test]
fn f9_a_no_blocks_the_document() {
    let text = patterns_fixture().replacen("| Yes |", "| No |", 1);
    let m = messages(&patterns_findings(&text));
    assert!(m.contains("No"), "{m}");
}

#[test]
fn f9_a_missing_honesty_test_section_fails() {
    let text = patterns_fixture().replace("## Honesty-test review", "## Review answers");
    let m = messages(&patterns_findings(&text));
    assert!(m.contains("Honesty-test review"), "{m}");
}

// ---------------------------------------------------------------------------------------------- T-0014 (IA and URL scheme)

#[test]
fn t14_spec_registries_are_read() {
    let spec = fake_spec();
    let permissions = permission_ids(&spec);
    assert!(permissions.contains("PERM-domain.read"));
    assert!(!permissions.contains("PERM-nope.read"));
    let classes = rate_limit_classes(&spec);
    for class in ["auth", "read", "write", "export", "stream", "public"] {
        assert!(classes.contains(class), "`{class}` missing: {classes:?}");
    }
}

#[test]
fn t14_a_complete_routes_file_passes() {
    let (screens, permissions, classes, tokens) = fixture_route_sets();
    let f = routes_findings5(&routes_fixture(), &screens, &permissions, &classes, &tokens);
    assert!(f.is_empty(), "{}", messages(&f));
}

#[test]
fn t14_an_unparseable_routes_file_fails() {
    let m = routes_messages("this is not a route table");
    assert!(m.contains("parse") || m.contains("cannot read"), "{m}");
}

#[test]
fn t14_a_route_lacking_a_key_fails() {
    let text = routes_fixture().replacen("permission = \"public\"\n", "", 1);
    let m = routes_messages(&text);
    assert!(m.contains("permission") || m.contains("missing"), "{m}");
}

#[test]
fn t14_a_value_outside_its_set_fails() {
    let (screens, permissions, classes, tokens) = fixture_route_sets();
    for (from, to, needle) in [
        ("surface = \"public\"", "surface = \"portal\"", "surface"),
        (
            "permission = \"public\"",
            "permission = \"owner\"",
            "permission",
        ),
        (
            "rate_limit_class = \"public\"",
            "rate_limit_class = \"slow\"",
            "rate-limit class",
        ),
        ("methods = [\"GET\"]", "methods = [\"FETCH\"]", "method"),
    ] {
        let text = routes_fixture().replacen(from, to, 1);
        let m = messages(&routes_findings5(
            &text,
            &screens,
            &permissions,
            &classes,
            &tokens,
        ));
        assert!(m.contains(needle), "{from}: {m}");
    }
}

#[test]
fn t14_a_permission_must_exist_in_the_catalog() {
    let (screens, permissions, classes, tokens) = fixture_route_sets();
    let text = routes_fixture().replacen(
        "permission = \"public\"",
        "permission = \"PERM-nope.read\"",
        1,
    );
    let m = messages(&routes_findings5(
        &text,
        &screens,
        &permissions,
        &classes,
        &tokens,
    ));
    assert!(m.contains("PERM-nope.read"), "{m}");
}

#[test]
fn t14_every_screen_must_appear_exactly_once() {
    let (screens, permissions, classes, tokens) = fixture_route_sets();
    let missing = routes_fixture().replace(
        &route_entry(
            "/page-s-001",
            "S-001",
            "public",
            "public",
            &["GET"],
            "public",
        ),
        "",
    );
    let m = messages(&routes_findings5(
        &missing,
        &screens,
        &permissions,
        &classes,
        &tokens,
    ));
    assert!(m.contains("S-001"), "{m}");
    let mut duplicated = routes_fixture();
    duplicated.push_str(&route_entry(
        "/page-s-001-again",
        "S-001",
        "public",
        "public",
        &["GET"],
        "public",
    ));
    let m = messages(&routes_findings5(
        &duplicated,
        &screens,
        &permissions,
        &classes,
        &tokens,
    ));
    assert!(m.contains("S-001") && m.contains("appears 2"), "{m}");
}

#[test]
fn t14_a_route_must_not_cite_an_unknown_screen() {
    let (screens, permissions, classes, tokens) = fixture_route_sets();
    let mut text = routes_fixture();
    text.push_str(&route_entry(
        "/page-s-999",
        "S-999",
        "public",
        "public",
        &["GET"],
        "public",
    ));
    let m = messages(&routes_findings5(
        &text,
        &screens,
        &permissions,
        &classes,
        &tokens,
    ));
    assert!(m.contains("S-999"), "{m}");
}

#[test]
fn t14_pattern_rules_are_checked() {
    let (screens, permissions, classes, tokens) = fixture_route_sets();
    for (pattern, needle) in [
        ("/Page", "uppercase"),
        ("/dns_records", "underscore"),
        ("/domains/", "trailing slash"),
        ("/docs?v=1", "`?`"),
        ("/user@host", "`@`"),
        ("/aaaaaaaaaaaaaaaaaaaaaa", "token-like"),
        ("/invite/{email}", "email"),
    ] {
        let text = route_entry(pattern, "S-001", "public", "public", &["GET"], "public");
        let m = messages(&routes_findings5(
            &text,
            &screens,
            &permissions,
            &classes,
            &tokens,
        ));
        assert!(m.contains(needle), "{pattern}: {m}");
    }
}

#[test]
fn t14_a_token_parameter_must_be_listed_in_the_token_routes_section() {
    let screens: BTreeSet<String> = ["S-001".to_owned()].into_iter().collect();
    let permissions = BTreeSet::new();
    let classes: BTreeSet<String> = ["public".to_owned()].into_iter().collect();
    let text = route_entry(
        "/reset/{token}",
        "S-001",
        "public",
        "public",
        &["GET"],
        "public",
    );
    let unlisted = routes_findings5(&text, &screens, &permissions, &classes, &BTreeSet::new());
    assert!(
        messages(&unlisted).contains("Token routes"),
        "{}",
        messages(&unlisted)
    );
    let listed: BTreeSet<String> = ["/reset/{token}".to_owned()].into_iter().collect();
    let ok = routes_findings5(&text, &screens, &permissions, &classes, &listed);
    assert!(messages(&ok).is_empty(), "{}", messages(&ok));
}

#[test]
fn t14_the_same_pattern_and_method_set_must_not_repeat() {
    let screens: BTreeSet<String> = ["S-001", "S-002"]
        .iter()
        .map(|screen| (*screen).to_owned())
        .collect();
    let permissions = BTreeSet::new();
    let classes: BTreeSet<String> = ["public".to_owned()].into_iter().collect();
    let mut text = route_entry("/dup", "S-001", "public", "public", &["GET"], "public");
    text.push_str(&route_entry(
        "/dup",
        "S-002",
        "public",
        "public",
        &["GET"],
        "public",
    ));
    let m = messages(&routes_findings5(
        &text,
        &screens,
        &permissions,
        &classes,
        &BTreeSet::new(),
    ));
    assert!(m.contains("same pattern") || m.contains("twice"), "{m}");
}

#[test]
fn t14_ia_sections_are_required() {
    assert!(
        ia_findings(&ia_fixture()).is_empty(),
        "{}",
        messages(&ia_findings(&ia_fixture()))
    );
    let missing = ia_fixture().replace("## Redirects", "## Redirect notes");
    assert!(messages(&ia_findings(&missing)).contains("Redirects"));
}

#[test]
fn t14_the_identifier_regex_and_example_are_checked() {
    let no_regex = ia_fixture().replace(
        "Regex: `^(org|dom|usr|rule|ban|evt|whk|key|cert|rpt|inv|apl)_[a-z2-7]{26}$`\n\n",
        "",
    );
    let m = messages(&ia_findings(&no_regex));
    assert!(m.contains("Regex"), "{m}");
    let mismatch = ia_fixture().replace("`org_ab2cd3ef4gh5jk6mn7pq2rs3tu`", "`ORG_invalid`");
    let m = messages(&ia_findings(&mismatch));
    assert!(m.contains("does not match"), "{m}");
}

#[test]
fn t14_url_rules_need_a_test_line_each() {
    let text = ia_fixture().replace("  Test: an uppercase letter fails the route check.\n", "");
    let m = messages(&ia_findings(&text));
    assert!(m.contains("Test:"), "{m}");
}

#[test]
fn t14_missing_ia_or_routes_documents_are_named() {
    let r = Repo::new("tree-t14");
    good_tree(&r);
    assert!(check(r.root()).is_empty(), "{}", messages(&check(r.root())));
    fs::remove_file(r.root().join("docs/UX/IA.md")).unwrap();
    let m = messages(&check(r.root()));
    assert!(m.contains("IA.md"), "{m}");
    good_tree(&r);
    fs::remove_file(r.root().join("docs/UX/routes.toml")).unwrap();
    let m = messages(&check(r.root()));
    assert!(m.contains("routes.toml"), "{m}");
}

// ---------------------------------------------------------------------------------------------- F-10 (review round 2)

fn single_screen_registry() -> (BTreeSet<String>, BTreeSet<String>, BTreeSet<String>) {
    let screens: BTreeSet<String> = ["S-001".to_owned()].into_iter().collect();
    let spec = fake_spec();
    (screens, permission_ids(&spec), rate_limit_classes(&spec))
}

fn consistency_messages(text: &str, exceptions: &BTreeMap<String, BTreeSet<String>>) -> String {
    let (screens, permissions, classes) = single_screen_registry();
    messages(&routes_findings(
        text,
        &screens,
        &permissions,
        &classes,
        &BTreeSet::new(),
        exceptions,
    ))
}

fn exceptions_fixture() -> String {
    format!(
        "{}\n## Rate-class exceptions\n\n| Pattern | Method | Reason |\n| --- | --- | --- |\n| `/x` | POST | a POST that only reads |\n",
        ia_fixture()
    )
}

#[test]
fn f10_a_public_permission_is_rejected_where_a_session_is_expected() {
    let bad_app = route_entry("/x", "S-001", "app", "public", &["GET"], "read");
    assert!(
        consistency_messages(&bad_app, &BTreeMap::new()).contains("F-10a"),
        "app read: {}",
        consistency_messages(&bad_app, &BTreeMap::new())
    );
    let bad_admin = route_entry("/x", "S-001", "admin", "public", &["GET"], "auth");
    assert!(consistency_messages(&bad_admin, &BTreeMap::new()).contains("F-10a"));
    let bad_api = route_entry("/x", "S-001", "api", "public", &["GET"], "public");
    assert!(consistency_messages(&bad_api, &BTreeMap::new()).contains("F-10a"));
    for (surface, class) in [("app", "auth"), ("app", "public"), ("public", "public")] {
        let good = route_entry("/x", "S-001", surface, "public", &["GET"], class);
        let m = consistency_messages(&good, &BTreeMap::new());
        assert!(!m.contains("F-10a"), "{surface}/{class}: {m}");
    }
}

#[test]
fn f10_b_platform_permissions_stay_on_the_admin_surface() {
    let bad_surface = route_entry(
        "/x",
        "S-001",
        "public",
        "PERM-platform.infra.read",
        &["GET"],
        "read",
    );
    assert!(consistency_messages(&bad_surface, &BTreeMap::new()).contains("F-10b"));
    let bad_admin = route_entry("/x", "S-001", "admin", "PERM-domain.read", &["GET"], "read");
    assert!(consistency_messages(&bad_admin, &BTreeMap::new()).contains("F-10b"));
    let good_admin = route_entry(
        "/x",
        "S-001",
        "admin",
        "PERM-platform.infra.read",
        &["GET"],
        "read",
    );
    assert!(!consistency_messages(&good_admin, &BTreeMap::new()).contains("F-10b"));
    let admin_login = route_entry("/x", "S-001", "admin", "public", &["GET"], "auth");
    assert!(!consistency_messages(&admin_login, &BTreeMap::new()).contains("F-10b"));
}

#[test]
fn f10_c_the_rate_class_must_match_the_methods() {
    let bad_post = route_entry("/x", "S-001", "app", "PERM-domain.read", &["POST"], "read");
    assert!(consistency_messages(&bad_post, &BTreeMap::new()).contains("F-10c"));
    let bad_get = route_entry("/x", "S-001", "app", "PERM-domain.read", &["GET"], "write");
    assert!(consistency_messages(&bad_get, &BTreeMap::new()).contains("F-10c"));
    let good_post = route_entry("/x", "S-001", "app", "PERM-domain.read", &["POST"], "write");
    assert!(!consistency_messages(&good_post, &BTreeMap::new()).contains("F-10c"));
    let good_get = route_entry("/x", "S-001", "app", "PERM-domain.read", &["GET"], "read");
    assert!(!consistency_messages(&good_get, &BTreeMap::new()).contains("F-10c"));
}

#[test]
fn f10_rate_class_exceptions_must_match_a_real_route() {
    let ia = exceptions_fixture();
    let exceptions = rate_class_exceptions(&ia);
    assert!(
        exceptions
            .get("/x")
            .is_some_and(|methods| methods.contains("POST"))
    );
    let route = route_entry("/x", "S-001", "app", "PERM-domain.read", &["POST"], "read");
    let covered = consistency_messages(&route, &exceptions);
    assert!(!covered.contains("F-10c"), "{covered}");
    let mut unmatched = exceptions.clone();
    unmatched.insert("/y".to_owned(), ["POST".to_owned()].into_iter().collect());
    let m = consistency_messages(&route, &unmatched);
    assert!(m.contains("F-10c") && m.contains("/y"), "{m}");
}

#[test]
fn f10_a_bad_exception_row_is_reported() {
    let bad_ia = ia_fixture()
        + "\n## Rate-class exceptions\n\n| Pattern | Method | Reason |\n| --- | --- | --- |\n| `/x` | FETCH | a made-up method |\n";
    let m = messages(&ia_findings(&bad_ia));
    assert!(
        m.contains("Rate-class exceptions") && m.contains("FETCH"),
        "{m}"
    );
    let good_ia = exceptions_fixture();
    assert!(ia_findings(&good_ia).is_empty());
}

// ---------------------------------------------------------------------------------------------- T-0015 (navigation)

#[test]
fn t15_a_complete_navigation_document_passes() {
    let m = messages(&navigation_findings(
        &navigation_fixture(),
        &fixture_route_permissions(),
        &shortcut_list(&fake_spec()),
    ));
    assert!(m.is_empty(), "{m}");
}

#[test]
fn t15_the_shortcut_list_is_read_from_b23() {
    let shortcuts = shortcut_list(&fake_spec());
    for expected in [
        "g o",
        "g d",
        "g e",
        "g b",
        "/",
        "c",
        "esc",
        "?",
        "ctrl/cmd+k",
    ] {
        assert!(shortcuts.contains(expected), "`{expected}`: {shortcuts:?}");
    }
}

#[test]
fn t15_a_missing_section_fails() {
    let text = navigation_fixture().replace("## Breadcrumbs", "## Crumb trail");
    let m = navigation_messages(&text);
    assert!(m.contains("Breadcrumbs"), "{m}");
}

#[test]
fn t15_an_empty_keyboard_or_aria_cell_fails() {
    let keyboard =
        navigation_fixture().replacen("| Tab, Enter | navigation | |", "|  | navigation | |", 1);
    let m = navigation_messages(&keyboard);
    assert!(m.to_lowercase().contains("keyboard"), "{m}");
    let aria =
        navigation_fixture().replacen("| Tab, Enter | navigation | |", "| Tab, Enter |  | |", 1);
    let m = navigation_messages(&aria);
    assert!(m.to_lowercase().contains("aria"), "{m}");
}

#[test]
fn t15_a_route_outside_the_route_table_fails() {
    let text = navigation_fixture().replace(
        "| Sidebar · Domains | /page-s-041 | public |",
        "| Sidebar · Domains | /page-missing | PERM-domain.read |",
    );
    let m = navigation_messages(&text);
    assert!(m.contains("/page-missing"), "{m}");
}

#[test]
fn t15_a_permission_that_differs_from_the_route_fails() {
    let text = navigation_fixture().replace(
        "| Sidebar · Domains | /page-s-041 | public |",
        "| Sidebar · Domains | /page-s-041 | PERM-domain.read |",
    );
    let m = navigation_messages(&text);
    assert!(
        m.to_lowercase().contains("permission") && m.contains("/page-s-041"),
        "{m}"
    );
}

#[test]
fn t15_a_missing_sidebar_item_tab_or_control_fails() {
    let sidebar = navigation_fixture().replace(
        "| Sidebar · Settings | /page-s-086 | public | Tab, Enter | navigation | |\n",
        "",
    );
    let m = navigation_messages(&sidebar);
    assert!(
        m.to_lowercase().contains("sidebar") && m.contains("Settings"),
        "{m}"
    );
    let tab = navigation_fixture().replace(
        "| Tab · Origin | /page-s-052 | public | Arrow keys, Home, End | tab | |\n",
        "",
    );
    let m = navigation_messages(&tab);
    assert!(
        m.to_lowercase().contains("tab") && m.contains("Origin"),
        "{m}"
    );
    let control = navigation_fixture().replace(
        "| Top bar · Help menu | - | - | Tab, Enter | menu | |\n",
        "",
    );
    let m = navigation_messages(&control);
    assert!(m.contains("Help menu"), "{m}");
}

#[test]
fn t15_the_shortcut_map_must_cover_b23_and_not_conflict() {
    let missing = navigation_fixture().replace("| `g o` | Go to Overview | Global |\n", "");
    let m = navigation_messages(&missing);
    assert!(m.contains("g o"), "{m}");
    let conflict = navigation_fixture().replace(
        "| `Ctrl/Cmd+K` | Open the command palette | Global |\n",
        "| `Ctrl/Cmd+R` | Open the command palette | Global |\n",
    );
    let m = navigation_messages(&conflict).to_lowercase();
    assert!(m.contains("reserved") && m.contains("ctrl/cmd+r"), "{m}");
    let duplicate = navigation_fixture().replace(
        "| `g d` | Go to Domains | Global |\n",
        "| `g o` | Go to Domains | Global |\n",
    );
    let m = navigation_messages(&duplicate);
    assert!(m.contains("g o"), "{m}");
    let few = navigation_fixture()
        .replace("| F5 | Reload |\n", "")
        .replace("| F6 | Address bar |\n", "")
        .replace("| Shift+Tab | Reverse focus |\n", "");
    let m = navigation_messages(&few).to_lowercase();
    assert!(m.contains("ten"), "{m}");
}

#[test]
fn t15_restricted_states_focus_and_mobile_are_required() {
    let restricted = navigation_fixture().replace("| plan-limited |", "| plan-gated |");
    assert!(navigation_messages(&restricted).contains("plan-limited"));
    let focus = navigation_fixture().replace("### Partial swaps", "### Swaps");
    assert!(navigation_messages(&focus).contains("Partial swaps"));
    let mobile = navigation_fixture().replace("### 480 px", "### 480px");
    assert!(navigation_messages(&mobile).contains("480 px"));
}

#[test]
fn t15_a_hover_only_row_fails() {
    let text = navigation_fixture().replace(
        "| Opened by keyboard; hover is not required. |",
        "| Opens on hover. |",
    );
    let m = navigation_messages(&text).to_lowercase();
    assert!(m.contains("hover"), "{m}");
}

#[test]
fn t15_wireframes_are_required() {
    let text: String = navigation_fixture()
        .lines()
        .filter(|line| !line.trim_start().starts_with("```"))
        .collect::<Vec<_>>()
        .join("\n");
    let m = navigation_messages(&text).to_lowercase();
    assert!(m.contains("wireframe"), "{m}");
}

#[test]
fn t15_missing_navigation_document_is_named() {
    let r = Repo::new("tree-t15");
    good_tree(&r);
    assert!(check(r.root()).is_empty(), "{}", messages(&check(r.root())));
    fs::remove_file(r.root().join("docs/UX/NAVIGATION.md")).unwrap();
    let m = messages(&check(r.root()));
    assert!(m.contains("NAVIGATION.md"), "{m}");
}

// ---------------------------------------------------------------------------------------------- F-11 (review round 2)

#[test]
fn f11_a_bound_default_needs_a_documented_conflict_row() {
    let text = navigation_fixture().replace(
        "| `/` | The browser quick find. | The search field may not receive focus. | The Search / command palette button opens the search; shortcuts can be turned off in preferences. |\n",
        "",
    );
    let m = navigation_messages(&text);
    assert!(
        m.contains('`') && m.to_lowercase().contains("documented conflicts"),
        "{m}"
    );
}

#[test]
fn f11_an_empty_conflict_mitigation_fails() {
    let text = navigation_fixture().replace(
        "| The Search / command palette button opens the palette; shortcuts can be turned off in preferences. |",
        "|  |",
    );
    let m = navigation_messages(&text);
    assert!(m.to_lowercase().contains("mitigation"), "{m}");
}

#[test]
fn f11_a_mitigation_must_name_a_navigable_element() {
    let text = navigation_fixture().replace(
        "| The Search / command palette button opens the palette; shortcuts can be turned off in preferences. |",
        "| The moon button opens the palette; shortcuts can be turned off in preferences. |",
    );
    let m = navigation_messages(&text);
    assert!(
        m.to_lowercase().contains("mitigation") && m.to_lowercase().contains("element"),
        "{m}"
    );
}

#[test]
fn f11_a_mitigation_must_say_shortcuts_can_be_turned_off() {
    let text = navigation_fixture().replace(
        "The Search / command palette button opens the palette; shortcuts can be turned off in preferences.",
        "The Search / command palette button opens the palette.",
    );
    let m = navigation_messages(&text);
    assert!(m.to_lowercase().contains("turned off"), "{m}");
}

#[test]
fn f11_a_stale_conflict_row_fails() {
    let stale = "| `Ctrl/Cmd+Q` | The browser quit shortcut. | The palette is unaffected. | The Sidebar · Domains item; shortcuts can be turned off in preferences. |\n";
    let text =
        navigation_fixture().replace("| `g`, `c`, `?` |", &format!("{stale}| `g`, `c`, `?` |"));
    let m = navigation_messages(&text);
    assert!(m.to_lowercase().contains("stale"), "{m}");
}

#[test]
fn f11_a_missing_only_path_sentence_fails() {
    let text = navigation_fixture().replace(
        "The shortcut map is a convenience, never the only path; every function is reachable from a control in the elements table. ",
        "",
    );
    let m = navigation_messages(&text);
    assert!(
        m.to_lowercase().contains("convenience") || m.to_lowercase().contains("only path"),
        "{m}"
    );
}

// ---------------------------------------------------------------------------------------------- T-0016 (journey maps)

#[test]
fn t16_spec_registries_are_read() {
    let spec = fake_spec();
    let titles = journey_headings(&spec);
    assert_eq!(
        titles.get("J-01").map(String::as_str),
        Some("Visitor discovers HDD and reads honest claims")
    );
    let errors = error_catalog(&spec);
    assert_eq!(errors.get("ERR-AUTH-002"), Some(&401));
    assert_eq!(errors.get("ERR-SYS-001"), Some(&503));
    assert!(audit_ids(&spec).contains("AUD-auth.signup"));
    assert!(
        matrix_personas(&good_matrix())
            .get("J-03")
            .is_some_and(|set| set.contains("dan"))
    );
    assert!(proposed_screens(&spec_patches_fixture()).contains("S-149"));
}

#[test]
fn t16_a_complete_journey_passes() {
    for journey in FIXTURE_JOURNEYS {
        let text = journey_fixture(&journey);
        let m = journey_messages(&text, journey.id);
        assert!(m.is_empty(), "{}: {m}", journey.id);
    }
}

#[test]
fn t16_a_changed_title_fails() {
    let text = journey_fixture(&FIXTURE_JOURNEYS[0]).replace(
        "# J-01 Visitor discovers HDD and reads honest claims",
        "# J-01 Something else",
    );
    let m = journey_messages(&text, "J-01");
    assert!(m.contains("title"), "{m}");
}

#[test]
fn t16_a_changed_persona_link_fails() {
    let text =
        journey_fixture(&FIXTURE_JOURNEYS[0]).replace("../personas/maya.md", "../personas/dan.md");
    let m = journey_messages(&text, "J-01");
    assert!(m.to_lowercase().contains("persona"), "{m}");
}

#[test]
fn t16_a_short_steps_table_fails() {
    let text: String = journey_fixture(&FIXTURE_JOURNEYS[0])
        .lines()
        .filter(|line| !line.starts_with("| 8 |"))
        .collect::<Vec<_>>()
        .join("\n");
    let m = journey_messages(&text, "J-01");
    assert!(m.to_lowercase().contains("at least 8"), "{m}");
}

#[test]
fn t16_an_empty_step_cell_fails() {
    let text = journey_fixture(&FIXTURE_JOURNEYS[0]).replacen(
        "| none | ERR-AUTH-002: Wrong password",
        "|  | ERR-AUTH-002: Wrong password",
        1,
    );
    let m = journey_messages(&text, "J-01");
    assert!(m.to_lowercase().contains("empty"), "{m}");
}

#[test]
fn t16_step_value_rules_fail() {
    let base = journey_fixture(&FIXTURE_JOURNEYS[0]);
    let bad_screen = base.replace("| S-006 | none |", "| S-999 | none |");
    assert!(journey_messages(&bad_screen, "J-01").contains("S-999"));
    let bad_emotion = base.replacen("| calm |", "| happy |", 1);
    assert!(journey_messages(&bad_emotion, "J-01").contains("happy"));
    let bad_copy = base.replacen("| j-01-step1-title |", "| Step one |", 1);
    assert!(
        journey_messages(&bad_copy, "J-01")
            .to_lowercase()
            .contains("copy key")
    );
    let bad_error = base.replacen("ERR-AUTH-002", "ERR-NOPE-001", 1);
    assert!(journey_messages(&bad_error, "J-01").contains("ERR-NOPE-001"));
    let server_error = base.replacen("ERR-AUTH-002", "ERR-SYS-001", 1);
    assert!(
        journey_messages(&server_error, "J-01")
            .to_lowercase()
            .contains("5xx")
    );
    let declared_server = base.replace("ERR-AUTH-002", "System error: ERR-SYS-001; retry later");
    assert!(
        !journey_messages(&declared_server, "J-01")
            .to_lowercase()
            .contains("5xx")
    );
}

#[test]
fn t16_a_spec_mentioned_screen_must_appear() {
    let text = journey_fixture(&FIXTURE_JOURNEYS[1]).replace("S-035", "S-022");
    let m = journey_messages(&text, "J-02");
    assert!(m.contains("S-035"), "{m}");
}

#[test]
fn t16_a_spec_ac_must_appear_in_success() {
    let text = journey_fixture(&FIXTURE_JOURNEYS[2]).replace("Checks: AC-35.", "Checks: none.");
    let m = journey_messages(&text, "J-03");
    assert!(m.contains("AC-35"), "{m}");
}

#[test]
fn t16_trust_security_and_accessibility_rules() {
    let base = journey_fixture(&FIXTURE_JOURNEYS[0]);
    let one_trust: String = base
        .lines()
        .filter(|line| !line.starts_with("| 2 | The limit is stated."))
        .collect::<Vec<_>>()
        .join("\n");
    assert!(
        journey_messages(&one_trust, "J-01")
            .to_lowercase()
            .contains("trust")
    );
    let bad_atk = base.replace("ATK-001", "ATK-999");
    assert!(journey_messages(&bad_atk, "J-01").contains("ATK-999"));
    let missing_accessibility: String = base
        .lines()
        .filter(|line| !line.starts_with("| 3 | The new h1"))
        .collect::<Vec<_>>()
        .join("\n");
    assert!(
        journey_messages(&missing_accessibility, "J-01")
            .to_lowercase()
            .contains("accessibility")
    );
}

#[test]
fn t16_a_missing_screen_must_be_proposed() {
    let text = journey_fixture(&FIXTURE_JOURNEYS[0]).replace("S-006", "S-150");
    let m = journey_messages(&text, "J-01");
    assert!(
        m.contains("S-150") && m.to_lowercase().contains("spec-patches"),
        "{m}"
    );
}

#[test]
fn t16_patches_rules() {
    let parts = journey_parts();
    let journeys: BTreeSet<String> = parts.titles.keys().cloned().collect();
    let mut needed: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    needed.insert(
        "S-149".to_owned(),
        ["J-08".to_owned()].into_iter().collect(),
    );
    let ok = patches_findings(&spec_patches_fixture(), &parts.screens, &journeys, &needed);
    assert!(messages(&ok).is_empty(), "{}", messages(&ok));
    let existing = spec_patches_fixture().replace("| S-149 |", "| S-041 |");
    let m = messages(&patches_findings(
        &existing,
        &parts.screens,
        &journeys,
        &needed,
    ));
    assert!(m.contains("S-041"), "{m}");
    let invented = spec_patches_fixture().replace("| J-08 |", "| J-99 |");
    let m = messages(&patches_findings(
        &invented,
        &parts.screens,
        &journeys,
        &needed,
    ));
    assert!(m.contains("J-99"), "{m}");
    let stale = spec_patches_fixture().replace("| J-08 |", "| J-01 |");
    let m = messages(&patches_findings(
        &stale,
        &parts.screens,
        &journeys,
        &needed,
    ));
    assert!(m.contains("S-149"), "{m}");
}

#[test]
fn t16_missing_journey_file_is_named() {
    let r = Repo::new("tree-t16");
    good_tree(&r);
    assert!(check(r.root()).is_empty(), "{}", messages(&check(r.root())));
    fs::remove_file(r.root().join("docs/UX/journeys/J-03.md")).unwrap();
    let m = messages(&check(r.root()));
    assert!(m.contains("J-03"), "{m}");
}

// ---------------------------------------------------------------------------------------------- F-12 (review round 2)

#[test]
fn f12_a_sentence_is_required_after_the_code() {
    let text = journey_fixture(&FIXTURE_JOURNEYS[0]).replacen(
        "ERR-AUTH-002: Wrong password or unknown email is rejected with the same error.",
        "ERR-AUTH-002",
        1,
    );
    let m = journey_messages(&text, "J-01");
    assert!(m.to_lowercase().contains("sentence"), "{m}");
}

#[test]
fn f12_a_short_sentence_fails() {
    let text = journey_fixture(&FIXTURE_JOURNEYS[0]).replacen(
        "ERR-AUTH-002: Wrong password or unknown email is rejected with the same error.",
        "ERR-AUTH-002: Wrong password rejected.",
        1,
    );
    let m = journey_messages(&text, "J-01");
    assert!(m.to_lowercase().contains("six"), "{m}");
}

#[test]
fn f12_a_sentence_unrelated_to_the_code_fails() {
    let text = journey_fixture(&FIXTURE_JOURNEYS[0]).replacen(
        "ERR-AUTH-002: Wrong password or unknown email is rejected with the same error.",
        "ERR-AUTH-002: The dashboard reloads after a long pause.",
        1,
    );
    let m = journey_messages(&text, "J-01");
    assert!(m.contains("B7"), "{m}");
}

#[test]
fn f12_a_sentence_unrelated_to_the_step_fails() {
    let text = journey_fixture(&FIXTURE_JOURNEYS[0]).replacen(
        "ERR-AUTH-002: Wrong password or unknown email is rejected with the same error.",
        "ERR-AUTH-002: An incorrect password is refused for that credential.",
        1,
    );
    let m = journey_messages(&text, "J-01");
    assert!(m.to_lowercase().contains("step"), "{m}");
}

#[test]
fn f12_a_fitting_sentence_passes() {
    let text = journey_fixture(&FIXTURE_JOURNEYS[0]);
    let m = journey_messages(&text, "J-01");
    assert!(!m.contains("F-12"), "{m}");
}

// ---------------------------------------------------------------------------------------------- T-0016 cutover safety (J-08, J-09)

#[test]
fn t16_cutover_safety_is_required_for_j08_and_j09() {
    let text =
        journey_fixture(&FIXTURE_JOURNEYS[7]).replace("## Cutover safety", "## Cutover notes");
    let m = journey_messages(&text, "J-08");
    assert!(m.contains("Cutover safety"), "{m}");
}

#[test]
fn t16_cutover_needs_four_non_empty_rows() {
    let text: String = journey_fixture(&FIXTURE_JOURNEYS[7])
        .lines()
        .filter(|line| {
            !line.starts_with("| 2 | The live site")
                && !line.starts_with("| 3 | The live site")
                && !line.starts_with("| 4 | The live site")
        })
        .collect::<Vec<_>>()
        .join("\n");
    let m = journey_messages(&text, "J-08");
    assert!(m.to_lowercase().contains("four"), "{m}");
}

#[test]
fn t16_cutover_guard_and_undo_need_a_control() {
    let guard = journey_fixture(&FIXTURE_JOURNEYS[7]).replace(
        "| Preview and the parity check run before the change. |",
        "| Wait and hope. |",
    );
    let m = journey_messages(&guard, "J-08");
    assert!(m.to_lowercase().contains("guard"), "{m}");
    let undo = journey_fixture(&FIXTURE_JOURNEYS[7]).replace(
        "| Undo with the instant return path of R-19 and the rollback instructions. |",
        "| Nothing. |",
    );
    let m = journey_messages(&undo, "J-08");
    assert!(m.to_lowercase().contains("undo"), "{m}");
}

#[test]
fn t16_cutover_row_is_needed_per_dns_step() {
    let text: String = journey_fixture(&FIXTURE_JOURNEYS[7])
        .lines()
        .filter(|line| !line.starts_with("| 2 | The live site"))
        .collect::<Vec<_>>()
        .join("\n");
    let m = journey_messages(&text, "J-08");
    assert!(
        m.contains("step 2") || m.to_lowercase().contains("dns"),
        "{m}"
    );
}

// ---------------------------------------------------------------------------------------------- T-0017 pass 1 (journeys_ops)

fn ops_messages(text: &str, id: &str) -> String {
    messages(&journeys_ops::ops_findings(
        text,
        id,
        &journeys_ops::attack_texts(&fake_spec()),
    ))
}

#[test]
fn t17_a_complete_safeguarded_journey_passes() {
    for journey in FIXTURE_JOURNEYS
        .iter()
        .filter(|journey| journey.id >= "J-13")
    {
        let text = journey_fixture(journey);
        let m = ops_messages(&text, journey.id);
        assert!(m.is_empty(), "{}: {m}", journey.id);
    }
}

#[test]
fn t17_safeguards_section_and_risky_rows_are_required() {
    let no_section =
        journey_fixture(&FIXTURE_JOURNEYS[12]).replace("## Safeguards", "## Guard rails");
    assert!(ops_messages(&no_section, "J-13").contains("Safeguards"));
    let no_row: String = journey_fixture(&FIXTURE_JOURNEYS[12])
        .lines()
        .filter(|line| !line.starts_with("| 1 | Changes the live setting."))
        .collect::<Vec<_>>()
        .join("\n");
    assert!(
        ops_messages(&no_row, "J-13")
            .to_lowercase()
            .contains("risky")
    );
}

#[test]
fn t17_safeguard_kind_copy_length_and_claims_are_checked() {
    let bad_kind = journey_fixture(&FIXTURE_JOURNEYS[12]).replace("| preview |", "| unsafe |");
    assert!(ops_messages(&bad_kind, "J-13").contains("Kind"));
    let long_copy = journey_fixture(&FIXTURE_JOURNEYS[12]).replace(
        "| Review step 1 of J-13 before it applies; the history keeps the previous value for undo. |",
        "| Review the change before it applies and then read every consequence in the panel, the parity report and the readiness list, and undo it from the history when you are ready to continue. |",
    );
    assert!(ops_messages(&long_copy, "J-13").contains("25"));
    let claims = journey_fixture(&FIXTURE_JOURNEYS[12]).replace(
        "| Review step 1 of J-13 before it applies; the history keeps the previous value for undo. |",
        "| This gives you complete protection with no gaps at all. |",
    );
    assert!(
        ops_messages(&claims, "J-13")
            .to_lowercase()
            .contains("claims")
    );
}

#[test]
fn t17_what_could_go_wrong_needs_three_rows() {
    let text: String = journey_fixture(&FIXTURE_JOURNEYS[12])
        .lines()
        .filter(|line| {
            !line.starts_with("| 2 | A record is saved")
                && !line.starts_with("| 3 | The user leaves")
        })
        .collect::<Vec<_>>()
        .join("\n");
    assert!(ops_messages(&text, "J-13").to_lowercase().contains("three"));
}

#[test]
fn t17_protection_journeys_need_three_atk_rows() {
    let text: String = journey_fixture(&FIXTURE_JOURNEYS[15])
        .lines()
        .filter(|line| !line.starts_with("| 3 | A probe reaches"))
        .collect::<Vec<_>>()
        .join("\n");
    assert!(
        ops_messages(&text, "J-16")
            .to_lowercase()
            .contains("three atk")
    );
}

#[test]
fn t17_decision_support_needs_five_items() {
    let text =
        journey_fixture(&FIXTURE_JOURNEYS[15]).replace("## Decision support", "## Decision notes");
    assert!(ops_messages(&text, "J-16").contains("Decision support"));
    let fewer: String = journey_fixture(&FIXTURE_JOURNEYS[15])
        .lines()
        .filter(|line| !line.starts_with("- The honest warning about shared IPs"))
        .collect::<Vec<_>>()
        .join("\n");
    assert!(ops_messages(&fewer, "J-16").to_lowercase().contains("five"));
}

#[test]
fn t17_atk_family_must_match_the_step() {
    let text = journey_fixture(&FIXTURE_JOURNEYS[12]).replace("ATK-008", "ATK-001");
    let mut families = BTreeMap::new();
    families.insert("ATK-001".to_owned(), "SQL injection tautology".to_owned());
    let m = messages(&journeys_ops::ops_findings(&text, "J-13", &families));
    assert!(m.to_lowercase().contains("family"), "{m}");
}

#[test]
fn t17_attack_texts_are_read_from_the_c5_rows_despite_the_heading_dot() {
    let texts = journeys_ops::attack_texts(&fake_spec());
    assert_eq!(texts.get("ATK-001").map(String::as_str), Some("an attack"));
    assert!(
        texts.len() >= 10,
        "the C5 fixture rows must be read: {texts:?}"
    );
}

#[test]
fn t17_risky_step_matches_whole_tokens_not_substrings() {
    assert!(!journeys_ops::risky_step(
        "Opens the presets.",
        "The page lists the current state."
    ));
    assert!(!journeys_ops::risky_step(
        "Copies the firewall address list.",
        "The page shows the addresses."
    ));
    assert!(journeys_ops::risky_step(
        "Sets the protection mode.",
        "The page shows the preset."
    ));
    assert!(journeys_ops::risky_step(
        "Adds a rule condition.",
        "The page shows the test."
    ));
    assert!(journeys_ops::risky_step(
        "Toggles the proxy state.",
        "The mail records stay grey."
    ));
}

#[test]
fn t16_audit_ids_expand_the_slash_alternatives_of_b8() {
    let spec = "### B8. Audit event taxonomy\n\n| Event | Fields | Notes |\n| --- | --- | --- |\n| AUD-waf.rule_created / updated / deleted | rule | rule |\n| AUD-appeal.submitted / resolved | appeal | appeal |\n| AUD-origin.updated / tested / lockdown_applied | site | site |\n| AUD-bypass.probe_run | site | site |\n";
    let ids = audit_ids(spec);
    assert!(ids.contains("AUD-waf.rule_created"), "{ids:?}");
    assert!(ids.contains("AUD-waf.rule_updated"), "{ids:?}");
    assert!(ids.contains("AUD-appeal.resolved"), "{ids:?}");
    assert!(ids.contains("AUD-origin.lockdown_applied"), "{ids:?}");
    assert!(ids.contains("AUD-bypass.probe_run"), "{ids:?}");
}

#[test]
fn t17_operator_questions_stay_open_and_are_cited() {
    let journeys = vec![
        ("J-16".to_owned(), journey_fixture(&FIXTURE_JOURNEYS[15])),
        ("J-23".to_owned(), journey_fixture(&FIXTURE_JOURNEYS[22])),
    ];
    let ok = journeys_ops::operator_questions_findings(&good_register(), &journeys);
    assert!(ok.is_empty(), "{}", messages(&ok));
    let uncited: Vec<(String, String)> = journeys
        .iter()
        .map(|(id, text)| {
            (
                id.clone(),
                text.replace("Question: Should the monitor-to-block switch use a scheduled switch with typed confirmation? See OPERATOR-QUESTIONS.md.", ""),
            )
        })
        .collect();
    let missing = journeys_ops::operator_questions_findings(&good_register(), &uncited);
    assert!(
        messages(&missing).to_lowercase().contains("question"),
        "{}",
        messages(&missing)
    );
    let not_open = good_register().replace(
        "| Scheduled switch with typed confirmation | OPEN |",
        "| Scheduled switch with typed confirmation | DRAFT |",
    );
    let m = journeys_ops::operator_questions_findings(&not_open, &journeys);
    assert!(messages(&m).contains("OPEN"), "{}", messages(&m));
}

// ---------------------------------------------------------------------------------------------- T-0017 pass 2 (J-19 to J-24)

#[test]
fn t17_j19_rule_builder_error_taxonomy_is_checked() {
    let base = journey_fixture(&FIXTURE_JOURNEYS[18]);
    assert!(
        ops_messages(&base, "J-19").is_empty(),
        "{}",
        ops_messages(&base, "J-19")
    );
    let missing = base.replace("## Rule builder error taxonomy", "## Rule builder notes");
    assert!(
        ops_messages(&missing, "J-19").contains("taxonomy"),
        "{}",
        ops_messages(&missing, "J-19")
    );
    let no_semantic: String = base
        .lines()
        .filter(|line| !line.starts_with("| semantic |"))
        .collect::<Vec<_>>()
        .join("\n");
    assert!(
        ops_messages(&no_semantic, "J-19")
            .to_lowercase()
            .contains("semantic"),
        "{}",
        ops_messages(&no_semantic, "J-19")
    );
    let bad_key = base.replace("rule-syntax-bracket", "Rule Syntax Bracket");
    assert!(
        ops_messages(&bad_key, "J-19").contains("copy key"),
        "{}",
        ops_messages(&bad_key, "J-19")
    );
}

#[test]
fn t17_j22_abuse_cases_need_five_rows_with_known_atks() {
    let base = journey_fixture(&FIXTURE_JOURNEYS[21]);
    assert!(
        ops_messages(&base, "J-22").is_empty(),
        "{}",
        ops_messages(&base, "J-22")
    );
    let fewer: String = base
        .lines()
        .filter(|line| {
            !line.starts_with("| A script fills") && !line.starts_with("| An appeal is used")
        })
        .collect::<Vec<_>>()
        .join("\n");
    assert!(
        ops_messages(&fewer, "J-22").to_lowercase().contains("five"),
        "{}",
        ops_messages(&fewer, "J-22")
    );
    let bad_atk = base.replace("ATK-003", "ATK-999");
    assert!(
        ops_messages(&bad_atk, "J-22").contains("ATK-999"),
        "{}",
        ops_messages(&bad_atk, "J-22")
    );
}

#[test]
fn t17_j23_owner_outcomes_are_the_four_choices() {
    let base = journey_fixture(&FIXTURE_JOURNEYS[22]);
    assert!(
        ops_messages(&base, "J-23").is_empty(),
        "{}",
        ops_messages(&base, "J-23")
    );
    let missing = base.replace(
        "- Decline the appeal with a reason and send a neutral message to the visitor.",
        "- Close the appeal.",
    );
    assert!(
        ops_messages(&missing, "J-23")
            .to_lowercase()
            .contains("decline"),
        "{}",
        ops_messages(&missing, "J-23")
    );
}

#[test]
fn t17_j24_stacks_are_conceptual_and_cover_every_stack() {
    let base = journey_fixture(&FIXTURE_JOURNEYS[23]);
    assert!(
        ops_messages(&base, "J-24").is_empty(),
        "{}",
        ops_messages(&base, "J-24")
    );
    let no_nft: String = base
        .lines()
        .filter(|line| !line.starts_with("| nftables |"))
        .collect::<Vec<_>>()
        .join("\n");
    assert!(
        ops_messages(&no_nft, "J-24").contains("nftables"),
        "{}",
        ops_messages(&no_nft, "J-24")
    );
    let code = base.replace(
        "## Stacks\n",
        "## Stacks\n\n```\nnft add rule inet filter input accept\n```\n",
    );
    assert!(
        ops_messages(&code, "J-24").contains("command"),
        "{}",
        ops_messages(&code, "J-24")
    );
}

#[test]
fn t17_j24_verification_probes_need_four_probes() {
    let base = journey_fixture(&FIXTURE_JOURNEYS[23]);
    let fewer: String = base
        .lines()
        .filter(|line| {
            !line.starts_with("| A request with a wrong secret")
                && !line.starts_with("| A request from the proxy path")
        })
        .collect::<Vec<_>>()
        .join("\n");
    assert!(
        ops_messages(&fewer, "J-24").to_lowercase().contains("four"),
        "{}",
        ops_messages(&fewer, "J-24")
    );
    let empty_cell = base.replace(
        "| A direct request to the origin address. | The origin still answers without the proxy. | Whether the owner's own network is allowed. |",
        "| A direct request to the origin address. | The origin still answers without the proxy. |  |",
    );
    assert!(
        ops_messages(&empty_cell, "J-24").contains("cannot prove"),
        "{}",
        ops_messages(&empty_cell, "J-24")
    );
}

// ---------------------------------------------------------------------------------------------- T-0018 (journeys_ext)

/// Findings of one journey text against the T-0018 extension context built from the fixture spec.
fn ext_messages(text: &str, id: &str) -> String {
    let parts = journey_parts();
    let ctx = journeys_ext::ExtContext {
        screens: &parts.screens,
        permissions: &parts.permissions,
        audits: &parts.audits,
    };
    messages(&journeys_ext::ext_findings(text, id, &ctx))
}

/// Findings of one dependency document against the fixture task graph.
fn dependency_messages(text: &str) -> String {
    let spec = fake_spec();
    let model = crate::tasks::parse(&spec).expect("fixture tasks parse");
    let order = crate::tasks::order(&model).expect("fixture task order");
    let journeys: BTreeSet<String> = JOURNEYS_IN_SCOPE
        .iter()
        .map(|id| (*id).to_owned())
        .collect();
    messages(&journeys_ext::dependencies_findings(
        text, &journeys, &model, &order,
    ))
}

/// The fixture journey with a list of lines removed (a mutation helper for the negative tests).
fn without_lines(text: &str, prefixes: &[&str]) -> String {
    text.lines()
        .filter(|line| !prefixes.iter().any(|prefix| line.starts_with(prefix)))
        .collect::<Vec<_>>()
        .join("\n")
}

#[test]
fn t18_the_extension_journeys_pass_the_extension_rules() {
    for journey in FIXTURE_JOURNEYS
        .iter()
        .filter(|journey| journey.id >= "J-25")
    {
        let text = journey_fixture(journey);
        let m = ext_messages(&text, journey.id);
        assert!(m.is_empty(), "{}: {m}", journey.id);
    }
    let m = dependency_messages(&journey_dependencies_fixture());
    assert!(m.is_empty(), "{m}");
}

#[test]
fn t18_stress_cases_need_the_three_named_cases() {
    let base = journey_fixture(&FIXTURE_JOURNEYS[24]);
    assert!(ext_messages(&base, "J-25").is_empty());
    let missing = without_lines(&base, &["| keyboard only |"]);
    assert!(
        ext_messages(&missing, "J-25").contains("keyboard only"),
        "{}",
        ext_messages(&missing, "J-25")
    );
    let duplicate = base.replace("| small screen |", "| low bandwidth |");
    assert!(
        ext_messages(&duplicate, "J-25").contains("exactly once"),
        "{}",
        ext_messages(&duplicate, "J-25")
    );
    let empty = base.replace(
        "| low bandwidth | The page loads its text before its images. | The checklist and its actions stay reachable. |",
        "| low bandwidth |  | The checklist and its actions stay reachable. |",
    );
    assert!(
        ext_messages(&empty, "J-25")
            .to_lowercase()
            .contains("empty"),
        "{}",
        ext_messages(&empty, "J-25")
    );
    let unknown = base.replace("| keyboard only |", "| tiny screen |");
    assert!(
        ext_messages(&unknown, "J-25").contains("tiny screen"),
        "{}",
        ext_messages(&unknown, "J-25")
    );
}

#[test]
fn t18_readiness_weights_fix_links_and_footnote_are_checked() {
    let base = journey_fixture(&FIXTURE_JOURNEYS[24]);
    assert!(ext_messages(&base, "J-25").is_empty());
    let ninety_nine = base.replace(
        "| Traffic flows through HDD | 20 |",
        "| Traffic flows through HDD | 19 |",
    );
    assert!(
        ext_messages(&ninety_nine, "J-25").contains("100"),
        "{}",
        ext_messages(&ninety_nine, "J-25")
    );
    let unknown_screen = base.replace("| S-044 |", "| S-999 |");
    assert!(
        ext_messages(&unknown_screen, "J-25").contains("S-999"),
        "{}",
        ext_messages(&unknown_screen, "J-25")
    );
    let fewer = without_lines(
        &base,
        &[
            "| Certificate valid |",
            "| Origin lockdown |",
            "| WAF in block mode |",
        ],
    );
    assert!(
        ext_messages(&fewer, "J-25").to_lowercase().contains("six"),
        "{}",
        ext_messages(&fewer, "J-25")
    );
    let duplicate = base.replace("| Certificate valid |", "| Traffic flows through HDD |");
    assert!(
        ext_messages(&duplicate, "J-25").contains("twice"),
        "{}",
        ext_messages(&duplicate, "J-25")
    );
    let footnote = base.replace(
        "Measures configuration completeness, not security.",
        "A complete protection score.",
    );
    assert!(
        ext_messages(&footnote, "J-25")
            .to_lowercase()
            .contains("footnote"),
        "{}",
        ext_messages(&footnote, "J-25")
    );
    let placement = base.replace(
        "below the readiness ring and repeats it above the checklist",
        "on a separate page",
    );
    assert!(
        ext_messages(&placement, "J-25").contains("placement"),
        "{}",
        ext_messages(&placement, "J-25")
    );
}

#[test]
fn t18_api_key_lifecycle_needs_every_stage() {
    let base = journey_fixture(&FIXTURE_JOURNEYS[26]);
    assert!(ext_messages(&base, "J-27").is_empty());
    let missing = without_lines(&base, &["| rotation |"]);
    assert!(
        ext_messages(&missing, "J-27").contains("rotation"),
        "{}",
        ext_messages(&missing, "J-27")
    );
    let unknown = base.replace("| rotation |", "| rotate in place |");
    assert!(
        ext_messages(&unknown, "J-27").contains("rotate in place"),
        "{}",
        ext_messages(&unknown, "J-27")
    );
    let duplicate = base.replace("| expiry |", "| rotation |");
    assert!(
        ext_messages(&duplicate, "J-27").contains("exactly once"),
        "{}",
        ext_messages(&duplicate, "J-27")
    );
    let empty = base.replace(
        "| revoke | The key is deleted and its secret stops working. |",
        "| revoke |  |",
    );
    assert!(
        ext_messages(&empty, "J-27")
            .to_lowercase()
            .contains("empty"),
        "{}",
        ext_messages(&empty, "J-27")
    );
}

#[test]
fn t18_admin_controls_need_known_permissions_audits_and_values() {
    for (index, id) in [(28, "J-29"), (29, "J-30"), (30, "J-31")] {
        let base = journey_fixture(&FIXTURE_JOURNEYS[index]);
        assert!(
            ext_messages(&base, id).is_empty(),
            "{}: {}",
            id,
            ext_messages(&base, id)
        );
    }
    let base = journey_fixture(&FIXTURE_JOURNEYS[28]);
    let unknown_permission = base.replace("PERM-platform.tenant.read", "PERM-platform.nope");
    assert!(
        ext_messages(&unknown_permission, "J-29").contains("PERM-platform.nope"),
        "{}",
        ext_messages(&unknown_permission, "J-29")
    );
    let tenant_only = base.replace("PERM-platform.tenant.read", "PERM-org.read");
    assert!(
        ext_messages(&tenant_only, "J-29")
            .to_lowercase()
            .contains("platform"),
        "{}",
        ext_messages(&tenant_only, "J-29")
    );
    let unknown_audit = base.replace("AUD-platform.support_lookup", "AUD-platform.nope");
    assert!(
        ext_messages(&unknown_audit, "J-29").contains("AUD-platform.nope"),
        "{}",
        ext_messages(&unknown_audit, "J-29")
    );
    let no_b8 = journey_fixture(&FIXTURE_JOURNEYS[29])
        .replace("No B8 event records abuse triage yet", "No audit event");
    assert!(
        ext_messages(&no_b8, "J-30").contains("B8"),
        "{}",
        ext_messages(&no_b8, "J-30")
    );
    let bad_reason = base.replace("| no | no |", "| maybe | no |");
    assert!(
        ext_messages(&bad_reason, "J-29")
            .to_lowercase()
            .contains("reason"),
        "{}",
        ext_messages(&bad_reason, "J-29")
    );
    let bad_step = base.replace("| no | no |", "| no | sometimes |");
    assert!(
        ext_messages(&bad_step, "J-29")
            .to_lowercase()
            .contains("step-up"),
        "{}",
        ext_messages(&bad_step, "J-29")
    );
    let duplicate = base.replace(
        "| Suspend a tenant | PERM-platform.tenant.suspend | AUD-platform.tenant_plan_changed | yes | yes |",
        "| Change a plan | PERM-platform.tenant.suspend | AUD-platform.tenant_plan_changed | yes | yes |",
    );
    assert!(
        ext_messages(&duplicate, "J-29")
            .to_lowercase()
            .contains("duplicate"),
        "{}",
        ext_messages(&duplicate, "J-29")
    );
}

#[test]
fn t18_privacy_timelines_are_configurable_and_legal_neutral() {
    let base = journey_fixture(&FIXTURE_JOURNEYS[32]);
    assert!(ext_messages(&base, "J-33").is_empty());
    let missing = without_lines(&base, &["| Data deletion |"]);
    assert!(
        ext_messages(&missing, "J-33").contains("deletion"),
        "{}",
        ext_messages(&missing, "J-33")
    );
    let fixed = base.replace("configurable defaults", "fixed values");
    assert!(
        ext_messages(&fixed, "J-33").contains("configurable"),
        "{}",
        ext_messages(&fixed, "J-33")
    );
    let promise = base.replace(
        "The page states the request time and the delivery address.",
        "We guarantee that the data is permanently deleted.",
    );
    assert!(
        ext_messages(&promise, "J-33")
            .to_lowercase()
            .contains("legal"),
        "{}",
        ext_messages(&promise, "J-33")
    );
    let no_default = base.replace(
        "Within 24 hours by default, configurable up to 7 days.",
        "Within 24 hours.",
    );
    assert!(
        ext_messages(&no_default, "J-33")
            .to_lowercase()
            .contains("default"),
        "{}",
        ext_messages(&no_default, "J-33")
    );
}

#[test]
fn t18_incident_timeline_and_retrospective_are_checked() {
    let base = journey_fixture(&FIXTURE_JOURNEYS[33]);
    assert!(ext_messages(&base, "J-34").is_empty());
    let missing = without_lines(&base, &["| De-escalation |"]);
    assert!(
        ext_messages(&missing, "J-34").contains("de-escalation"),
        "{}",
        ext_messages(&missing, "J-34")
    );
    let fewer = without_lines(&base, &["8. ", "9. "]);
    assert!(
        ext_messages(&fewer, "J-34")
            .to_lowercase()
            .contains("eight"),
        "{}",
        ext_messages(&fewer, "J-34")
    );
    let bad_screen = base.replace("| S-093 |", "| S-999 |");
    assert!(
        ext_messages(&bad_screen, "J-34").contains("S-999"),
        "{}",
        ext_messages(&bad_screen, "J-34")
    );
    let empty = base.replace("| The alert rule fires on an attack spike. |", "|  |");
    assert!(
        ext_messages(&empty, "J-34")
            .to_lowercase()
            .contains("empty"),
        "{}",
        ext_messages(&empty, "J-34")
    );
}

#[test]
fn t18_dependency_rows_are_complete_and_acyclic() {
    let base = journey_dependencies_fixture();
    assert!(dependency_messages(&base).is_empty());
    let missing = without_lines(&base, &["| J-34 |"]);
    assert!(
        dependency_messages(&missing).contains("J-34"),
        "{}",
        dependency_messages(&missing)
    );
    let invented = base.replace("| J-01 | none |", "| J-99 | none |");
    assert!(
        dependency_messages(&invented).contains("J-99"),
        "{}",
        dependency_messages(&invented)
    );
    let unknown = base.replace("| J-02 | J-01 |", "| J-02 | J-98 |");
    assert!(
        dependency_messages(&unknown).contains("J-98"),
        "{}",
        dependency_messages(&unknown)
    );
    let itself = base.replace("| J-05 | J-04 |", "| J-05 | J-05 |");
    assert!(
        dependency_messages(&itself).contains("itself"),
        "{}",
        dependency_messages(&itself)
    );
    let cycle = base.replace(
        "| J-01 | none | The journey is ordered after its prerequisites. |",
        "| J-01 | J-34 | This is an exception ordered after its prerequisite. |",
    );
    assert!(
        dependency_messages(&cycle).contains("cycle"),
        "{}",
        dependency_messages(&cycle)
    );
    let later = base.replace("| J-02 | J-01 |", "| J-02 | J-05 |");
    assert!(
        dependency_messages(&later).contains("exception"),
        "{}",
        dependency_messages(&later)
    );
    let exception = base.replace("| J-03 | J-02 |", "| J-03 | J-20 |").replace(
        "| J-03 | J-20 | The journey is ordered after its prerequisites. |",
        "| J-03 | J-20 | This is an exception: the specification lists them in this order. |",
    );
    assert!(
        !dependency_messages(&exception).contains("exception"),
        "{}",
        dependency_messages(&exception)
    );
}

#[test]
fn t18_dependency_graph_is_a_text_graph_with_every_journey() {
    let base = journey_dependencies_fixture();
    let no_graph = base.replace("## Graph", "## Picture");
    assert!(
        dependency_messages(&no_graph).contains("Graph"),
        "{}",
        dependency_messages(&no_graph)
    );
    let mermaid = base.replace(
        "A text graph; no diagram tool is required.",
        "```mermaid\ngraph TD\n```",
    );
    assert!(
        dependency_messages(&mermaid).contains("Mermaid"),
        "{}",
        dependency_messages(&mermaid)
    );
    let missing_node = without_lines(&base, &["J-31 -> J-29"]);
    assert!(
        dependency_messages(&missing_node).contains("J-31"),
        "{}",
        dependency_messages(&missing_node)
    );
}

#[test]
fn t18_task_dependencies_agree_with_the_spec_task_graph() {
    let base = journey_dependencies_fixture();
    assert!(dependency_messages(&base).is_empty());
    let not_an_edge = base.replace(
        "| J-02 needs J-01 | T-0001 | T-0002 | direct |",
        "| J-02 needs J-03 | T-0001 | T-0002 | direct |",
    );
    assert!(
        dependency_messages(&not_an_edge).contains("dependency table"),
        "{}",
        dependency_messages(&not_an_edge)
    );
    let wrong_direct = base.replace(
        "| J-02 needs J-01 | T-0001 | T-0002 | direct |",
        "| J-02 needs J-01 | T-0002 | T-0001 | direct |",
    );
    assert!(
        dependency_messages(&wrong_direct)
            .to_lowercase()
            .contains("direct"),
        "{}",
        dependency_messages(&wrong_direct)
    );
    let wrong_earlier = base.replace(
        "| J-08 needs J-07 | T-0001 | T-0004 | earlier |",
        "| J-08 needs J-07 | T-0004 | T-0001 | earlier |",
    );
    assert!(
        dependency_messages(&wrong_earlier).contains("earlier"),
        "{}",
        dependency_messages(&wrong_earlier)
    );
    let unstated_none = base.replace(
        "The same task T-0002 delivers both journeys, so the spec names no task dependency.",
        "The tasks ship together.",
    );
    assert!(
        dependency_messages(&unstated_none).contains("no task dependency"),
        "{}",
        dependency_messages(&unstated_none)
    );
    let unknown_task = base.replace(
        "| T-0001 | T-0002 | direct |",
        "| T-0001 | T-9999 | direct |",
    );
    assert!(
        dependency_messages(&unknown_task).contains("T-9999"),
        "{}",
        dependency_messages(&unknown_task)
    );
}

#[test]
fn t18_a_missing_extension_journey_or_dependency_file_is_named() {
    let r = Repo::new("tree-t18");
    good_tree(&r);
    assert!(check(r.root()).is_empty(), "{}", messages(&check(r.root())));
    fs::remove_file(r.root().join("docs/UX/journeys/J-34.md")).expect("remove");
    let m = messages(&check(r.root()));
    assert!(m.contains("J-34"), "{m}");
    let r = Repo::new("tree-t18-deps");
    good_tree(&r);
    fs::remove_file(r.root().join("docs/UX/journey-dependencies.md")).expect("remove");
    let m = messages(&check(r.root()));
    assert!(m.contains("journey-dependencies"), "{m}");
}

// ---------------------------------------------------------------------------------------------- T-0018 F-13 (round 2)

#[test]
fn t18_f13_task_order_contradiction_needs_an_exception() {
    let base = journey_dependencies_fixture();
    assert!(
        dependency_messages(&base).is_empty(),
        "{}",
        dependency_messages(&base)
    );
    // A mapped edge whose prerequisite task comes after the dependent task in the stable order.
    let contradiction = base.replace(
        "| J-08 needs J-07 | T-0001 | T-0004 | earlier | T-0001 comes earlier in the stable order than T-0004. |",
        "| J-08 needs J-07 | T-0004 | T-0001 | none | The spec names no task dependency between these tasks. |",
    );
    let m = dependency_messages(&contradiction);
    assert!(
        m.to_lowercase().contains("exception"),
        "the contradiction must be reported: {m}"
    );
    assert!(m.contains("T-0004"), "{m}");
    // The same contradiction is accepted when the row records it as an exception.
    let exception = base.replace(
        "| J-08 needs J-07 | T-0001 | T-0004 | earlier | T-0001 comes earlier in the stable order than T-0004. |",
        "| J-08 needs J-07 | T-0004 | T-0001 | none | The spec names no task dependency here; the stable order builds T-0004 before T-0001, recorded as an exception. |",
    );
    assert!(
        dependency_messages(&exception).is_empty(),
        "{}",
        dependency_messages(&exception)
    );
}

#[test]
fn t18_f13_alternative_journeys_have_no_edge_between_them() {
    let base = journey_dependencies_fixture();
    assert!(
        dependency_messages(&base).is_empty(),
        "{}",
        dependency_messages(&base)
    );
    // J-08 and J-09 are alternative integration choices of the same wizard.
    let alternative = base.replace("| J-09 | J-07 |", "| J-09 | J-08 |").replace(
        "| J-09 | J-08 | The journey is ordered after its prerequisites. |",
        "| J-09 | J-08 | The CNAME setup follows the delegation setup. |",
    );
    let m = dependency_messages(&alternative);
    assert!(
        m.to_lowercase().contains("alternative"),
        "the alternative edge must be reported: {m}"
    );
    // The reverse direction is rejected too; the exception word only satisfies the later-number rule.
    let reverse = base.replace(
        "| J-08 | J-07 | The journey is ordered after its prerequisites. |",
        "| J-08 | J-09 | This is an exception under review. |",
    );
    let m = dependency_messages(&reverse);
    assert!(
        m.to_lowercase().contains("alternative"),
        "the reverse alternative edge must be reported: {m}"
    );
}
