# Persona-journey matrix

Every journey of spec B3 ([J-01 to J-34](../SPEC.md#b3-core-user-journeys)) is linked to at least one persona file
in this directory. `cargo xtask ux-docs` fails if a journey is missing, is listed twice, invents an id outside the B3
range, or its row names no persona file (T-0012 A2). The personas themselves are fictional composites; see each file's
header.

The primary persona for the pilot is Maya until the operator answers the
[primary-persona question](../OPERATOR-QUESTIONS.md#primary-persona-for-the-pilot-added-by-t-0012) (A5).

| Journey | Story (B3) | Persona(s) | Why it matters to them |
| --- | --- | --- | --- |
| [J-01](../SPEC.md#j-01-visitor-discovers-hdd-and-reads-honest-claims) | Visitor discovers HDD and reads honest claims | [Maya](personas/maya.md) | Decides whether the product is for her before she signs up. |
| [J-02](../SPEC.md#j-02-visitor-signs-up-and-verifies-email) | Visitor signs up and verifies email | [Maya](personas/maya.md) | The first step of her success path. |
| [J-03](../SPEC.md#j-03-new-user-enrolls-mfa) | New user enrolls MFA | [Maya](personas/maya.md), [Dan](personas/dan.md), [Sara](personas/sara.md), [Omar](personas/omar.md), [Alex](personas/alex.md) | Required for platform roles; recommended for everyone else. |
| [J-04](../SPEC.md#j-04-returning-user-logs-in) | Returning user logs in | [Maya](personas/maya.md), [Dan](personas/dan.md), [Sara](personas/sara.md), [Omar](personas/omar.md), [Alex](personas/alex.md) | Every daily session starts here. |
| [J-05](../SPEC.md#j-05-user-resets-a-forgotten-password) | User resets a forgotten password | [Maya](personas/maya.md), [Alex](personas/alex.md) | The flow that must never confirm whether an account exists. |
| [J-06](../SPEC.md#j-06-user-accepts-a-team-invite) | User accepts a team invite | [Dan](personas/dan.md), [Sara](personas/sara.md), [Alex](personas/alex.md), [Omar](personas/omar.md) | How a team grows without shared passwords. |
| [J-07](../SPEC.md#j-07-owner-completes-the-onboarding-checklist) | Owner completes the onboarding checklist | [Maya](personas/maya.md), [Alex](personas/alex.md) | The shortest route from signup to a protected site. |
| [J-08](../SPEC.md#j-08-owner-adds-a-domain-using-full-nameserver-delegation) | Owner adds a domain using full nameserver delegation | [Maya](personas/maya.md), [Alex](personas/alex.md) | The recommended integration mode. |
| [J-09](../SPEC.md#j-09-owner-adds-a-domain-using-cname-partial-setup) | Owner adds a domain using CNAME (partial) setup | [Maya](personas/maya.md), [Dan](personas/dan.md) | The lighter mode for teams that keep their DNS provider. |
| [J-10](../SPEC.md#j-10-owner-attaches-an-apex-via-aalias-or-only-a-subdomain) | Owner attaches an apex via A/ALIAS or only a subdomain | [Maya](personas/maya.md), [Dan](personas/dan.md) | The DNS question that most often blocks cutover. |
| [J-11](../SPEC.md#j-11-owner-verifies-ownership) | Owner verifies ownership | [Maya](personas/maya.md), [Dan](personas/dan.md), [Alex](personas/alex.md) | Proves control before a domain is touched. |
| [J-12](../SPEC.md#j-12-owner-configures-and-tests-the-origin) | Owner configures and tests the origin | [Maya](personas/maya.md), [Dan](personas/dan.md) | A wrong origin is an outage, so the test is part of the flow. |
| [J-13](../SPEC.md#j-13-owner-imports-existing-dns-and-resolves-parity-warnings) | Owner imports existing DNS and resolves parity warnings | [Maya](personas/maya.md), [Dan](personas/dan.md) | Mail must keep working after a nameserver change. |
| [J-14](../SPEC.md#j-14-owner-edits-dns-and-toggles-orangegrey) | Owner edits DNS and toggles orange/grey | [Maya](personas/maya.md), [Dan](personas/dan.md) | The daily DNS task after onboarding. |
| [J-15](../SPEC.md#j-15-owner-issues-tls-and-enables-hsts) | Owner issues TLS and enables HSTS | [Maya](personas/maya.md), [Dan](personas/dan.md) | The certificate is the visible sign that the site works. |
| [J-16](../SPEC.md#j-16-owner-enables-protection-in-monitor-mode-reviews-switches-to-block) | Owner enables protection in monitor mode, reviews, switches to block | [Maya](personas/maya.md), [Sara](personas/sara.md) | The decision the product exists for; it must be reversible. |
| [J-17](../SPEC.md#j-17-owner-enables-the-vulnerable-origin-shield) | Owner enables the Vulnerable-Origin Shield | [Maya](personas/maya.md), [Sara](personas/sara.md) | The strictest mode, so the consequences must be plain. |
| [J-18](../SPEC.md#j-18-analyst-investigates-an-attack) | Analyst investigates an attack | [Sara](personas/sara.md) | Evidence and policy branch, in one place. |
| [J-19](../SPEC.md#j-19-owner-builds-a-custom-rule) | Owner builds a custom rule | [Dan](personas/dan.md), [Sara](personas/sara.md) | The API and the UI must offer the same power. |
| [J-20](../SPEC.md#j-20-owner-configures-rate-limits-for-login) | Owner configures rate limits for login | [Maya](personas/maya.md), [Dan](personas/dan.md) | The most common abuse control after onboarding. |
| [J-21](../SPEC.md#j-21-owner-configures-alerts-and-webhooks) | Owner configures alerts and webhooks | [Dan](personas/dan.md), [Omar](personas/omar.md) | Out-of-band notification is part of "a few days, then block". |
| [J-22](../SPEC.md#j-22-blocked-visitor-files-an-appeal) | Blocked visitor files an appeal | [Vi](personas/vi.md), [Maya](personas/maya.md) | The only journey a visitor walks; the owner whose visitors file appeals must understand it. |
| [J-23](../SPEC.md#j-23-owner-handles-an-appeal) | Owner handles an appeal | [Sara](personas/sara.md), [Maya](personas/maya.md) | False positives are handled as a workflow, not by email. |
| [J-24](../SPEC.md#j-24-owner-locks-down-the-origin) | Owner locks down the origin | [Maya](personas/maya.md), [Dan](personas/dan.md), [Omar](personas/omar.md) | Bypass prevention is an owner task with an operator tool. |
| [J-25](../SPEC.md#j-25-owner-views-protection-readiness-and-fixes-items) | Owner views Protection Readiness and fixes items | [Maya](personas/maya.md) | The checklist that tells her what is still missing. |
| [J-26](../SPEC.md#j-26-owner-invites-teammates-and-assigns-roles) | Owner invites teammates and assigns roles | [Alex](personas/alex.md) | Client work is delegated per client. |
| [J-27](../SPEC.md#j-27-developer-creates-an-api-key-and-uses-the-api) | Developer creates an API key and uses the API | [Dan](personas/dan.md) | Automation without a browser session. |
| [J-28](../SPEC.md#j-28-owner-exports-reports-and-audit-logs) | Owner exports reports and audit logs | [Dan](personas/dan.md), [Sara](personas/sara.md), [Alex](personas/alex.md), [Omar](personas/omar.md) | The evidence trail for a client, a manager or an incident review. |
| [J-29](../SPEC.md#j-29-platform-admin-onboards-and-manages-tenants) | Platform admin onboards and manages tenants | [Omar](personas/omar.md) | Tenant lifecycle is an operator duty. |
| [J-30](../SPEC.md#j-30-platform-admin-investigates-abuse-and-global-bans) | Platform admin investigates abuse and global bans | [Omar](personas/omar.md) | Global jail and never-ban controls. |
| [J-31](../SPEC.md#j-31-platform-admin-toggles-safe-mode-maintenance-checks-infra) | Platform admin toggles safe mode, maintenance, checks infra | [Omar](personas/omar.md) | Emergency controls with typed confirmation. |
| [J-32](../SPEC.md#j-32-owner-removes-a-domain-safely) | Owner removes a domain safely | [Maya](personas/maya.md), [Alex](personas/alex.md) | Leaving must not leave dangling records behind. |
| [J-33](../SPEC.md#j-33-user-exports-data-or-deletes-the-account) | User exports data or deletes the account | [Maya](personas/maya.md), [Alex](personas/alex.md), [Dan](personas/dan.md) | The privacy path out of the product. |
| [J-34](../SPEC.md#j-34-incident-attack-spike) | Incident: attack spike | [Sara](personas/sara.md), [Omar](personas/omar.md), [Maya](personas/maya.md) | The journey that decides whether the product is trusted during an attack. |

The [adversary persona](personas/adversary.md) is deliberately absent as a journey owner: it is designed for, never for
its convenience. Its abuse stories are reviewed against every journey above, and specifically against J-16, J-18, J-22
and J-34.
