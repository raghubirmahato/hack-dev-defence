# Omar, the platform operator

**Fictional composite.** Omar is not a real person and stands for no single customer: he is a composite of the platform
operators described in spec [B1.4](../../SPEC.md#b14-omar-the-platform-operator). His scenarios are design inputs, not
evidence; a measurable outcome below names a real test, audit event or metric.

In `owner_only` deployments Omar is also Maya; the two roles are separated in the interface but not in the person. He is
not the pilot's assumed primary persona (that is Maya until the
[primary-persona question](../../OPERATOR-QUESTIONS.md#primary-persona-for-the-pilot-added-by-t-0012) is answered). The
[UX charter](../CHARTER.md) applies to every screen he uses.

## Context of use

| Aspect | Detail |
| --- | --- |
| Device | Laptop and phone; SSH, `hddctl` and the journal are his usual tools. |
| Connectivity | On call from home or a phone hotspot; the link can be slow exactly during an incident. |
| Interruptions | Constant; every runbook step must be resumable and print the next exact instruction. |
| Vocabulary | systemd, journald, PostgreSQL, XDP, ACME, ASN, upstream scrubbing; he expects exact field names. |
| First check of the day | Service health, job queues, shield state, backup age and whether HDD itself is up. |

## Scenarios

### 1. Restore service during an incident

When saturation or a dependency failure is reported, I want to see one health view with the failing service and the last action
taken, so I can restore service without guessing which component is down.

Measurable outcome: AC-20 (observability and alerting) and AC-42 (admin operations and tenant lifecycle) pass;
`MET-hdd_proxy_shed_total` and `MET-hdd_safe_mode` show the state the health view reports.

### 2. Roll out a rule pack without an outage

When a new rule pack must reach tenants, I want to run a staged rollout with a diff of what changes and automatic rollback, so
I can stop one bad rule before it takes every domain down.

Measurable outcome: AC-42 and AC-16 (config revisions and convergence) pass; `AUD-platform.rule_pack_rolled_out` and
`AUD-platform.rule_pack_rolled_back` record both outcomes.

### 3. Prove that a backup is real

When the machine is lost, I want to perform a tested restore and see a drill history, so I can see the backup is usable before I need it.

Measurable outcome: AC-54 (backups, restore, upgrade and disaster recovery) passes; `AUD-platform.restore_drill` records
each drill and its result.

## Anti-goals

- A platform that needs a working UI session to recover from an outage.
- Silent auto-update or auto-failover.
- A shield page that hides which upstream capacity is missing.
- Admin access reachable from an untrusted network.
- A backup that has never been restored, or a report that calls the setup protected while a bypass path is open (R-34).

## Accessibility

B1.4 names no accessibility needs for Omar, so these are derived from his duties and are the design assumption, not a
quotation: he may operate emergency controls from a phone, under stress, with one hand. Mapped to the
[B11.11](../../SPEC.md#b1111-accessibility-contract-summary-of-wcag-22-aa-obligations-the-components-encode) criteria:
2.1.1 (all functionality by keyboard), 2.4.11 (focus not obscured by a sticky status banner), 3.3.4 (destructive and
emergency actions are reversible or confirmed by typing), 2.5.8 (targets at least 24 CSS px on a phone) and 1.4.3
(contrast of text, including status text).

Assistive technology assumptions: phone browser with zoom and a laptop keyboard; no screen reader is assumed, so every
status colour must also carry a text label and the emergency path must be reachable without a pointer.

## Journeys and screens

- Journeys: [J-29](../../SPEC.md#j-29-platform-admin-onboards-and-manages-tenants),
  [J-30](../../SPEC.md#j-30-platform-admin-investigates-abuse-and-global-bans),
  [J-31](../../SPEC.md#j-31-platform-admin-toggles-safe-mode-maintenance-checks-infra) and
  [J-34](../../SPEC.md#j-34-incident-attack-spike).
- Screens: [S-084](../../SPEC.md#b121-screen-table) Audit log,
  [S-100](../../SPEC.md#s-100-admin-overview) Admin overview,
  [S-102](../../SPEC.md#s-102-tenant-detail-admin) Tenant detail,
  [S-106](../../SPEC.md#b121-screen-table) Global jail,
  [S-109](../../SPEC.md#b121-screen-table) Never-ban and allowlists,
  [S-110/S-111](../../SPEC.md#s-110s-111-infra-and-services) Infra nodes and services,
  [S-122](../../SPEC.md#b121-screen-table) Emergency controls,
  [S-127](../../SPEC.md#b121-screen-table) DDoS readiness and shield and
  [S-135/S-136](../../SPEC.md#s-135s-136-runtime-hosting-and-first-run-setup) Runtime and hosting check.
- Success, from B1.4: the platform is healthy, tenants are onboarded, abuse is handled, rule packs roll out safely and a
  saturation is visible before a customer reports it.
