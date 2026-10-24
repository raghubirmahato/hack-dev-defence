# Dangerous actions and their safeguards

T-0025 steps 1 and 2 (`REQ-UXR-15`). This catalog lists the actions in HDD that can lock an operator
out, break a site, delete data or change every tenant at once. Each row names the risk, the
safeguards that must exist before the action, the undo path, the audit event and the copy key whose
text lives in [security-ux.ftl](../../i18n/en/security-ux.ftl).

Screens are B12.1 ids, permissions are B4.2 ids and audit events are B8 ids. `cargo xtask ux-docs`
checks this table: at least twenty rows, every cell non-empty, every audit event and permission in
the master specification, every copy key defined exactly once, the step-up claims against the B4.2
`S` cells, the typed-confirmation set of TC-7, and every cited attack class drawn from C5.

## Catalog

| ID | Action | Screen | Permission | Risk | Safeguards | Undo path | Audit event | Copy key |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| DA-01 | Remove a domain (decommission) | S-094 | PERM-domain.delete | The domain stops being served and its history is lost. | Preview of the records and the zone export; typed confirmation of the domain name; step-up re-authentication. | Re-add the domain and import the zone export; the history of the old domain is not restored. | AUD-domain.decommissioned | `domain-remove-confirm` |
| DA-02 | Delete a DNS record | S-045 | PERM-dns.write | The name stops resolving for web or mail. | Preview of the record before and after; 30-second undo toast; dry-run of the zone. | 30-second undo toast, then a DNS version rollback (S-048). | AUD-dns.record_deleted | `dns-record-delete-confirm` |
| DA-03 | Import or overwrite a DNS zone | S-047 | PERM-dns.import | Imported records replace the live zone and can drop mail. | Preview of the diff against the live zone; step-up (stronger than B4.2). | Roll back to the previous DNS version (S-048). | AUD-dns.record_imported | `dns-import-confirm` |
| DA-04 | Change the nameservers (cutover guidance) | S-042 | PERM-domain.update | The whole domain, including email, changes delegation. | Preview of the old and new nameserver pair; rollback text kept to the end. | Set the nameservers back at the registrar; the rollback text keeps the old pair. | AUD-domain.updated | `nameserver-change-confirm` |
| DA-05 | Switch protection to block mode | S-054, S-055 | PERM-waf.mode.update | Matching visitors are blocked and the sending address is banned. | Consequences preview; seven-day would-block counts; self-lockout preview; time box option. | Switch back to monitor at any time; an undo toast follows a confirmed switch. | AUD-waf.mode_changed | `block-mode-confirm` |
| DA-06 | Create a manual ban | S-067, S-069 | PERM-ban.create | An address or a whole network is refused, possibly a shared address. | Self-lockout preview; dry-run against recent traffic; time box on the TTL. | Unban from the jail list (S-067); the ban is also released by its TTL. | AUD-ban.created | `ban-create-confirm` |
| DA-07 | Add an access-list entry (deny or allow) | S-063, S-069 | PERM-access.write | A deny refuses an address, network, country or ASN at the edge, and an allow lets traffic skip the list. | Preview of affected sessions; self-lockout preview; step-up (stronger than B4.2). | Remove the entry from the access list; the removal is audited. | AUD-access.entry_added | `access-deny-confirm` |
| DA-08 | Apply a geo-block by country or ASN | S-063 | PERM-access.write | Every visitor from that country or network is refused, including customers and a travelling operator. | Preview of the recent visitor count; self-lockout preview of the session country and ASN. | Remove the geo entry; sessions from the country are admitted again. | AUD-access.entry_added | `geo-block-confirm` |
| DA-09 | Create a WAF rule with a broad scope | S-059 | PERM-waf.rules.write | A wide path or parameter match refuses legitimate traffic, and a slow pattern can stress the rule engine. | Plain-language preview; dry-run replay over recent traffic (S-060). | Disable or delete the rule; a config revision rollback restores the previous state. | AUD-waf.rule_created | `rule-broad-confirm` |
| DA-10 | Enable safe mode | S-093 | PERM-waf.safe_mode | Inspection, jails and rate limits stop for the time box. | Step-up and a reason; time box; visible banner. | End it early, or wait for the auto-revert at the stated time. | AUD-waf.safe_mode_on | `safe-mode-confirm` |
| DA-11 | Apply origin lockdown | S-098 | PERM-origin.lockdown | Requests that skip HDD are refused at the origin. | Preview of the allowlist; verification probes. | Restore the previous firewall state; the wizard keeps the revert text. | AUD-origin.lockdown_applied | `origin-lockdown-confirm` |
| DA-12 | Create an API key | S-080 | PERM-apikey.create | The key acts with the chosen scopes and its secret is shown once. | Preview of the scopes; step-up for an admin key. | Revoke the key (DA-28); the secret itself cannot be recovered. | AUD-apikey.created | `api-key-create-confirm` |
| DA-13 | Remove an MFA second factor from your account | S-088 | PERM-account.self | The account can be entered with one factor. | Step-up (stronger than B4.2); recovery-code check. | Enrol a new factor; the removed factor cannot be restored. | AUD-auth.mfa_removed | `mfa-remove-confirm` |
| DA-14 | Delete the organisation | S-086 | PERM-org.delete | Domains, members, keys and events are deleted. | Preview of the owned resources; typed confirmation of the organisation slug; step-up. | No automatic undo: the export is the recovery path; re-create the organisation and import it. | AUD-org.deleted | `org-delete-confirm` |
| DA-15 | Change a global platform setting | S-119 | PERM-platform.settings.write | Every tenant and every outgoing email uses the new value. | Preview of the affected tenants; typed confirmation of the setting name; step-up. | Restore the previous value from the audit diff. | AUD-platform.settings_changed | `global-setting-confirm` |
| DA-16 | Create a global ban | S-106 | PERM-platform.jail.write | An address is refused by every tenant, including shared addresses. | Preview of the affected sites; typed confirmation of the address; time box on the TTL; step-up. | Release the global ban; the release is audited. | AUD-ban.global_created | `global-ban-confirm` |
| DA-17 | Publish or roll back a rule pack | S-107 | PERM-platform.rules.publish | Every site inspects with the new pack. | Staged rollout preview; dry-run; typed confirmation of the pack name; step-up. | Roll back to the previous pack version; the audit records the rollback. | AUD-platform.rule_pack_published | `rule-pack-confirm` |
| DA-18 | Push a virtual patch as an emergency release | S-126 | PERM-vkb.emergency | A wrong signature can refuse benign traffic on every site. | Two-person approval; preview of the evidence; time box on the expiry; step-up. | Roll back the rule; the virtual patch is not a fix, so the exposure remains. | AUD-vkb.emergency_push | `virtual-patch-confirm` |
| DA-19 | Start an impersonation session | S-118 | PERM-platform.impersonate | Support reads tenant data as the tenant sees it. | Reason and duration preview; read-only banner; step-up. | End the session at any time; the read-only session expires at the stated time. | AUD-platform.impersonation_started | `impersonation-start-confirm` |
| DA-20 | Remove a member | S-081 | PERM-member.remove | The member loses access to every domain of the organisation. | Preview of the permissions lost; confirmation. | Invite the member again; the membership is not restored by the undo. | AUD-member.removed | `member-remove-confirm` |
| DA-21 | Change a member's role to owner | S-081 | PERM-member.role.update | The member can delete the organisation and change every setting. | Preview of the permissions granted; step-up. | Change the role back; the change is audited. | AUD-member.role_changed | `member-role-confirm` |
| DA-22 | Transfer organisation ownership | S-086 | PERM-org.transfer | The current owner loses control of the organisation. | Preview of both owners; step-up. | Transfer ownership back, which needs the new owner's consent. | AUD-org.transferred | `org-transfer-confirm` |
| DA-23 | Change the never-ban list | S-109 | PERM-platform.jail.write | A listed network can never be banned, so an attacker network becomes exempt. | Preview of collisions with active bans; typed confirmation of the CIDR; step-up. | Remove the entry; the audit keeps the change. | AUD-platform.never_ban_changed | `never-ban-change-confirm` |
| DA-24 | Enable under attack mode | S-093 | PERM-waf.policy.update | Every new visitor is challenged; scripts without a browser challenge fail. | Effect preview; typed confirmation of the domain name; time box; visible banner. | End it early, or wait for the auto-revert. | AUD-waf.under_attack_on | `under-attack-confirm` |
| DA-25 | Pause protection for a domain | S-093 | PERM-domain.pause | Nothing is inspected, jailed or rate limited while the pause lasts. | Step-up (stronger than B4.2) and a reason; time box; visible banner. | Resume early, or wait for the auto-revert. | AUD-domain.paused | `pause-confirm` |
| DA-26 | Change the HSTS or TLS mode | S-050, S-051 | PERM-tls.write | A long HSTS max-age that a misconfigured origin cannot serve makes the site unreachable. | Preview of the header change; step-up (stronger than B4.2). | Revert the header, but browsers that stored the rule keep it until the max-age expires. | AUD-tls.settings_changed | `hsts-change-confirm` |
| DA-27 | Delete a custom certificate | S-051 | PERM-tls.cert.write | Visitors to the covered names see a TLS error once the certificate is gone. | Preview of the covered names; step-up. | Re-upload the certificate; the private key is not kept by HDD. | AUD-tls.cert_deleted | `certificate-delete-confirm` |
| DA-28 | Revoke an API key | S-080 | PERM-apikey.revoke | Automation that uses the key fails immediately. | Preview of the last use; confirmation. | No undo: create a new key and update the client. | AUD-apikey.revoked | `api-key-revoke-confirm` |
| DA-29 | Open the origin by removing the lockdown | S-052 | PERM-origin.lockdown | Requests that skip HDD can reach the origin again. | Preview of the direct path; step-up (stronger than B4.2). | Re-apply the lockdown (DA-11); the direct path stays open until then. | AUD-bypass.state_changed | `origin-unlock-confirm` |
| DA-30 | Use a platform emergency control (safe mode, signup freeze or global challenge) | S-122 | PERM-platform.emergency | The control applies to every tenant for its window and changes what visitors see. | Preview of the affected tenants and the end time; typed confirmation of the emergency control name; step-up. | Clear the control early, or wait for the auto-revert at the stated time. | AUD-platform.emergency_used | `platform-emergency-confirm` |
| DA-31 | Suspend or delete a tenant | S-102 | PERM-platform.tenant.suspend | The tenant's writes are refused and, on deletion, its data enters the grace period. | Preview of the customer notice and the grace period; typed confirmation of the tenant name; step-up. | Unsuspend the tenant, or cancel the deletion while the grace period runs. | AUD-org.suspended | `tenant-suspend-confirm` |
| DA-32 | Toggle the proxy state of a DNS record | S-046 | PERM-dns.write | Traffic starts or stops going through HDD for the name, and mail records cannot be proxied. | Preview of the route change and of the mail records kept grey; undo toast. | Toggle it back from the record row. | AUD-dns.record_updated | `proxy-toggle-confirm` |
| DA-33 | Change the shield preset, strictness or ban-on-first-hit policy | S-054, S-057 | PERM-waf.policy.update | More payload classes are blocked and a hard hit can ban an address. | Plain-language preview of the blocked classes; self-lockout preview. | Return to the previous preset; a config revision rollback restores it. | AUD-waf.policy_updated | `shield-policy-confirm` |
| DA-34 | Decline a ban appeal | S-069 | PERM-appeal.resolve | The visitor stays blocked and receives the neutral message; the decision affects a third party. | Preview of the evidence and the visitor message; reason required. | No direct undo: unban or allowlist the address (DA-06, DA-07); the decision is audited. | AUD-appeal.resolved | `appeal-decline-confirm` |
| DA-35 | Change a DNS record value | S-046 | PERM-dns.write | The name resolves to a new value for web or mail. | Preview of the before and after value; dry-run of the zone. | Undo toast, then a DNS version rollback (S-048). | AUD-dns.record_updated | `dns-record-update-confirm` |
| DA-36 | Create a scoped WAF exception | S-064, S-069 | PERM-waf.exceptions.write | The matched traffic skips the rule until the exception expires. | Preview of the scope, the expiry and the affected rules. | Remove the exception, or wait for its expiry. | AUD-waf.exception_created | `exception-create-confirm` |
| DA-37 | Apply or enable a rate-limit preset or rule | S-061 | PERM-ratelimit.write | Requests above the limit are challenged or banned. | Preview of the login path, the limit and the ban ladder; dry-run with the burst helper. | Pause the rule; the previous revision stays in the list. | AUD-ratelimit.rule_changed | `ratelimit-confirm` |

## Safeguard kinds

| Kind | What it adds | Typical rows |
| --- | --- | --- |
| Preview | Shows what would change before the save: before and after values, affected records, counts and known limits. | DA-02, DA-05, DA-09 |
| Dry-run | Replays the change against recent traffic or a test sample without touching the live configuration. | DA-06, DA-09, DA-17 |
| Typed confirmation | The user types the exact resource name; the destructive button stays disabled until the value matches. TC-7 of [SECURITY-UX.md](SECURITY-UX.md) lists the rows that require it. | DA-01, DA-14, DA-15 |
| Time box | The change reverts at a stated time unless it is explicitly extended; the countdown stays visible. | DA-10, DA-24, DA-25 |
| Step-up | Re-authentication before the mutation. A row whose B4.2 permission has `S` needs it; a row that asks for it beyond B4.2 says `stronger than B4.2`. | DA-01, DA-02, DA-10 |

## Undo and irreversibility

Reversibility differs per action, and the dialog says which case applies. Reversible: a ban
(DA-06), a DNS record delete (DA-02), a DNS value change (DA-35), an access entry (DA-07), a rule
(DA-09), a mode switch (DA-05), a proxy toggle (DA-32), a time-boxed control (DA-10, DA-24, DA-25).
Partly reversible: the DNS zone (DA-03) can be rolled back to a version, but a delegated domain
(DA-04) depends on the registrar's TTL. Not reversible: the secret of an API key (DA-12), a removed
second factor (DA-13), an organisation deletion (DA-14), an HSTS header already stored by a browser
(DA-26), a deleted certificate's private key (DA-27) and a revoked key's secret (DA-28). Declining an
appeal (DA-34) leaves a third party blocked and can only be corrected by a later unban or allowlist.
The copy for those rows states the irreversibility instead of promising an undo.

## Audit-event notes

B8 groups several events in one slash row. The catalog names the branch that records the action and
does not invent a second id; each row reference sits beside the event it claims:

- The DNS row of B8 groups several branches: `AUD-dns.record_deleted` (DA-02), `AUD-dns.record_imported` (DA-03), `AUD-dns.record_updated` (DA-32) and `AUD-dns.record_updated` (DA-35); the nameserver cutover is a domain lifecycle update, `AUD-domain.updated` (DA-04).
- The MFA row gives the removal branch `AUD-auth.mfa_removed` (DA-13).
- The org lifecycle row gives `AUD-org.deleted` (DA-14) and `AUD-org.transferred` (DA-22).
- The membership row gives `AUD-member.removed` (DA-20) and `AUD-member.role_changed` (DA-21).
- The platform ban row gives `AUD-ban.global_created` (DA-16); the never-ban list writes `AUD-platform.never_ban_changed` (DA-23).
- The API-key row gives `AUD-apikey.created` (DA-12) and `AUD-apikey.revoked` (DA-28); certificate deletion writes `AUD-tls.cert_deleted` (DA-27) from the certificate row.
- The policy-shaped changes are `AUD-waf.policy_updated` (DA-33), `AUD-waf.exception_created` (DA-36), `AUD-ratelimit.rule_changed` (DA-37) and `AUD-platform.emergency_used` (DA-30).
- The org row's suspension branch is `AUD-org.suspended` (DA-31).
- The appeal decision is `AUD-appeal.resolved` (DA-34).

The exact final event names are fixed when those events are implemented; the grouping is recorded
here instead of inventing ids.

## Confirmation copy

The copy for every confirmation is an English Fluent message in
[security-ux.ftl](../../i18n/en/security-ux.ftl). Keys are lowercase semantic words
joined by hyphens (B11.12); the file defines each key exactly once, and a value never contains
markup or an emoji. A typed-confirmation row's value contains the `Type { $resource }` placeholder
that names the value the user must type. The copy deck of B13 is separate and keeps its own keys.
