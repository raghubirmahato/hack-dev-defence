# Onboarding and activation

Status: design deliverable for T-0026 (REQ-UXR-16), steps 1 and 3 to 8 and acceptance A3 and A4. The score model it
refers to is in [READINESS-MODEL.md](READINESS-MODEL.md). The check that enforces this document is
`cargo xtask ux-docs` (module `ux_docs::onboarding`).

The objective is the first fifteen minutes: a new owner should reach a protected domain without guessing, and should
decide about block mode with evidence rather than pressure. The stage map, the checklist and the next-best-action card
are one journey; the [J-07 journey](journeys/J-07.md) records the same stages in the journey format. The voice follows
the [content strategy](CONTENT.md); the measures follow the [experience measures](MEASURES.md) and the decision that
rules out outside analytics ([UXD-003](decisions/UXD-003.md)).

## Stage map

Twelve stages, in checklist order. The screen is the B12.1 screen the stage is designed around; the exit criterion is
derived state, so the checklist can show it without a stored flag (T-0143).

| Stage | Screen | User goal | Why we ask | Exit criterion | Drop-off risk |
| --- | --- | --- | --- | --- | --- |
| account | S-020 | Create an account with an address the owner can open. | Security notices and sign-in links need a verified address. | The account is active and the address is verified. | The confirmation message never arrives and the page offers no resend path. |
| org | S-035 | Name the organisation and choose its slug. | Domains, members and invoices belong to an organisation. | The organisation has a name and a unique slug. | A slug collision reads as a generic failure and the form is abandoned. |
| MFA nudge | S-030 | Add a second sign-in step. | A password alone should not reach the security console. | MFA is enrolled, or the owner records a deliberate deferral. | The owner postpones and later loses the recovery codes. |
| first domain | S-041 | Add the first website. | HDD protects domains; nothing else works before one exists. | A draft domain exists for the organisation. | The empty list looks like a broken page instead of a starting point. |
| DNS connect | S-047 | Import the current records and choose a connection mode. | Reviewing the import first keeps mail and other records alive. | The parity report is acknowledged and a mode is chosen. | An unexpected diff looks dangerous and the owner leaves. |
| verify | S-042 | Prove control of the domain. | HDD must not proxy a name that someone else owns. | The ownership token is confirmed. | A slow poller looks stuck and the owner refreshes it repeatedly. |
| origin | S-052 | Point HDD at the origin and test the connection. | Protection needs a reachable origin for legitimate requests. | The connection test succeeds. | A TLS or SSRF explanation reads as a product fault. |
| monitor mode | S-054 | Start in monitor mode. | Monitor shows what would have been blocked before anything is blocked. | The domain is active and recording would-be blocks. | A chart with no blocks is read as a failed installation. |
| first events | S-065 | See the first requests arrive. | Real events make the risk concrete and the next decision possible. | One event is visible, or the waiting state explains why none is. | No traffic yet is read as a broken domain. |
| block-mode decision | S-055 | Decide whether to switch to block mode. | Blocking changes what visitors can do, so the owner decides. | Block mode is on, or the owner records a deferred decision. | The switch happens without a review of false positives. |
| alerts | S-076 | Test an alert channel. | An alert that never arrives is worse than no alert. | A test alert is delivered to the chosen channel. | The test fails and the owner leaves the channel untested. |
| team | S-082 | Invite a teammate who can share the work. | A second owner or analyst prevents a single-person lockout. | An invitation is sent, or the owner skips the step deliberately. | The invitation expires and nobody resends it. |

## Checklist structure

| Property | Rule |
| --- | --- |
| Derived state | An item is complete only when its own data says so; no stored checkbox can mark it done. |
| Persistence | The checklist stays on S-040 until every item is done or the owner dismisses it. |
| Resume | Reopening S-035 returns to the first unfinished item and keeps the earlier answers. |
| Ordering | Items follow the stage order; a blocked item moves to the end with the reason beside it. |
| Optional items | The team invitation is optional and its absence never blocks activation. |
| Dismissal and return | A dismissal hides the checklist for 14 days; critical items stay in the attention list instead. |
| No dead ends | Every item has a fix link to S-040 or its own screen and a reason when it cannot proceed. |

The checklist never blocks product use: every screen stays reachable while an item is open. An item whose data is
unknown shows `Unknown (reason)` and never shows as complete (T-0143 A5).

## Next best action

The card is shown on S-040 and on the domain overview S-043. The list is evaluated top to bottom; the first match wins,
and later rules are not evaluated once a rule matches. Priorities are unique and increase by one. Rules 1 to 11 name one
check condition each. Rule 12 is the generic rule: its condition `any check is not Pass` opens the remediation link of the
first non-Pass check in catalog order, so every check of the model has a fix path. Rule 13 is the unconditional last rule;
it is reached only when every check passes and returns the distinct outcome `Nothing to do now.`, so a non-Pass state,
including an Unknown, never ends there.

Conditions use the check ids of the [readiness model](READINESS-MODEL.md), so the card and the score read the same
state. A condition on a check that the score does not report cannot be expressed. The card names who can perform the
step: for a non-owner role, rule 11 says that an owner or an admin enrols MFA for the organisation.

1. rule 1: if RD-DELEGATION is Fail then Finish the DNS connection at S-047.
2. rule 2: if RD-DELEGATION is Unknown then Check DNS delegation at S-099.
3. rule 3: if RD-TRAFFIC is Fail then Send traffic through HDD at S-043.
4. rule 4: if RD-ORIGIN-HEALTH is Fail then Fix the origin health at S-053.
5. rule 5: if RD-ORIGIN-HEALTH is Unknown then Run an origin test at S-052.
6. rule 6: if RD-LOCKDOWN is Fail then Apply the origin lockdown at S-098.
7. rule 7: if RD-CERT is Fail then Fix the certificate at S-051.
8. rule 8: if RD-WAF-MODE is Partial then Review monitor results at S-054.
9. rule 9: if RD-WAF-MODE is Fail then Choose a protection mode at S-055.
10. rule 10: if RD-ALERT-TESTED is Fail then Test the alert channel at S-076.
11. rule 11: if RD-MFA is Fail then Ask an owner or an admin to enrol MFA at S-030.
12. rule 12: if any check is not Pass then Open the remediation link for the first non-Pass check in catalog order.
13. rule 13: if always then Nothing to do now.

### Example evaluations

Each row is a state (every check not named is Pass) and the action the list must return. The `ux-docs` check evaluates
the table against the list, so an edit to a rule or a row that disagrees fails the gate. Eight rows name two or more
checks, which is what proves the priority order rather than one rule at a time.

| Inputs | Expected rule | Expected action |
| --- | --- | --- |
| RD-DELEGATION=Fail; others=Pass | 1 | Finish the DNS connection at S-047. |
| RD-DELEGATION=Unknown; others=Pass | 2 | Check DNS delegation at S-099. |
| RD-TRAFFIC=Fail; others=Pass | 3 | Send traffic through HDD at S-043. |
| RD-ORIGIN-HEALTH=Fail; others=Pass | 4 | Fix the origin health at S-053. |
| RD-ORIGIN-HEALTH=Unknown; others=Pass | 5 | Run an origin test at S-052. |
| RD-LOCKDOWN=Fail; others=Pass | 6 | Apply the origin lockdown at S-098. |
| RD-CERT=Fail; others=Pass | 7 | Fix the certificate at S-051. |
| RD-WAF-MODE=Partial; others=Pass | 8 | Review monitor results at S-054. |
| RD-WAF-MODE=Fail; others=Pass | 9 | Choose a protection mode at S-055. |
| RD-ALERT-TESTED=Fail; others=Pass | 10 | Test the alert channel at S-076. |
| RD-MFA=Fail; others=Pass | 11 | Ask an owner or an admin to enrol MFA at S-030. |
| RD-DELEGATION=Fail; RD-MFA=Fail; others=Pass | 1 | Finish the DNS connection at S-047. |
| RD-ORIGIN-HEALTH=Unknown; RD-LOCKDOWN=Fail; others=Pass | 5 | Run an origin test at S-052. |
| RD-WAF-MODE=Partial; RD-CERT=Fail; others=Pass | 7 | Fix the certificate at S-051. |
| RD-HTTPS=Fail; RD-HSTS=Fail; others=Pass | 12 | Open the remediation link for RD-HTTPS at S-050. |
| RD-TRAFFIC=Fail; RD-ORIGIN-HEALTH=Unknown; others=Pass | 3 | Send traffic through HDD at S-043. |
| RD-SHIELD=Unknown; others=Pass | 12 | Open the remediation link for RD-SHIELD at S-057. |
| RD-GREY=Fail; RD-DNS-BACKUP=Fail; others=Pass | 12 | Open the remediation link for RD-GREY at S-045. |
| RD-ORIGIN-EXPOSURE=Fail; RD-SCANNER=Partial; others=Pass | 12 | Open the remediation link for RD-ORIGIN-EXPOSURE at S-138. |
| every check unknown | 2 | Check DNS delegation at S-099. |
| others=Pass | 13 | Nothing to do now. |

## Nudges and reminders

Nudges are quiet by default. In-app cards appear only inside the owner's local working hours, and no email is sent
inside the quiet hours of 22:00 to 07:00. The reminder job refuses to send when the organisation has no verified
owner. The opt-out lives in notification preferences on S-086 and applies to every kind below; it never hides a
security notice such as a new sign-in or a certificate expiry.

| Nudge | Channel | Frequency cap | Opt-out |
| --- | --- | --- | --- |
| Unfinished critical stage | in-app card | at most 1 per 72 hours and at most 3 per week | Dismiss the card; turn off onboarding tips on S-086. |
| Unfinished critical stage | email | at most 1 per 7 days and at most 4 in total | Turn off onboarding reminders on S-086; opt out in notification preferences. |
| Monitor review reminder | in-app card | at most 1 per 24 hours and at most 2 per week | Dismiss the card for 14 days; opt out on S-086. |
| Weekly summary | email | 1 per week | Unsubscribe in the footer; opt out on S-086. |
| Completion thanks | in-app card | 1 per organisation in total | Dismiss the card; no further copy is sent. |

The caps are maxima, not schedules: the job never sends two nudges for the same stage in one cap window, and a nudge
that is dismissed or opted out is not sent again for that stage.

## Empty states

A new account sees an explanation and one next action, never a zero dressed up as a measurement. `empty-events` and
`empty-domains` are B13 keys, defined in `i18n/en/copy-deck.ftl`. The other six `empty-*` keys are defined in
`i18n/en/onboarding.ftl`; the T-0144 registry records them and this task does not add them to the copy deck.

| Screen | Empty state | Copy key | Next action |
| --- | --- | --- | --- |
| S-035 | The profile fields are empty and no sample name is filled in. | `empty-onboarding-profile` | Fill the profile and continue. |
| S-040 | No domains and no events; the checklist is the only content and no chart shows zero. | `empty-domains` | Add a website. |
| S-041 | The list has no rows and offers one add action. | `empty-domains` | Add a website. |
| S-044 | No domain or no check data; an explanation replaces the score ring instead of a score of 0. | `empty-readiness` | Add a website. |
| S-054 | No requests have arrived; the page says so and links the troubleshooting steps. | `empty-events` | Check DNS propagation. |
| S-065 | The monitor has no events and shows its live status plus the waiting guidance. | `empty-events` | Wait for traffic or check the domain status. |
| S-076 | No alert rule exists; the page offers a blank template and no pre-filled destination. | `empty-alerts` | Create an alert rule. |
| S-082 | No invitations; the page says the team step is optional and offers the invite form. | `empty-team` | Invite a teammate or skip the step. |
| S-073 | No reports; the page offers the first report. | `empty-reports` | Create a report. |
| S-090 | No export or deletion request; the page shows the request forms and the current state. | `empty-privacy` | Request an export. |

## Monitor-to-block decision

The switch is a decision, not a step to rush. The owner sees the evidence below before the switch and can postpone
without losing the work. The [J-16 journey](journeys/J-16.md) records the same decision support.

| Item | What the screen shows | Rule |
| --- | --- | --- |
| Would-have-blocked count | S-054 shows the count for the chosen window and labels it as a hypothetical count. | The count is read from `waf_events` rows in monitor mode; it is never extrapolated. |
| Sample events | S-065 and S-066 show up to ten examples with the rule and a redacted payload. | The examples are real events; no generated sample is shown. |
| False-positive review | S-064 and S-069 show how an exception or an appeal undoes a wrong block. | The owner reviews the candidate rules before the switch. |
| 48-hour readiness hint | S-055 states that at least 48 hours of monitor traffic give a better decision. | The hint is a recommendation, not a countdown or a block. |
| Typed confirmation | S-055 asks the owner to type the domain name before block mode starts. | The confirmation is required and the safe option stays selected. |

The hint says 48 hours because a weekly traffic cycle contains quiet and busy periods; the owner may switch earlier
and the switch remains reversible with one click. R-28 applies: the destructive choice is never the default.

## Measures

Every number is produced inside the installation from data HDD already holds. There is no third-party analytics
script and no tracking cookie. A figure that rests on fewer than five accounts shows "not enough data" instead of a
ratio, and a rate always appears with its numerator and denominator.

| Measure | Counter or event | Source | Privacy |
| --- | --- | --- | --- |
| Stage completion time | `onboarding.stage_completed` | server-side counter and `audit_log` | organisation id and stage only; no address |
| Stage drop-off | `onboarding.stage_abandoned` | server-side stage counter | organisation id and stage only |
| Time to first protected domain | `AUD-domain.created` and `AUD-domain.activated` | `audit_log` | timestamps and organisation id only |
| Next best action completed | `onboarding.next_action_completed` | server-side action counter | action id and organisation id only |
| Nudge sent and opted out | `onboarding.nudge_sent` and `onboarding.nudge_opt_out` | server-side nudge counter | kind and organisation id only |
| Email delivery | `MET-hdd_mail_sent_total` | B9 metrics | template label only |

The counters are server-side and keyed by organisation and stage; the product does not record page views, pointer
movement or per-user click streams. The two local `onboarding.*` counters are not B9 metrics and are reported only to
the installation's own operator. See the [experience measures](MEASURES.md) for the common privacy treatment.

## Activation emails

Four emails cover the first week. Each has one subject, a short structure and semantic key stems. The stems are new and
do not collide with the B13 copy deck; every stem of the four activation emails will live in `i18n/en/onboarding.ftl`
when those tasks land, and an i18n check resolves them when the templates ship (T-0082).

| Email | Subject | Structure | i18n key stems |
| --- | --- | --- | --- |
| welcome | Welcome to Hack Dev Defence | Opening line, the one action to take now, what the checklist does, the footer with the privacy link. | `email-welcome-subject`, `email-welcome-intro`, `email-welcome-action`, `email-welcome-footer` |
| verify | Confirm your email address | Greeting, the confirm button, the expiry time, the resend link, a short safety note. | `email-verify-subject`, `email-verify-button`, `email-verify-expiry`, `email-verify-resend` |
| first domain | Add your first website | Why a domain is needed, the exact next step, one link to the add-domain wizard, where to ask for help. | `email-first-domain-subject`, `email-first-domain-intro`, `email-first-domain-action` |
| weekly summary | Your week in protection | Seven-day counts from local data, the open readiness items, one next action, the unsubscribe footer. | `email-weekly-summary-subject`, `email-weekly-summary-counts`, `email-weekly-summary-action`, `email-weekly-summary-footer` |

The welcome email is sent once per account. The verify email is sent by the verification flow, not by the onboarding
job. The first-domain email is sent only while the organisation owns no domain. The weekly summary is opt-out and
carries no comparison with other installations.

## References

- [Readiness model](READINESS-MODEL.md): the categories, weights, unknown rule and the exact footnote.
- [J-07](journeys/J-07.md), [J-16](journeys/J-16.md) and [J-25](journeys/J-25.md): the journey records this document
  implements.
- [UX charter](CHARTER.md), [content strategy](CONTENT.md) and [experience measures](MEASURES.md).
