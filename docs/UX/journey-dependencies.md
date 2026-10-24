# Journey dependencies

Every journey of B3 is finished by T-0016, T-0017 and T-0018. This document records which journey a journey needs
before it can make sense, so reviewers can see the order the product teaches. A `Needs` edge means: the prerequisite
journey's outcome must exist before the dependent journey can start.

Rule used by the check: a dependency points to a lower-numbered journey. A dependency on a higher-numbered journey is
accepted only when the `Why` cell of that row says so as an `exception`; no journey may depend on itself. Two journeys
the specification presents as alternatives of the same choice (J-08 and J-09, `docs/spec/B1.md` line 248) must not
depend on each other. The graph must be acyclic and the section `Graph` below is a text graph, never a diagram tool.
The section `Task dependencies` maps every journey dependency to the specification tasks that deliver the two
journeys and states the basis: `direct`, `earlier` (the stable task order places the prerequisite task first) or
`none` (the specification names no task dependency). When the stable task order puts the prerequisite task after the
dependent task, the `Why the order agrees` cell records that as an `exception` instead of hiding it.

## Dependency table

| Journey | Needs | Why |
| --- | --- | --- |
| J-01 | none | A visitor can reach the public story with no earlier journey. |
| J-02 | J-01 | Signup starts from the public page and its call to action. |
| J-03 | J-02 | MFA enrolment needs an account created by signup. |
| J-04 | J-02 | Login needs the account and the verified email. |
| J-05 | J-04 | Password reset is reached from the login screen. |
| J-06 | J-02, J-26 | An invitation created by J-26 must exist, and a new user accepts it through signup (J-02); the J-26 edge is an exception to the lower-number rule. An existing user reaches the same membership through login (J-04) instead. |
| J-07 | J-02 | The checklist starts right after signup and verification, before the first normal login. |
| J-08 | J-07 | The add-domain wizard starts from the onboarding checklist call. |
| J-09 | J-07 | J-09 is the CNAME alternative of J-08; both start from the wizard entry reached from J-07 (B1.md line 248). |
| J-10 | J-07 | The apex choice is a step of the same wizard, so it needs the wizard entry, not J-08 (B1.md line 251). |
| J-11 | J-07 | Ownership verification is a step of the wizard reached from J-07 (B1.md line 254). |
| J-12 | J-07 | The origin step is part of the wizard; it needs the wizard entry, not the delegation journey (B1.md line 257). |
| J-13 | J-07 | The DNS import and parity review is the wizard's record step, reached from J-07 (B1.md line 260). |
| J-14 | J-13 | Editing records needs an imported zone to edit. |
| J-15 | J-12 | Certificates need the configured origin and hostname. |
| J-16 | J-15 | Monitor mode needs a working HTTPS path (J-15); its later block-mode switch uses the J-24 lockdown state, which is not a prerequisite of this journey. |
| J-17 | J-16 | The shield builds on the protection settings chosen in monitor mode. |
| J-18 | J-16 | The analyst reads events produced by monitor or block mode. |
| J-19 | J-16 | A custom rule is written against the recent traffic that monitor mode produces (B1.md line 278). |
| J-20 | J-16 | Rate limits are applied to the authentication endpoints detected in the traffic (B1.md line 281). |
| J-21 | J-16 | Alert rules target the attack events that monitor mode produces (B1.md line 284). |
| J-22 | J-16 | The appeal exists because a protection mode can block a visitor. |
| J-23 | J-22 | The owner resolves an appeal the visitor has filed. |
| J-24 | J-12 | The lockdown wizard needs a configured origin (J-12) and comes before block mode, not after it (R-34). |
| J-25 | J-08 | Readiness is a per-domain page: it needs the domain that the add-domain wizard creates (J-08), while TLS, origin and lockdown are checks on the page, not prerequisites to view it. |
| J-26 | J-04 | Team invitations need a signed-in owner. |
| J-27 | J-04 | Creating an API key needs the signed-in developer. |
| J-28 | J-16 | Reports need the event data that protection produces; the audit trail starts earlier (B1.md line 305). |
| J-29 | J-02 | A platform tenant exists once an organisation has signed up. |
| J-30 | J-29 | Global bans and abuse triage operate on tenants. |
| J-31 | J-29 | Emergency controls and infra checks need the platform surface. |
| J-32 | J-08 | Decommission reverses the integration created by the add-domain wizard; J-08 is the canonical add journey and J-09 and J-10 are alternative modes of the same outcome. |
| J-33 | J-04, J-26 | The privacy page needs the signed-in account and the owner transfer that the team journey provides. |
| J-34 | J-16, J-21 | The incident starts from an alert on protection events: monitor mode produces the events (J-16) and an alert rule must exist (J-21) (B1.md line 323). |

## Graph

The graph is the same information as the table, written as directed arrows from a journey to the journey it needs.

J-01 <- none

J-02 -> J-01

J-03 -> J-02

J-04 -> J-02

J-05 -> J-04

J-06 -> J-02

J-06 -> J-26

J-07 -> J-02

J-08 -> J-07

J-09 -> J-07

J-10 -> J-07

J-11 -> J-07

J-12 -> J-07

J-13 -> J-07

J-14 -> J-13

J-15 -> J-12

J-16 -> J-15

J-17 -> J-16

J-18 -> J-16

J-19 -> J-16

J-20 -> J-16

J-21 -> J-16

J-22 -> J-16

J-23 -> J-22

J-24 -> J-12

J-25 -> J-08

J-26 -> J-04

J-27 -> J-04

J-28 -> J-16

J-29 -> J-02

J-30 -> J-29

J-31 -> J-29

J-32 -> J-08

J-33 -> J-04

J-33 -> J-26

J-34 -> J-16

J-34 -> J-21

## Task dependencies

Each row maps one edge of the dependency table to the tasks that deliver the two journeys. `direct` means the
dependent task names the prerequisite task in its `deps:` line; `earlier` means the stable topological order of
section 0.9 places the prerequisite task first; `none` means the specification names no task dependency between the
two tasks. A `none` row whose tasks nevertheless appear in the opposite order records that as an `exception`.

| Journey dependency | Prerequisite task | Dependent task | Basis | Why the order agrees |
| --- | --- | --- | --- | --- |
| J-02 needs J-01 | T-0054 | T-0107 | earlier | The stable order places the public pages task before the signup task. |
| J-03 needs J-02 | T-0107 | T-0114 | earlier | The signup task precedes the MFA enrolment task. |
| J-04 needs J-02 | T-0107 | T-0112 | earlier | The signup task precedes the login task. |
| J-05 needs J-04 | T-0112 | T-0119 | earlier | The login task precedes the password reset task. |
| J-06 needs J-02 | T-0107 | T-0127 | earlier | The signup task precedes the invitation task. |
| J-06 needs J-26 | T-0127 | T-0127 | none | The same task T-0127 delivers both journeys, so the spec names no task dependency. |
| J-07 needs J-02 | T-0107 | T-0143 | earlier | The signup task precedes the onboarding checklist task. |
| J-08 needs J-07 | T-0143 | T-0168 | earlier | The onboarding checklist task precedes the go-live task. |
| J-09 needs J-07 | T-0143 | T-0159 | earlier | The onboarding checklist task precedes the CNAME integration task. |
| J-10 needs J-07 | T-0143 | T-0162 | earlier | The onboarding checklist task precedes the A-record verification task. |
| J-11 needs J-07 | T-0143 | T-0160 | earlier | The onboarding checklist task precedes the ownership verification task. |
| J-12 needs J-07 | T-0143 | T-0163 | earlier | The onboarding checklist task precedes the origin configuration task. |
| J-13 needs J-07 | T-0143 | T-0157 | earlier | The onboarding checklist task precedes the DNS import task. |
| J-14 needs J-13 | T-0157 | T-0181 | earlier | The DNS import task precedes the DNS records screen task. |
| J-15 needs J-12 | T-0163 | T-0196 | earlier | The origin task precedes the TLS settings task. |
| J-16 needs J-15 | T-0196 | T-0237 | earlier | The TLS settings task precedes the security policy task. |
| J-17 needs J-16 | T-0237 | T-0224 | earlier | The security policy task precedes the shield task. |
| J-18 needs J-16 | T-0237 | T-0446 | earlier | The security policy task precedes the live monitor task. |
| J-19 needs J-16 | T-0237 | T-0228 | earlier | The security policy task precedes the rule builder task. |
| J-20 needs J-16 | T-0237 | T-0230 | earlier | The security policy task precedes the rate-limit task. |
| J-21 needs J-16 | T-0237 | T-0453 | earlier | The security policy task precedes the alert-rules task. |
| J-22 needs J-16 | T-0237 | T-0324 | earlier | The security policy task precedes the appeals task. |
| J-23 needs J-22 | T-0324 | T-0324 | none | The same task T-0324 delivers both journeys, so the spec names no task dependency. |
| J-24 needs J-12 | T-0163 | T-0406 | earlier | The origin task precedes the origin lockdown wizard task. |
| J-25 needs J-08 | T-0168 | T-0172 | earlier | The go-live task precedes the readiness task. |
| J-26 needs J-04 | T-0112 | T-0127 | earlier | The login task precedes the invitation task. |
| J-27 needs J-04 | T-0112 | T-0124 | earlier | The login task precedes the API key task. |
| J-28 needs J-16 | T-0237 | T-0448 | earlier | The security policy task precedes the report builder task. |
| J-29 needs J-02 | T-0107 | T-0419 | earlier | The signup task precedes the tenant list task. |
| J-30 needs J-29 | T-0419 | T-0424 | earlier | The tenant list task precedes the global jail task. |
| J-31 needs J-29 | T-0419 | T-0434 | earlier | The tenant list task precedes the emergency controls task. |
| J-32 needs J-08 | T-0168 | T-0173 | earlier | The go-live task precedes the decommission task. |
| J-33 needs J-04 | T-0112 | T-0130 | earlier | The login task precedes the data export and deletion task. |
| J-33 needs J-26 | T-0127 | T-0130 | earlier | The invitation task precedes the data export and deletion task. |
| J-34 needs J-16 | T-0237 | T-0477 | earlier | The security policy task precedes the incident-timeline task. |
| J-34 needs J-21 | T-0453 | T-0477 | earlier | The alert-rules task precedes the incident-timeline task. |
