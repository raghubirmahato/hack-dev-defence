# AGENTS.md: digest of the Hack Dev Defence (HDD) build specification

Digest only (at most 150 lines, checked by `cargo xtask verify` once it exists). Detail lives in `docs/SPEC.md` (verbatim, sha256 in `docs/SPEC.sha256`)
and its split in `docs/spec/`. Per-task detail: `docs/tasks/Pxx/T-nnnn.md`. Phase detail: `docs/phases/Pxx.md`. Spec v5.2, 599 tasks, 35 phases (P00 to P34).

## Session start ritual (spec section 0.1)
1. Read this file, then `STATUS.md`, then `HANDOFF.md`, then `git status`.
2. Read Part A section 0 of the spec once per session (`docs/spec/A0.md`), then the phase file of the task in hand, then only the registry rows the task references.
3. Registry lookup is by ID with grep: `S-nnn` screens, `J-nn` journeys, `ATK-nnn` attacks, `AC-nn` checks, `ERR-` codes, `MET-` metrics, `AUD-` audit events, `PERM-` permissions.
4. Never rely on chat memory: facts live in `STATUS.md`, `HANDOFF.md`, an ADR, `docs/DEVIATIONS.md` or `docs/CAPABILITY-MATRIX.md`.
5. Priority on conflict: safety envelope > honesty/claims > Part C hardening > numbered requirements and `AC-nn` > tasks > backlog. Take the safer option and log it in DEVIATIONS.

## Non-negotiable rules (section 3)
- R-01 No placeholders: no `todo!()`, `unimplemented!()`, `// TODO`, fake data; lints deny `unwrap`/`expect`/`panic`/indexing/`dbg!`/`print_stdout` outside tests.
- R-02 Honest verification: no pass without pasted real output; never delete, skip, `#[ignore]` or weaken a test, fixture or threshold; every check ends PASS, FAIL or UNVERIFIED(reason).
- R-03 Secure by default: no hardcoded/default secrets; `secrecy`/`zeroize`; containers non-root, read-only, caps dropped.
- R-04 Human-gated steps are real: detect state with real probes, print exact instructions, wait.
- R-05 Environment discovery first (read-only); say what degrades.
- R-06 Phased with gates: do not pass a gate without real output in the E5.1 report.
- R-07 Traceability: every requirement `REQ-<PREFIX>-<nn>` links to at least one test in `docs/CAPABILITY-MATRIX.md`.
- R-08 Vet dependencies before pinning (exists, maintained, licence, MSRV, API); ADR for FFI/unmaintained/unsafe-API crates; never assert a version from memory.
- R-09 No panic reachable from network input; release profile unwinds; caught panics counted and alerted.
- R-10 Claims policy (section 4): `cargo xtask claims-lint`; forbidden phrases include "absolute", "complete", "total" protection claims.
- R-11 Virtual patches are not fixes; the vulnerability stays open until patched or VEX `not_affected`.
- R-12 HDD patches itself: own dependencies follow advisory SLAs and signed updates.
- R-13 Escalation actions are reversible and audited; no permanent DNS/firewall/provider change without audit and undo.
- R-14 Failure budget: at most 3 distinct root-cause fixes per failing check, then `docs/diagnoses/<id>.md` and ask the operator; never loosen a test or limit.
- R-15 Deviations and assumptions go to `docs/DEVIATIONS.md`.
- R-16 UI honesty: no fabricated numbers, sample rows or placeholder charts; empty states are honest. Prototypes are labelled design artifacts.
- R-17 WCAG 2.2 AA is a gate (AC-40); a screen without keyboard operation is not done.
- R-18 Tenant isolation is tested (RLS plus BOLA suite) before any tenant-owned resource is exposed.
- R-19 No self-lockout: warn, preview, undo; never remove the break-glass path.
- R-20 Enumeration-safe and timing-safe identity flows.
- R-21 No secrets or PII in URLs; single-use tokens exchanged by POST.
- R-22 One egress path: everything outbound goes through `hdd-common::egress` (allowlist or SSRF guard, timeout, size cap).
- R-23 Detection changes are measured against benign corpus, core set, held-out set and mutation score; tuning never uses held-out data.
- R-24 Bans are explainable (rule, subtype, vector, field, redacted evidence, branch, TTL step, config revision).
- R-25 Data minimisation: evidence at most 512 bytes redacted; bodies never logged in full.
- R-26 Inspection never fails open; safe mode is the only deliberate pass-through and never bypasses the access gate.
- R-27 UI/API parity: every UI action is an API call under the same authorisation.
- R-28 No dark patterns: type-to-confirm for destructive actions; safe option is the default.
- R-29 Budgets (performance, size, accessibility) are tests.
- R-30 Docs ship with the feature (user docs plus operations entry).
- R-31 One code path, two runtime profiles (`local`, `hosted`); no `DEV_MODE`; `cargo xtask profile-parity` must show zero decision differences.
- R-32 No absolute claims: completeness is shown by the coverage map and the known-limitations list, never by adjectives.
- R-33 Learned components (Sentinel) are bounded, advisory-first, explainable; they never ban alone or override a deterministic verdict.
- R-34 A site is not "protected" while it can be bypassed; `block` mode needs a verified lockdown state or a typed, audited risk acceptance.

## Safety envelope essentials (section 2)
- Attack-shaped traffic goes only to the allowlist derived from the live profile (`test_hostname`, `sandbox_hostname`, lab addresses in lab mode). Never scan or probe third parties. In `saas` mode tenants' domains are never targets.
- Payload classes: A (inert shapes, GET/HEAD to `test_hostname`), B (destructive if it reached an origin: sandbox only), C (never sent live: inspect API and unit tests only). Every live attack-shaped request passes the inspect-first gate.
- Rate profiles: `functional`, `burst`, `protocol-abuse`, `load` (needs separate written approval), `lab`. Kill switch file `/var/run/hdd-acceptance.stop`.
- No volumetric test over the internet; L3/L4 floods exist only in the operator's closed lab. Vuln-Lab (`lab/vulnlab`) is lab-only and never shipped.
- The runner IP is never in `admin_cidrs`; every test ban has a short TTL. Email only to `operator_email`. Never print secrets. Destructive-command guard and SSH-lockout protection (timed auto-revert) on host-affecting changes.
- Local profile: loopback binding only, no silent privilege, owner-only data dir, no XDP/nftables, no trust-root install without consent (section 2.11).

## Commands
- `cargo xtask verify [--only step ...]` is the gate: fmt, clippy, nextest, doc-tests, deny, audit, vet, unsafe-scan, vulnlab-graph, rules, machete, spec/tasks/adr checks, dependency-vetting, profile-check, secret-scan, claims-lint, rust-share, matrix-check, profile-lint, kv-lint, ux-docs (logs + sha256 under `acceptance-verify/`). Steps that cannot run end `UNVERIFIED(reason)`.
- Also: `cargo xtask spec split|check|show T-nnnn`, `tasks index [--check]|order|check`, `matrix generate|check`, `gate-report Gnn [--collect] [--check]`, `profile schema|check`, `profile-lint`, `kv-lint`, `profile-parity` (stub), `verify --only kv-bench|kv-redis`, `db up|down|reset|status` (embedded PostgreSQL), `build-plan table`, `deps check`, `adr check`, `secrets scan [--staged]`, `hooks install`, `gen-secrets`, `claims-lint`, `rust-share`. Stubs (success + note until their task): `attack-matrix check` (T-0245), `contrast-check` (T-0030), `i18n check` (T-0082), `routes check` (T-0073).
- `hddctl preflight --plan` prints the build track and what can run here; `hddctl preflight --profile-only [--file hdd.live.yaml]` validates the live profile; without the flag it adds the two egress-guarded probes. `ui verify`, `db up` and `hdd-acceptance` come later.
- Every new external crate needs an entry in `docs/vetting.toml` (and an ADR if FFI, `unsafe` API or no release for a year). Every outbound connection goes through `hdd-common::egress`.

## Task protocol (section 0.6) and states
Read block and registry rows -> write failing tests (`red`) -> minimum implementation -> `cargo xtask verify` -> live/lab checks with evidence -> tag checklists (section 0.7) -> update ARCHITECTURE/OPERATIONS/CAPABILITY-MATRIX/STATUS -> hostile self-review (E6) -> Conventional Commit with `Task: T-nnnn` trailer. Never force-push; never commit secrets.
States: `todo`, `designing`, `red`, `green`, `verified`, `accepted`, `done`, `blocked(<reason>)`, `deferred(<reason>, <effort>)`.
Execution order is the stable topological order of `deps:` (`INDEX.md`); a dependency on a later number is legal (T-0561 to T-0563 run right after G00).

## Where things live
`crates/` workspace (owners in `ARCHITECTURE.md`) | `lab/` never shipped | `design/` tokens and prototypes | `docs/UX/` UX charter (`CHARTER.md`: seven principles, five honesty tests), `MEASURES.md`, `decisions/UXD-nnn.md` | `tests/fixtures/` tagged payloads | `docs/spec/INDEX.md` task to file+line |
`docs/COLLAB.md` shared log of the two tools (Claude leads and commits; DeepSeek Harness implements the assignment written there; read it at session start) | `docs/tasks/` one file per task | `docs/gates/` gate reports and template | `docs/adr/` decisions | `docs/OPERATOR-QUESTIONS.md` open questions | `hdd.live.example.yaml` profile | `.env.example` settings.

## Current position
Phase P00 (gate G00, milestone M0). T-0001 to T-0010 are done. Every pass condition of G00 holds with evidence (`docs/gates/G00.md`), including the first response (`docs/FIRST-RESPONSE.md`, all 58 questions OPEN). **G00 passed**: committed (1ec43bd, 051eeac, fb82732) and tagged `gate-G00`; the pre-commit hook is installed. Waiting for the operator's answers. T-0561 to T-0563 (DS0) are verified (evidence under `docs/evidence/P33/`). T-0011 (UX charter) T-0012 (personas) and T-0013 (pattern review, UNVERIFIED(capability_not_supplied)) are verified (`docs/UX/`). T-0014 (IA and URL scheme, `docs/UX/routes.toml`) is verified. T-0015 (navigation model) is verified. T-0016 (journey maps J-01 to J-12) is verified. T-0017 (journey maps J-13 to J-24) is verified. T-0018 (journey maps J-25 to J-34, dependency graph) is verified, so all 34 journeys exist. T-0019 (content strategy, glossary, claims context rules, copy deck) is verified. Batch B1 (T-0022 accessibility, T-0024 responsive, T-0025 security UX, T-0026 onboarding, T-0027 data visualization) is verified. Batch B2 (T-0020 error UX, T-0023 i18n, T-0210 hdd-canary, T-0215 hdd-acceptance skeleton) is verified. Next: T-0021, T-0028 (human gate G01), or the hackathon demo track HK1 (see COLLAB.md); T-0564 needs the Q-048 answer. Authoritative detail: `STATUS.md`, `HANDOFF.md`.

## Stop conditions and approvals (sections 0.5, E8.1)
Ask the operator (one batched message, only when blocked) before: loosening any E4 value or safety limit; adding an egress destination; production ACME issuance; apex cutover; a `load` run; provider-side tests; enabling open signup; emailing anyone but `operator_email`; changing brand, legal text or pricing; switching a production site `monitor` -> `block`; enabling auto-update or auto-failover.
Human stops: M1 design sign-off (P03), STOP #1 at M5 (canary files, pilot NS/A delegation, provider AUP), M3 SMTP details, STOP #2 at M12 (registrar prep, origin firewall + secret header, secondary DNS, DDoS contract), production ACME approval, any `load` run, cutover.
If context runs low, write `HANDOFF.md` (phase, failing tests, next 10 tasks, decisions, open questions, resume commands) so a new session resumes without loss.
