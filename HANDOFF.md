# HANDOFF

Entry point 3 of 3 (AGENTS.md, STATUS.md, HANDOFF.md). Rewritten at the end of every working session so a new session can resume from files alone.

## Session record

- Date: 2026-10-18 (second P00 session). Builder: Windows 11, Track L (no Docker), Rust 1.98.1. See `docs/ENV.md`.
- Done this session: T-0005 (`hdd-xtask`: verify pipeline, spec/tasks tools, claims-lint, rust-share, secret scanner, hooks, gen-secrets), T-0006 (profile types, schema,
  validator, `hddctl preflight`), the dependency-vetting lint that finishes T-0008, T-0009 (egress clients, SSRF guard, target guard, kill switch, deny log, probes) and the
  mechanics of T-0010 (capability matrix tooling, gate report generator). `tools/bootstrap/` is deleted (DEV-V5-000 closed on 2026-10-18).
- Third session (2026-10-19): **T-0007 done** - the first response is `docs/FIRST-RESPONSE.md` (six items of section 9, all 58 questions with levels pilot / cutover / feature / default). No answer yet: every question is OPEN.
- Fourth session (2026-10-19): DS0 built - T-0561, T-0562, T-0563 (see STATUS.md). Environment facts for the next session: Windows Application Control (a code-integrity policy: "did not meet the Enterprise signing level") blocks freshly linked executables and, intermittently, installed tools (`os error 4551`); after a rebuild repeat the command, touching a source file first if the same exe stays blocked; a blocked step is a FAIL until it passes. `cargo-deny` and `cargo-machete` were reinstalled at the same pinned versions for that reason. The embedded database of this session is stopped; `target/hdd-db` holds the cached archive (git-ignored).
- Gate closure (2026-10-19, operator's request): three commits (1ec43bd xtask, 051eeac common/hddctl, fb82732 docs and evidence), tag `gate-G00` on fb82732, `cargo xtask hooks install` done (core.hooksPath=.githooks). `.gitignore` now keeps gate evidence logs. **G00 passed.** Report: `docs/gates/G00.md`; evidence (logs with sha256, negative demonstrations, hook demonstration, preflight outputs, hostile review) is in `docs/gates/evidence/G00/`.

## Phase and position

Phase P00, gate G00, milestone M0. All ten tasks T-0001 to T-0010 are `done` (promoted 2026-10-19 after the tag; evidence in `docs/matrix-links.toml`). Execution order: `INDEX.md`.

## Failing tests

None. `cargo xtask verify` ends with 0 FAIL and 4 UNVERIFIED named stubs (attack-matrix, contrast, i18n, routes checks). Full output tails: `docs/gates/G00.md` section 1.

## Next 10 tasks

| # | Task | Why now | Blocker |
| --- | --- | --- | --- |
| 1 | Operator answers to `docs/FIRST-RESPONSE.md` | Q-048 (local, hosted or both) decides the path; pilot-level questions (Q-019 to Q-022, Q-025, Q-027, Q-039, Q-040, Q-048, Q-051, Q-052) are needed before any live step | the operator |
| 2 | Batch B2 is verified (T-0020, T-0023, T-0210, T-0215). Next: T-0021, then T-0028 (review pack, human gate G01); hackathon demo track HK1 runs first on the operator's instruction | P01 | none |
| 3 | T-0022 Accessibility strategy and test plan | P01 | none |
| 5 | T-0564 `hdd-local` supervisor (lifecycle, readiness, first run, doctor) | DS0; also lands the `profile-parity` check | Q-048 answer |

Order note: T-0561 to T-0563 (DS0) are verified (2026-10-19); T-0564 and later DS0 tasks follow once Q-048 is answered.

## Decisions made this session

Recorded in `docs/DEVIATIONS.md` (ASM-007 onward) and the ADRs: serde-saphyr as YAML parser (ADR-0002), `serde_path_to_error` (ADR-0026), `ring` as provisional TLS provider (ADR-0001, `spiking`),
`cargo vet` with all third-party crates exempted and no imported audit sets, tokei/cargo-vet/cargo-geiger installed after vetting, the matrix rules (`docs/matrix-links.toml`), and
the honest handling of what could not be done (no fuzz target, no benchmark).

## Open questions

Nothing has been answered (all OPEN). Full register with levels: `docs/OPERATOR-QUESTIONS.md` (Q-001 to Q-058); the message to the operator: `docs/FIRST-RESPONSE.md`. The ones that decide the path ahead: Q-048 (local, hosted or both; the Track L builder suggests local first),
Q-001 (`owner_only` or `saas`), Q-040 (egress allowlist, needed for the reachability probes and ACME), Q-005/Q-006 (brand, legal text owner). New this session: which published `cargo vet` audit sets to trust;
(the commit and hook question was answered yes on 2026-10-19).

## Resume commands

```bash
cd "D:/Hack Dev Defence"
head -40 STATUS.md
cargo xtask verify                      # the gate; logs and sha256 under acceptance-verify/
cargo xtask gate-report G00 --check     # the committed report equals the regenerated one
./target/debug/hddctl preflight --profile-only --file hdd.live.example.yaml
```
