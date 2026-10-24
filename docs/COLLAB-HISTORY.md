# Collaboration history (closed tasks T-0012 to T-0016)

Moved out of `docs/COLLAB.md` on 2026-10-19 so that the live log stays short enough for a fresh session to read in full. Nothing here is current; it is
the record of the reports and review findings of the closed tasks. The lessons they taught are summarised under `Lessons` in `docs/COLLAB.md`.

## Reports (closed tasks)


### 2026-10-19 · DeepSeek Harness · T-0012 Personas and jobs-to-be-done · status: implemented, local checks PASS, not committed

**Files changed (all within the assignment; `STATUS.md`, `HANDOFF.md`, the matrix files and `INDEX.md` untouched; no commit):**

- `docs/UX/personas/maya.md`, `dan.md`, `sara.md`, `omar.md`, `vi.md`, `alex.md`, `adversary.md` (new, 7 files): each has
  a "fictional composite" header, the five context-of-use rows (device, connectivity, interruptions, vocabulary, first
  check of the day), three "When ..., I want to ..., so I can ..." scenarios with a measurable outcome naming an `AC-`,
  `AUD-` or `MET-` id, anti-goals, accessibility needs and assistive-technology assumptions mapped to B11.11, and links
  to their journeys and screens. B1.1 to B1.7 are quoted as the source; B1.4 and B1.6 name no accessibility needs, so
  their sections say the needs are derived from the duties (A3 is then explicit, not invented).
- `docs/UX/persona-journey-matrix.md` (new): J-01 to J-34, each row linked to at least one persona file; the adversary is
  deliberately not a journey owner and its abuse stories are reviewed against every journey (noted in the file).
- `docs/OPERATOR-QUESTIONS.md` (changed, +16 lines): appended `## Primary persona for the pilot (added by T-0012)` with
  default Maya (B1.1), State **OPEN**, and a link from the matrix and `personas/maya.md` (A5). It is deliberately not a
  `Q-nnn` row: `rules::check_first_response` freezes the numbered register at the 58 verbatim Appendix E8 questions and
  every id must appear in `FIRST-RESPONSE.md`; turning it into Q-059 needs those two files and the rule changed, which is
  outside T-0012. `cargo xtask verify --only rules` PASS with this shape.
- `crates/hdd-xtask/src/ux_docs.rs` (+581): `attack_registry()` (only C5 table rows; the master specification is read via
  `spec::load_master`, so it is sha256-verified), `persona_findings()` (header, context rows, scenarios and outcomes,
  anti-goals, B11.11 mapping, journeys/screens), `adversary_findings()` (>=10 distinct `ATK-` ids, each a C5 row),
  `matrix_findings()` (every J-01..J-34 exactly once and linked to a persona file, no invented ids) and
  `primary_persona_findings()` (question present, default Maya, OPEN); all are wired into `check()`, which now also
  reports missing persona files, a missing matrix or register, and an unreadable registry.
- `crates/hdd-xtask/src/ux_docs/tests.rs` (+338): 16 new tests and fixtures; `good_tree` now writes personas, the matrix,
  the register and a synthetic master spec with its checksum.

**Tests first (red):** `docs/evidence/P01/T-0012-red.txt` (full `cargo nextest run -p hdd-xtask --no-fail-fast` output,
26790 bytes, sha256 `aefad2ce06b6d8f43b925387c622ee17bf5216383355df2b9ec6d7a55354bc12`). Result line: `Summary [1.353s]
127 tests run: 112 passed, 15 failed, 0 skipped` — the 15 new negative tests fail against the empty stub functions. The
positive fixture test passed trivially against the stub and is green after the implementation; the shipped-documents
test became meaningful when `check()` was wired.

**Commands and real result lines** (full output: `docs/evidence/P01/T-0012-verify.txt`, 17955 bytes, sha256
`609a268bcfff450942c0130d5fff2c828c874a224f3efed07cf3fb17624010fc`):

- `cargo fmt --all --check` → `(exit 0)`
- `cargo clippy --workspace --all-targets -- -D warnings` → `(exit 0)`
- `cargo nextest run -p hdd-xtask --no-fail-fast` → `Summary [2.808s] 127 tests run: 127 passed, 0 skipped`
- `cargo xtask ux-docs` → `ux-docs: PASS`
- `cargo xtask claims-lint` → `claims-lint: scanned 105 files with 34 phrases` / `claims-lint: PASS`
- `cargo xtask verify --only rules spec-check tasks-check ux-docs claims-lint` → `verify: 5 PASS, 0 FAIL, 0 UNVERIFIED`
- `cargo xtask verify --only matrix-check` → `verify: 1 PASS, 0 FAIL, 0 UNVERIFIED`
- `cargo xtask verify --only secret-scan` → `verify: 1 PASS, 0 FAIL, 0 UNVERIFIED`

**Negative demonstrations:** `docs/evidence/P01/T-0012-negative-demos.txt` (2407 bytes, sha256
`b16dae923ba39ff721131d5dc7922e85cfc45cc1e583afd26838498c52c64f66`). Ten mutations of the shipped documents each make
`cargo xtask ux-docs` FAIL with the intended finding: header without "fictional composite" (maya, alex), two scenarios,
no measurable outcome, no anti-goals, accessibility not mapped to B11.11, 7 distinct `ATK-` ids, `ATK-999` not in the
registry, J-17 missing from the matrix, question not OPEN. Restoring the files gives `ux-docs: PASS`, and the restored
SHA-256 hashes equal the pre-demo hashes.

**UNVERIFIED:** none of the implemented checks is UNVERIFIED. The full gate `cargo xtask verify` (all steps, workspace
nextest, doc-tests, deny/audit/vet) was not run by the implementer — by agreement it is Claude's gate. No live or lab
check applies to this `[DOC]` task.

**Notes for review (not fixed, outside the assignment):** the `verify.rs` log label for the `ux-docs` step still says
"T-0011: charter, measures and decisions ..."; it does not mention the T-0012 checks. Also, if the Lead prefers the
primary-persona question to be a numbered `Q-059`, that needs `FIRST-RESPONSE.md` and `rules::check_first_response`
changed together, plus the "58 questions" wording in `STATUS.md`; left to the Lead.

### 2026-10-19 · DeepSeek Harness · T-0012 round 3

**F-4 (vacuous outcome).** Tests first: `docs/evidence/P01/T-0012-f4-red.txt` (sha256
`8ada37dbf05a5c16e11eeb74b0876bc36c03daf1a38ec4f1936bec923a206e97`): `Summary ... 2 tests run: 0 passed,
2 failed`; the failures are `` `see J-02` must not be measurable `` and `` `zero` must be measurable ``. Implemented:
`without_identifiers` removes `J-nn`, `S-nnn`, `ATK-nnn`, `T-nnnn`, `Q-nnn` and `B<n>.<n>` before measurement;
`is_measurable` then accepts an `AC-nn`/`AUD-...`/`MET-...` id, a number with a unit (`3 minutes`, `5 clicks`, `100%`,
`0 errors`), a comparator plus number (`at most 2`, `under 10 s`, `within 1 day`) or `zero`; the scenario finding text
now states that rule. `cargo xtask ux-docs` PASS, so every outcome in the seven shipped personas passes the stricter
rule and no persona outcome needed changing. Demonstration (`docs/evidence/P01/T-0012-f4-f5-demos.txt`, sha256
`41df9b3172cbaab15177356139c3e23ddac2858b4a0b756474819a3d94fe6514`): maya's first outcome replaced by "Measurable
outcome: it works well for everyone, see J-02." makes `ux-docs` FAIL with `docs/UX/personas/maya.md:23: a scenario's
measurable outcome names no ...`; restored file gives PASS and the SHA-256 is unchanged.

**F-5 (criteria validated).** Tests first: `docs/evidence/P01/T-0012-f5-red.txt` (sha256
`2b6fb474b94e86f3dfe644b2ebae75fbde8e5032d353dd4368eccfa60841f96a`): `Summary ... 4 tests run: 1 passed, 3 failed`
(the table-parsing and `9.9.9`-reported tests fail against the stub). Implemented `b11_11_criteria`, which reads the
`### B11.11` table's "Criterion" column through `spec::load_master` (entries split on `/`, `x` entries kept), and
`criterion_is_covered` (exact match, or an `x` entry for the same major.minor). Every cited criterion is now reported
when the table does not cover it, and only covered criteria count toward the two-criterion minimum. Verified every
shipped persona: `cargo xtask ux-docs` PASS, so none cites an uncovered criterion; the specification was not edited.
Demonstration (same file): maya citing `9.9.9` makes `ux-docs` FAIL with `` `9.9.9` is not a criterion of the B11.11
table (A3) ``; restored file gives PASS.

**Minor (section-scoped match).** `primary_persona_findings` now reads only the section titled `Primary persona for
the pilot`; a row elsewhere that mentions both "persona" and "primary" is ignored. Test first:
`docs/evidence/P01/T-0012-minor-red.txt` (sha256
`a84468af249d523b9dc3063d2e9c380c6ac98fc3fd89680f40603c8a93e9e4f0`): the decoy row used to be matched (findings on
the wrong row); the test now passes.

**Checks (round 3):** `docs/evidence/P01/T-0012-verify-round3.txt`, sha256
`5d5ce14f397a5fd35d5ac47f41a6735978a55bf572c2760678a56b9f5c9a5761`: `cargo fmt --all --check` exit 0;
`cargo clippy --workspace --all-targets -- -D warnings` exit 0; `cargo nextest run -p hdd-xtask --no-fail-fast` →
`Summary [3.093s] 136 tests run: 136 passed, 0 skipped`; `cargo xtask ux-docs` → `ux-docs: PASS`;
`cargo xtask claims-lint` → `claims-lint: PASS`; `cargo xtask verify --only rules spec-check tasks-check ux-docs
claims-lint` → `verify: 5 PASS, 0 FAIL, 0 UNVERIFIED`. Full gate remains Claude's; UNVERIFIED: none. No commit;
`STATUS.md` and `HANDOFF.md` untouched. Note: the round-2 reply that was under Reports is no longer in this file; I
have not re-added it unasked.

### 2026-10-19 · DeepSeek Harness · T-0012 round 4

**F-6 (missing Maya link on J-22).** `docs/UX/persona-journey-matrix.md` J-22 row now links `[Vi](personas/vi.md),
[Maya](personas/maya.md)` with the reason "the owner whose visitors file appeals must understand it"; the J-23 row is
unchanged. `cargo xtask ux-docs` PASS.

**F-7 (the check can see this class of error).** Tests first: `docs/evidence/P01/T-0012-f6-red.txt` (sha256
`073be2ec73c7c79c361e32b3d37032ddbc52d90476995daabe5c46d1e8198d22`). Part 1 shows the new tests against the stubbed
`key_journeys` (`Summary ... 4 tests run: 2 passed, 2 failed`, failing: the slash/range expansion and a declared key
journey missing from the persona file). Part 2 shows the shipped tree failing before the F-6 edit: `the matrix row for
J-22 does not link persona maya, whose key journeys include it (spec B1.1)` (`Summary ... 1 test run: 0 passed,
1 failed`). Implemented: `key_journeys(spec, heading)` reads the `Key journeys` row of the `### B1.x` tables through
`spec::load_master` and expands `J-a/J-b` and `J-a to J-b` forms (B1.7 has no row and is exempt);
`persona_journey_list()` reads the persona's `Journeys and screens` list; `matrix_persona_links()` reads the persona
files each journey row links; `key_journey_findings()` reports, per persona, every declared key journey missing from
the persona file or from its matrix row, and every journey the file lists whose matrix row does not link it (the
matrix may link more personas than a file lists). Tests cover: expansion of `J-29 to J-31` and `J-08/J-09`; a declared
journey missing from the matrix row (names persona and journey); a file-listed journey whose row omits the persona; a
declared journey missing from the persona file. Mutation demo: `docs/evidence/P01/T-0012-f6-demos.txt` (sha256
`6aa3c45b7499d2ec3085da6982847900e4117b1b81544102ec53fa004220edef`) removes Maya from the J-22 row → `ux-docs` FAIL
(`the matrix row for J-22 does not link persona maya ...`), restores it → PASS, SHA-256 unchanged
(`4B48E26C...0DFF545`).

**Checks (round 4):** `docs/evidence/P01/T-0012-verify-round4.txt`, sha256
`ef1e3b8979c4292d241742053c28da02b43ea688d006263caf6cefd97b6830dc`: `cargo fmt --all --check` exit 0;
`cargo clippy --workspace --all-targets -- -D warnings` exit 0; `cargo nextest run -p hdd-xtask --no-fail-fast` →
`Summary [3.345s] 140 tests run: 140 passed, 0 skipped`; `cargo xtask ux-docs` → `ux-docs: PASS`;
`cargo xtask claims-lint` → `claims-lint: PASS`; `cargo xtask verify --only rules spec-check tasks-check ux-docs
claims-lint` → `verify: 5 PASS, 0 FAIL, 0 UNVERIFIED`. Full gate remains Claude's; UNVERIFIED: none. No commit;
`STATUS.md` and `HANDOFF.md` untouched.

### 2026-10-19 · DeepSeek Harness · T-0013 round 1

Status: implemented; the review is `UNVERIFIED(capability_not_supplied)` by design (no network, no operator-supplied
screenshots or exports); local checks PASS; not committed. `STATUS.md`, `HANDOFF.md`, the matrix files and `INDEX.md` are
untouched.

**Files changed:**

- `docs/UX/PATTERNS.md` (new, 13,277 bytes): status line `UNVERIFIED(capability_not_supplied) - ...` with the reason;
  the twelve review questions; 14 topics (onboarding, DNS import, proxy toggles, WAF modes, event logs, rule builders,
  bans, analytics, API keys, team management, appeals, notifications, protection readiness, origin lockdown), each with
  `Source: first principles`, `Problem:`, `Common solutions:`, `Pitfalls:` and `Accessibility and clarity pitfalls:`;
  `Non-goals`; and a `Honesty-test review` with five yes/no answers and a reason each.
- `docs/UX/design-requirements.md` (new, 5,850 bytes): DR-01 to DR-20 in one table, each with a testable requirement, a
  rationale, a link to an existing `PATTERNS.md` topic anchor and existing targets (`S-035`, `S-040`, `S-042`, `S-044`,
  `S-045`, `S-046`, `S-047`, `S-054`, `S-055`, `S-059`, `S-060`, `S-065`, `S-066`, `S-067`, `S-068`, `S-069`, `S-070`,
  `S-076`, `S-079`, `S-080`, `S-081`, `S-083`, `S-098`, `S-138`, `S-140`, `S-145`, plus B11.8 components such as
  `Stepper`, `CloudToggle`, `PayloadViewer`, `LiveFeed`, `ReadinessRing` and `CountdownBadge`).
- `crates/hdd-xtask/src/ux_docs.rs`: `patterns_findings()` (status, 12-topic minimum, five labeled parts, `Source:`
  values, PASS only with a fetched source), `screen_ids()` (B12.1 table, ranges expanded), `component_names()` (B11.8),
  `design_requirement_findings()` (DR-01..20 once each, rationale, real PATTERNS anchor, real screen or component) and
  `self_copy_findings()` (a >12-word sentence repeated verbatim across UX documents); `check()` loads the two new
  documents and the spec tables; module doc updated.
- `crates/hdd-xtask/src/ux_docs/tests.rs`: 17 new tests and fixtures; `fake_spec` now carries the B11.8 and B12.1
  tables; `good_tree` writes valid `PATTERNS.md` and `design-requirements.md`.
- `crates/hdd-xtask/src/verify.rs`: the `ux-docs` step label now names the T-0013 checks (text only).
- `docs/UX/personas/sara.md` and `docs/UX/personas/omar.md`: one sentence each reworded ("measured results" → "evidence").
  The new self-copy guard found that sentence verbatim in two persona documents; rewording was the minimum fix and no
  test was weakened.

**Tests first (red):** `docs/evidence/P01/T-0013-red.txt`, 13,166 bytes, sha256
`580de9f437e730b16b3c9c8dd8cc0c871b09d970d835936f54ce4d8919fc48ce`: `Summary [0.928s] 17 tests run: 3 passed,
14 failed, 0 skipped`. The three passes are the positive fixtures, which pass trivially until the checks exist; every
negative case (topics, parts, sources, status, PASS rule, DR ids, targets, anchors, rationale, copy guard) failed.

**Commands and real result lines** (full output: `docs/evidence/P01/T-0013-verify.txt`, 21,569 bytes, sha256
`0b5df23c7d54c82b480a918d2d88b780fed44ff2ce69e86834787433f3043dd2`):

- `cargo fmt --all --check` → `(exit 0)`
- `cargo clippy --workspace --all-targets -- -D warnings` → `(exit 0)`
- `cargo nextest run -p hdd-xtask --no-fail-fast` → `Summary [3.478s] 157 tests run: 157 passed, 0 skipped`
- `cargo xtask ux-docs` → `ux-docs: PASS`
- `cargo xtask claims-lint` → `claims-lint: scanned 123 files with 34 phrases` / `claims-lint: PASS`
- `cargo xtask verify --only rules spec-check tasks-check ux-docs claims-lint` → `verify: 5 PASS, 0 FAIL, 0 UNVERIFIED`

**Mutation demonstrations:** `docs/evidence/P01/T-0013-negative-demos.txt`, 7,465 bytes, sha256
`c7fa55906509910e59e7a326b665b8872081b9514dad254e933ba4ebcc72cd76`. Twelve mutations of the shipped documents each
make `ux-docs` FAIL with the intended finding: fewer than twelve topics; a topic without `Pitfalls:`; `Source:` outside
the three values; a status line that is neither PASS nor UNVERIFIED; PASS while every topic is first principles; a
missing DR-07; DR-08 relabelled as DR-07 (repeat plus missing); no screen or component; `S-999`; a missing PATTERNS.md
anchor; an empty rationale; a long sentence copied from MEASURES.md. The restored documents give `ux-docs: PASS` and
their SHA-256 values equal the values before the demonstrations (`PATTERNS.md` `4A8B7BF5...E17E8C41E`,
`design-requirements.md` `947D3126...2740EA24C`).

**Acceptance:** A1 has 14 topics; A2 states a source per topic (all `first principles`); A3 holds because no network was
used and no third-party text was fetched or copied, and the copy guard is green; A4 has DR-01 to DR-20, each with an
existing screen or component; A5 states `UNVERIFIED(capability_not_supplied)` with the reason. Claims-lint PASS and the
B11.12 voice rules are followed.

**UNVERIFIED:** the review itself is `UNVERIFIED(capability_not_supplied)` (no network access, no operator-supplied
screenshots or exports; the task says its absence must not block the phase). No implemented check is UNVERIFIED. The
full gate `cargo xtask verify` remains Claude's.

**Notes for review:** the PATTERNS.md honesty-test table paraphrases the charter's five questions instead of quoting
them, because the copy guard rejects a verbatim sentence shared by two UX documents; `PATTERNS.md` has 14 topics rather
than the minimum 12; and the `ux-docs` verify label was updated in `verify.rs` so the step log names the new checks.

### 2026-10-19 · DeepSeek Harness · T-0013 round 2

**F-8 (component matched as a whole token).** Tests first: `docs/evidence/P01/T-0013-f8-red.txt`, 1,235 bytes, sha256
`c7fe4b01d59e2ad1dcb2393a31c0829be04e1dea1f103865ad16e9fa952c139c`: `Summary [0.021s] 1 test run: 0 passed, 1 failed`
(`DataTableOfDoom` was accepted before the fix). Implemented `names_component()`, which matches a component only as a
`\b`-delimited token: `DataTableOfDoom` and `Linked` fail, while `DataTable`, `` `DataTable` `` and `S-045, inventedword`
pass (a valid screen is enough). The shipped document still passes: `cargo xtask ux-docs` → `ux-docs: PASS`, so no
shipped row was passing only through a substring and no shipped row needed changing.

**F-9 (honesty-test review checked).** Tests first: `docs/evidence/P01/T-0013-f9-red.txt`, 4,093 bytes, sha256
`d24ccf57807160616ae8a260d1d1d59709ed0e298ff568a79ca5bfd49af2d40d`: `Summary [0.030s] 6 tests run: 1 passed,
5 failed` (the five-yes table passed; four rows, `Maybe`, an empty reason, one `No` and a missing section failed).
Implemented in `patterns_findings`: the `## Honesty-test review` section must exist; its table must have exactly five
rows; each `Answer` must be `Yes` or `No` (case-insensitive) with a non-empty `Reason`; any `No` is a finding. The
shipped table has five `Yes` rows with reasons, so `ux-docs` PASS.

**Mutation demonstrations:** `docs/evidence/P01/T-0013-negative-demos-round2.txt`, 1,556 bytes, sha256
`01581517a936a0fb46debbe11e73bcbda5225fa5979581f28aa6645a2eeaa4d2`. Four mutations of the shipped documents each make
`ux-docs` FAIL with the intended finding: `DataTableOfDoom` on DR-03 (`DR-03 names no screen ... or component`); an
honesty answer `Maybe`; an honesty answer `No`; four honesty rows. Restored documents give `ux-docs: PASS` and their
SHA-256 values equal the values before the demonstrations (`PATTERNS.md` `4A8B7BF5...E17E8C41E`,
`design-requirements.md` `947D3126...2740EA24C`).

**Checks (round 2):** `docs/evidence/P01/T-0013-verify-round2.txt`, 21,740 bytes, sha256
`b0472b6ea40702a43c66c9bde4896c3da34f2a26ae6eebaf90e9773f2efb7e3d`: `cargo fmt --all --check` exit 0;
`cargo clippy --workspace --all-targets -- -D warnings` exit 0; `cargo nextest run -p hdd-xtask --no-fail-fast` →
`Summary [3.997s] 164 tests run: 164 passed, 0 skipped`; `cargo xtask ux-docs` → `ux-docs: PASS`;
`cargo xtask claims-lint` → `claims-lint: scanned 127 files with 34 phrases` / `claims-lint: PASS`;
`cargo xtask verify --only rules spec-check tasks-check ux-docs claims-lint` → `verify: 5 PASS, 0 FAIL, 0 UNVERIFIED`.
Full gate remains Claude's; UNVERIFIED: none. No commit; `STATUS.md` and `HANDOFF.md` untouched.

### 2026-10-19 · DeepSeek Harness · T-0014 round 1

Status: implemented; local checks PASS; not committed. `STATUS.md`, `HANDOFF.md`, the matrix files and `INDEX.md` are
untouched. The `routes check` stub was not changed; `routes.toml` is checked by `ux-docs` until T-0073.

**Files changed:**

- `docs/UX/routes.toml` (new, 160 `[[route]]` entries): one row per route of the B2.2 URL map and per screen of B12.1.
  Every route has `pattern`, `screen`, `surface`, `permission`, `methods`, `rate_limit_class` and, where useful, `note`.
  The visitor-facing responses are marked with `screen = "data-plane"` and a note naming S-140 to S-148; the eight
  screens B2.2 serves at two paths have two rows each. The file was generated by a throwaway script kept outside the
  repository (scratch directory); every value was transcribed from B2.1, B2.2, B2.3, B4.2, B6 and B12.1.
- `docs/UX/IA.md` (new, 181 lines): `Surfaces and hosts`, `URL rules` (8 rules, each with a `Test:` line), `Identifier
  format` (12 prefixes, 26-character base32, regex and a worked example), `Deep linking`, `Redirects`, `Not found and
  forbidden`, `Titles and headings`, `Token routes` (the five token paths and their mitigations), `Permission rule`
  (the documented derivation) and `Assumptions` (shared screens, paths for screens absent from B2.2, the data-plane
  catch-all, the `/__hdd/` exception, rate classes where B6 is silent, and the permission shorthands).
- `crates/hdd-xtask/src/ux_docs.rs`: `RouteEntry`/`RoutesFile` (serde), `permission_ids()` (B4.2), `rate_limit_classes()`
  (B6.1), `token_route_patterns()` (IA `## Token routes`), `routes_findings()` (keys/values, whole-token permission and
  screen checks, screen coverage including the data-plane marking, all pattern rules, token rule, duplicate
  pattern/method set) and `ia_findings()` (ten sections, one `Test:` line per URL rule, identifier regex compiled with the
  `regex` crate and matched against its example). `check()` reads both documents, and the spec load now also parses B4.2
  and B6.1 through `spec::load_master`. Module doc updated.
- `crates/hdd-xtask/src/ux_docs/tests.rs`: fake B4.2 and B6.1 sections, fixture route table and IA document, and 15 new
  tests; `good_tree` writes valid `IA.md` and `routes.toml`.
- `crates/hdd-xtask/src/verify.rs`: the `ux-docs` step label now names the T-0014 checks (text only; the `routes check`
  stub is unchanged).

**Tests first (red):** `docs/evidence/P01/T-0014-red.txt`, 13,192 bytes, sha256
`b94d461ad77fe0d4a13785d12aa2a7281b58e09fcbca122bce6732ffef4cc036`: `Summary [1.250s] 15 tests run: 1 passed,
14 failed, 0 skipped`. The one pass is the positive fixture, which passes trivially while the checks are stubs; every
failure mode listed in the assignment has a failing test in the red run.

**Commands and real result lines** (full output: `docs/evidence/P01/T-0014-verify.txt`, 24,280 bytes, sha256
`a8786c12fa4e2ef7f6c855cc8181af31799f74cf0e66c0b4d14b7441932420e6`):

- `cargo fmt --all --check` → `(exit 0)`
- `cargo clippy --workspace --all-targets -- -D warnings` → `(exit 0)`
- `cargo nextest run -p hdd-xtask --no-fail-fast` → `Summary [4.565s] 179 tests run: 179 passed, 0 skipped`
- `cargo xtask ux-docs` → `ux-docs: PASS`
- `cargo xtask claims-lint` → `claims-lint: scanned 133 files with 34 phrases` / `claims-lint: PASS`
- `cargo xtask verify --only rules spec-check tasks-check ux-docs claims-lint` → `verify: 5 PASS, 0 FAIL, 0 UNVERIFIED`

**Mutation demonstrations:** `docs/evidence/P01/T-0014-negative-demos.txt`, 2,449 bytes, sha256
`02158751bdead24a816f9c3512e20a16dac46a63dca2df8eb9a4e060a7921285`. Seven mutations each make `ux-docs` FAIL with the
intended finding: a dropped screen (`S-041 appears 0 time(s)`), a duplicated screen (`S-041 appears 2 time(s)`), an
invented permission (`PERM-nope.read is not an id of the B4.2 catalog`), a trailing slash, an `{email}` placeholder, an
unlisted `{token}`, and an identifier example that does not match its regex. Restored files give `ux-docs: PASS` and
their SHA-256 values equal the originals (`routes.toml` `445840F0...2FFB8B65`, `IA.md` `26424CED...63CE7FF`).

**Acceptance:** A1 every B12.1 screen is covered (visitor screens marked data-plane); A2 every route names a B4.2
permission or `public`; A3 the eight URL rules each carry a `Test:` line; A4 the identifier regex and worked example
exist and match; A5 no route carries a token or an email outside the listed token routes. Claims-lint PASS and the
B11.12 voice rules are followed.

**Notes for review (assumptions that need a reviewer's eye):** A1 says "exactly once", but B2.2 itself serves eight
screens at two paths each (S-046, S-059, S-065, S-067, S-070, S-074, S-134, S-136); the check therefore allows exactly
two rows for those eight screens and rejects a duplicate of any other screen (demonstrated). The visitor-facing screens
S-140 to S-148 have no path in B2.2, so the check requires each to be named by a data-plane note on the catch-all or a
specific `/__hdd/` route. S-015/16/17, S-137/138/139 and the component gallery have no B2.2 path; `IA.md` records the
paths chosen for them under Assumptions. Where B6 is silent the rate class is conservative (public, auth, read, write,
export or stream as described in Assumptions), and the permission shorthands (`analytics`, `search`) are listed there.

**UNVERIFIED:** none of the implemented checks is UNVERIFIED. The full gate `cargo xtask verify` remains Claude's, and
the route table is not yet compared with a real router: `xtask routes check` stays the stub until T-0073, as the
assignment says.

### 2026-10-19 · DeepSeek Harness · T-0014 round 2

Status: F-10 fixed; local checks PASS; not committed. `STATUS.md`, `HANDOFF.md`, the matrix files and `INDEX.md` are
untouched, and the `routes check` stub is unchanged.

**Rules added to `routes_findings`** (tests first, see the red evidence):

- F-10a: `permission = "public"` fails on the `admin` and `api` surfaces, and on the `app` surface unless the class is
  `auth` or `public`.
- F-10b: a `PERM-platform.*` permission fails outside the `admin` surface; an `admin` route needs a `PERM-platform.*`
  permission, or `public` with class `auth`.
- F-10c: a route with a non-GET/HEAD method needs class `write`, `auth` or `export`, and a GET/HEAD-only route must not
  have class `write`. `rate_class_exceptions()` parses the optional `## Rate-class exceptions` table of `IA.md`
  (pattern, method, reason); `ia_findings()` reports a row with a pattern not starting `/`, an unknown method or an
  empty reason, and `routes_findings()` reports an exception that does not match a real route and method. `check()`
  parses the section and passes it in. The shipped table needs no exception after the data fixes below, so `IA.md` has
  no exception row; the round trip is exercised by the tests (`f10_rate_class_exceptions_must_match_a_real_route`).

**Tests first (red):** `docs/evidence/P01/T-0014-f10-red.txt`, 4,857 bytes, sha256
`2a14e04f933f26559f1dedf1e51c88e9e43a3f41e283335abfde3ead329f0323`: `Summary [0.029s] 5 tests run: 0 passed,
5 failed, 0 skipped`. The five tests are the failing and passing fixture per rule (a, b, c), the exception round trip
and the bad exception row.

**Data rows changed in `docs/UX/routes.toml`** (161 rows now; the catch-all split adds one), each justified by the
spec:

1. `/openapi.json`: surface `api` → `public`. B6.10 line 1592 lists `GET /openapi.json` as public, and F-10a forbids a
   public permission on the api surface; the document is public, and the note records that the api host serves it too.
2. `/app`: class `read` → `auth`. B2.2 line 883 is the post-login redirect to the last organisation overview, so it is
   an authentication-surface route; F-10a allows `public` on the app surface only with class `auth` or `public`. The
   class choice is recorded in the IA `Assumptions` section.
3. `/__hdd/challenge/verify`: class `public` → `auth`. B6.10 line 1594 is the POST proof-of-work verification, an
   authentication step; F-10c.
4. `/__hdd/appeal` POST row (S-146): class `public` → `write`. B6.10 line 1595 gives `POST /__hdd/appeal` as the appeal
   submission, which creates a record; F-10c.
5. `/__hdd/csp-report`: class `public` → `write`. B6.10 line 1596 is the POST CSP intake, which writes an aggregate;
   F-10c.
6. `/{path}` catch-all: split into a GET/HEAD row with class `public` and a POST/PUT/PATCH/DELETE row with class
   `write`. B2.2 lines 943 to 950 describe the visitor responses for any blocked, rate-limited, origin-down,
   unknown-host, under-attack or suspended request, with no method limitation; F-10c.
7. Every GET/HEAD-only row that had class `write` now has class `read` (F-10c: B6.1 line 1415 defines the classes and
   a read route must not use `write`): `/app/o/{org}/domains/new` (S-042), `/dns/new` and `/dns/{rec}` (S-046),
   `/dns/import` (S-047), `/security/waf` (S-055), `/security/emergency` (S-093), `/settings/decommission` (S-094),
   `/origin/lockdown` (S-098), `/security/access-gate` (S-131), `/security/api` (S-132), `/security/flows` (S-133),
   `/app/o/{org}/settings` (S-086), `/reports/new` (S-074), and on the admin surface `/admin/jail`, `/admin/rules`,
   `/admin/intel`, `/admin/allowlists`, `/admin/abuse`, `/admin/signup-policy`, `/admin/plans`, `/admin/impersonation`,
   `/admin/settings`, `/admin/email-templates`, `/admin/flags`, `/admin/emergency`, `/admin/releases`, `/admin/backups`,
   `/admin/virtual-patches`, `/admin/ddos`, `/admin/firewall`, `/admin/announcements` (B6.11 platform table). The IA
   `Assumptions` section now states that a route's class follows its own methods.

**Mutation demonstrations:** `docs/evidence/P01/T-0014-negative-demos-round2.txt`, 1,787 bytes, sha256
`25a13b9e0c8ababa3b1ee35a5f9c3bddd62da87d1fd94d221b92215daff56a3b`. Four mutations each make `ux-docs` FAIL with the
intended finding: F-10a (`/admin` permission public), F-10b (`/admin` moved to the public surface with a platform
permission), F-10c (`DELETE` added to `/admin` with class read) and F-10c in the other direction (`/features` GET-only
with class write). Restored files give `ux-docs: PASS` and their SHA-256 values equal the originals (`routes.toml`
`C4BF455E...33CF7FA`, `IA.md` `F1385B75...60E6AA6F`).

**Checks (round 2):** `docs/evidence/P01/T-0014-verify-round2.txt`, 24,018 bytes, sha256
`9706b1b09bfc76867932a4aab800673ea0600fabdf5cd52ecc8700ea2687ea00`: `cargo fmt --all --check` exit 0;
`cargo clippy --workspace --all-targets -- -D warnings` exit 0; `cargo nextest run -p hdd-xtask --no-fail-fast` →
`Summary [4.295s] 184 tests run: 184 passed, 0 skipped`; `cargo xtask ux-docs` → `ux-docs: PASS`;
`cargo xtask claims-lint` → `claims-lint: scanned 136 files with 34 phrases` / `claims-lint: PASS`;
`cargo xtask verify --only rules spec-check tasks-check ux-docs claims-lint` → `verify: 5 PASS, 0 FAIL, 0 UNVERIFIED`.
The `ux-docs` step label in `verify.rs` now names the cross-key consistency checks.

**UNVERIFIED:** none. The full gate `cargo xtask verify` remains Claude's; the `routes check` stub is still T-0073's.

### 2026-10-19 · DeepSeek Harness · T-0015 round 1

Status: implemented; local checks PASS; not committed. `STATUS.md`, `HANDOFF.md`, the matrix files and `INDEX.md` are
untouched. The `routes check` stub is unchanged.

**Files changed:**

- `docs/UX/NAVIGATION.md` (new, 234 lines): ASCII wireframes (four fenced blocks) plus the nine required sections.
  `Navigation elements` is one table with the 13 org-sidebar items (`Sidebar · …`), the 9 domain tabs (`Tab · …`) and
  the 7 top-bar controls (`Top bar · …`), each with a keyboard path, an ARIA role and, for sidebar and tabs, a route
  whose permission repeats `routes.toml`; a `Global · Skip link` row records the B11.11 skip link. `Org and domain
  switchers` covers type-ahead, recents, keyboard and empty states; `Breadcrumbs` caps the depth at four and marks
  `aria-current="page"`; `Command palette and shortcuts` gives scope, ranking, the shortcut map (all nine B2.3
  shortcuts) and a 14-row `Reserved by browsers and assistive technology` table, and states how single-letter
  shortcuts are disabled while a field has focus and how a user turns them off; `Restricted items` distinguishes
  `permission-hidden` and `plan-limited`; `Admin surface` specifies the persistent "Platform admin" band without
  colour alone; `Focus management` has `Full page loads` and `Partial swaps`; `Mobile` has `360 px`, `480 px` and
  `768 px`; `Review checklist` has yes/no questions and names T-0138 and T-0151.
- `crates/hdd-xtask/src/ux_docs.rs`: `shortcut_list()` parses B2.3 from the master specification (the keyboard-shortcut
  line's code spans plus the `Ctrl/Cmd+K` control) and normalises keys; `tables_in()` and `subsection_body()` support
  several tables per section and level-3 subsections; `navigation_findings()` checks the nine sections, the elements
  table (six columns, non-empty `Keyboard`/`ARIA role`, whole-name matching of the three element groups, every route in
  `routes.toml` with an equal permission), the restricted states, the shortcut map (B2.3 coverage, duplicates, reserved
  conflicts, at least ten reserved rows), the focus and mobile subsections, the documented no-hover rule and the three
  wireframes. `check()` reads and cross-checks `NAVIGATION.md` and passes the route map and the B2.3 shortcuts; the
  spec load now also parses B2.3. Module doc and the `ux-docs` step label in `verify.rs` name T-0015.
- `crates/hdd-xtask/src/ux_docs/tests.rs`: a fake B2.3 section and three extra B12.1 rows in `fake_spec`, a valid
  `navigation_fixture()` written into `good_tree`, a fixture route-permission map, and 12 new tests: one passing
  fixture plus a failing case for each rule (missing section, empty keyboard and ARIA cells, unknown route, differing
  permission, missing sidebar item, tab and control, missing B2.3 shortcut, reserved-key conflict, duplicate shortcut,
  fewer than ten reserved rows, missing restricted state, missing focus subsection, missing mobile width, hover-only
  row, missing wireframes) and the missing-document tree test.

**Tests first (red):** `docs/evidence/P01/T-0015-red.txt`, 10,734 bytes, sha256
`0e3448153576257b967371842c5186f02e0f9e0ff940d0c498f3fe6630476758`: `Summary [1.300s] 12 tests run: 1 passed,
11 failed, 184 skipped`. The one pass is the positive fixture, which passes trivially while the new check is a stub;
every failure mode listed in the assignment has a failing test in the red run.

**Commands and real result lines** (full output: `docs/evidence/P01/T-0015-verify.txt`, 25,575 bytes, sha256
`b420f3dfe14725ab30e552248037ba8bcaf44d481d87140428ea5698681bc48b`):

- `cargo fmt --all --check` → `(exit 0)`
- `cargo clippy --workspace --all-targets -- -D warnings` → `(exit 0)`
- `cargo nextest run -p hdd-xtask --no-fail-fast` → `Summary [4.372s] 196 tests run: 196 passed, 0 skipped`
- `cargo xtask ux-docs` → `ux-docs: PASS`
- `cargo xtask claims-lint` → `claims-lint: scanned 141 files with 34 phrases` / `claims-lint: PASS`
- `cargo xtask verify --only rules spec-check tasks-check ux-docs claims-lint` → `verify: 5 PASS, 0 FAIL, 0 UNVERIFIED`

**Mutation demonstrations:** `docs/evidence/P01/T-0015-negative-demos.txt`, 2,076 bytes, sha256
`0ee222ae7c6adbbecf0df19075f452315a3238218c06fab14651da4d246036a6`. Seven mutations each make `ux-docs` FAIL with
the intended finding: a route not in `routes.toml`; a permission that differs from the route; `Ctrl/Cmd+R` used as a
shortcut (reserved conflict and missing `?`); a duplicated `g o` (and missing `g d`); a renamed 480 px subsection; an
empty ARIA cell; and a removed sidebar item. Restored file gives `ux-docs: PASS` and its SHA-256 equals the original
(`NAVIGATION.md` `D711450F...35D4EC43`).

**Acceptance:** A1 every element has a keyboard path and an ARIA role, and every route cell is tied to `routes.toml`;
A2 focus management is specified for full loads and partial swaps; A3 `permission-hidden` and `plan-limited` are
distinguished; A4 the 360, 480 and 768 px layouts are specified; A5 the shortcut map has no conflict with the
reserved list and covers B2.3. `claims-lint` and the B11.12 voice rules pass.

**UNVERIFIED:** none of the implemented checks is UNVERIFIED. The full gate `cargo xtask verify` remains Claude's; the
navigation is a document contract, so the browser-side behaviour is implemented and verified later by T-0138 and
T-0151, as the task says.

### 2026-10-19 · DeepSeek Harness · T-0015 round 2

Status: F-11 fixed; local checks PASS; not committed. `STATUS.md`, `HANDOFF.md`, the matrix files and `INDEX.md` are
untouched.

**Document changes (`docs/UX/NAVIGATION.md`, 250 lines):**

- New section `Documented conflicts` with the table `Keys | Owner of the default | Effect | Mitigation`. It records
  the three real conflicts the specification forces: `Ctrl/Cmd+K` (browser address/search bar), `/` (browser quick
  find), and the `g` chords plus `c` and `?` (screen-reader browse-mode quick navigation), grouped in one row that
  names every key. Each mitigation names a control that exists in the elements table (`Search / command palette`,
  `Sidebar · Domains`), gives a way to reach the same function without the key, and states that shortcuts can be turned
  off. The section is now one of the required sections, so its absence fails.
- `Command palette and shortcuts` now says shortcuts are conveniences and never the only path (WCAG 2.1.4 and 2.1.1).
- The A5 claim is re-worded in the opening paragraph and in the review checklist: the reserved table lists keys the
  product never binds, and `Documented conflicts` lists the keys it does bind despite a default, with mitigations.

**Check changes (`ux_docs.rs`, `tests.rs`):** `NAV_SECTIONS` now has ten sections; `navigation_findings()` collects the
element names from the elements table (plus `search control` and `command palette`), parses the conflicts table with the
new `mentions_phrase()` whole-word matcher, and checks: every map key that is `Ctrl/Cmd+K`, `/`, `?` or a single letter
has a row (whole-key match); every row has a non-empty owner, effect and mitigation; a mitigation names a real
navigation element and says shortcuts can be turned off; a row whose keys match no map key (exact, or a single-letter
prefix such as `g`) is stale; and the `Command palette and shortcuts` section carries the only-path sentence. The
fixture gained the section and the sentence; six new tests cover the failing case for each rule (missing `/` row, empty
mitigation, mitigation naming a non-existent element, missing turn-off wording, stale row, missing only-path sentence)
and the passing fixture. The module doc and the `ux-docs` step label name the F-11 checks.

**Tests first (red):** `docs/evidence/P01/T-0015-f11-red.txt`, 5,226 bytes, sha256
`abdb1bcbde6f75a0502ea096abacafdecf4d18cfe782fbad11e1213fe0f20546`: `Summary [0.041s] 6 tests run: 0 passed,
6 failed, 196 skipped`, before the checks existed.

**Commands and real result lines** (full output: `docs/evidence/P01/T-0015-verify-round2.txt`, 26,187 bytes, sha256
`8add84641b6b9b0ff09b49cfb128c9f066fd8aacbf6fc2172e5940a8334c1aa0`):

- `cargo fmt --all --check` → `(exit 0)`
- `cargo clippy --workspace --all-targets -- -D warnings` → `(exit 0)`
- `cargo nextest run -p hdd-xtask --no-fail-fast` → `Summary [4.375s] 202 tests run: 202 passed, 0 skipped`
- `cargo xtask ux-docs` → `ux-docs: PASS`
- `cargo xtask claims-lint` → `claims-lint: scanned 144 files with 34 phrases` / `claims-lint: PASS`
- `cargo xtask verify --only rules spec-check tasks-check ux-docs claims-lint` → `verify: 5 PASS, 0 FAIL, 0 UNVERIFIED`

**Mutation demonstrations:** `docs/evidence/P01/T-0015-negative-demos-round2.txt`, 1,392 bytes, sha256
`c91c230b92263be17c180764628a47891d4031c22de9f460d3c1dfd0a8673971`. Each of the four mutations makes `ux-docs` FAIL
with the intended F-11 finding: the `/` row removed (`has ... no row in Documented conflicts`); an empty mitigation
cell; a mitigation naming a non-existent `moon button` element; and a stale `Ctrl/Cmd+Q` row. Restored file gives
`ux-docs: PASS` and its SHA-256 equals the original (`NAVIGATION.md` `65D49F60...04DD3D`).

**Acceptance:** A5 is now honest: the document states which fixed shortcuts collide with a browser or screen-reader
default, guarantees each has a non-shortcut path that exists in the navigation table, and states that shortcuts can be
turned off; A1 to A4 are unchanged and still pass. `claims-lint` and the B11.12 voice rules pass.

**UNVERIFIED:** none. The full gate `cargo xtask verify` remains Claude's; the behaviour is implemented and verified
later by T-0138 and T-0151.

### 2026-10-19 · DeepSeek Harness · T-0016 round 1

Status: first delivery, J-01 to J-06 complete; local checks PASS; not committed. The assignment allows splitting the
twelve journeys, so **J-07 to J-12 are not delivered in this pass** and the check currently iterates
`JOURNEYS_IN_SCOPE = [J-01 .. J-06]`; extending that constant and adding the six files is the whole change for the
second delivery (the check code is already general: it reads the titles, personas, spec mentions and AC ids per id from
the master specification, and the 12-step threshold for J-08/J-09 is already implemented). `STATUS.md`, `HANDOFF.md`,
the matrix files and `INDEX.md` are untouched. The `routes check` stub is unchanged.

**Documents (new):**

- `docs/UX/journeys/J-01.md` to `J-06.md`: each has the exact spec B3 title, the persona links of the
  persona-journey matrix row, the trigger, and the required sections. Steps tables have eight rows each (J-01 to J-06;
  the J-08/J-09 twelve-row rule is implemented but not exercised here), every row names an existing B12.1 screen,
  an existing B7 `ERR-` code, one of the three emotional states and a semantic copy key; the security tables cite
  existing C5 `ATK-` ids; the accessibility tables have one row for every step that changes the screen; instrumentation
  cites existing B8 `AUD-` events; `Success and checks` carries every `AC-nn` the spec text names; `Missing screens` is
  `None` for all six. Where B8 genuinely has no event (MFA enrolment, invitation acceptance) the document states the
  gap instead of inventing an id.
- `docs/UX/spec-patches.md`: one proposed row, `S-149` (the highest existing id is S-148), for the domain-settings page
  that B12.1 lacks, needed by J-08, J-09, J-14 and J-15, status `proposed`.

**Checks (`ux_docs.rs`, `tests.rs`):** `journey_headings()`, `error_catalog()`, `audit_ids()`, `matrix_personas()`,
`proposed_screens()`, `missing_screens()` and `tokens_in()` read the master specification and the UX documents;
`journey_findings()` enforces title, personas, sections, the nine-column steps table, minimum row count, non-empty
cells, screen syntax and membership (or a proposed id), emotional states, copy-key shape, `ERR-` existence and the
5xx-versus-`system` rule, duplicate steps, trust rows, C5-backed security rows, accessibility coverage for every
changed screen, B8 audit ids, spec-mentioned screens and AC ids, and `Missing screens` consistency;
`patches_findings()` enforces the proposals-only rule, journey ids, `proposed` status, the reason, and that a proposal
needed by a delivered journey is actually cited in that journey's `Missing screens`. `check()` reads the six files and
`spec-patches.md`, and the spec load is repeated for the journey registries. `good_tree` and the fake spec gained the
six fixtures, the B7/B8/J sections and the extra B12.1 rows. The module doc and the `ux-docs` step label name T-0016.

**Tests first (red):** `docs/evidence/P01/T-0016-red.txt`, 12,004 bytes, sha256
`4ebba79f5d3b74f96c1c58fabf16b2d722f04c575bf62b3723400a731fd1fbb2`: `Summary [1.620s] 13 tests run: 1 passed,
12 failed, 202 skipped`. The one pass is the positive journey fixture, which passes trivially while the check is a
stub; each failure mode has a failing test in the red run.

**Commands and real result lines** (full output: `docs/evidence/P01/T-0016-verify.txt`, 27,707 bytes, sha256
`dc0bdf491d116739974a64e2f4575f7f365234486efb3c0833c97d4be36e14ab`):

- `cargo fmt --all --check` → `(exit 0)`
- `cargo clippy --workspace --all-targets -- -D warnings` → `(exit 0)`
- `cargo nextest run -p hdd-xtask --no-fail-fast` → `Summary [7.007s] 215 tests run: 215 passed, 0 skipped`
- `cargo xtask ux-docs` → `ux-docs: PASS`
- `cargo xtask claims-lint` → `claims-lint: scanned 155 files with 34 phrases` / `claims-lint: PASS`
- `cargo xtask verify --only rules spec-check tasks-check ux-docs claims-lint` → `verify: 5 PASS, 0 FAIL, 0 UNVERIFIED`

**Mutation demonstrations:** `docs/evidence/P01/T-0016-negative-demos.txt`, 3,152 bytes, sha256
`a800d2081de51e5aa83e8506d46820d7543f6ca97d711bd9bac639dcf92874d2`. Eight mutations each make `ux-docs` FAIL with
the intended finding: a spec-mentioned screen removed from J-02; a bad `ERR-NOPE-999`; a bad `ATK-999`; a seven-row
steps table; a changed title; a removed persona link; a step screen `S-150` missing from `spec-patches.md`; and a patch
for the existing `S-041`. All seven shipped files were restored and their SHA-256 values equal the originals.

**Acceptance (delivered part):** A1 eight steps and a failure path per step for J-01 to J-06; A2 every step names an
existing screen or the `email` screen; A3 every error path cites an existing B7 code (4xx for user paths, 5xx only with
`system`); A4 trust, security and accessibility tables exist and cite real C5 ids; A5 no screen is proposed unless it
is missing from B12.1 and needed by a journey. `claims-lint` and the B11.12 voice rules pass.

**UNVERIFIED:** none for the delivered six journeys. J-07 to J-12 are deliberately not delivered in this pass (the
assignment permits the split); their documents, and the extension of `JOURNEYS_IN_SCOPE`, remain for the second
delivery. The full gate `cargo xtask verify` remains Claude's.

### 2026-10-19 · DeepSeek Harness · T-0016 round 2

Status: **F-12 fixed completely for J-01 to J-06; J-07 to J-12 are not delivered in this pass.** The assignment says
that if both cannot be finished, F-12 comes first and Claude assigns the rest; that is the case here. Local checks PASS;
not committed; `STATUS.md`, `HANDOFF.md`, the matrix files and `INDEX.md` untouched.

**F-12a: every row re-read and rewritten.** All 48 `Error path` cells of J-01 to J-06 now start with a code that is a
real failure of that step and continues with a sentence a reader can act on. Six rows needed a new code; the other 42
kept their code with a sentence written for the step. Every change (journey, step, old code → new code, B7 line of the
new code):

- J-01: 1 SYS-001 (1737); 2 SYS-003 (1739); 3–6 PERM-002 (1673); 7 SYS-004 (1740); **8 RATE-001 → SYS-004 (1740)**
  (the step reads the form; a paused-signup notice fits, a rate limit did not).
- J-02: 1 AUTH-010 (1663); 2–3 AUTH-004 (1657); 4–5 AUTH-009 (1662); **6 AUTH-002 → AUTH-007 (1660)** (a confirmation
  continues to a login page, no password is typed on that step); 7 SYS-001 (1737); **8 SYS-001 → ORG-001 (1683)**
  (the step finishes the organisation slug field).
- J-03: 1 AUTH-006 (1659); 2 AUTH-003 (1656); 3 AUTH-004 (1657); **4 VAL-001 → SYS-001 (1737)** (a page fault while
  the recovery codes are generated, not an invalid request body); 5 SYS-001 (1737); 6 AUTH-017 (1670); **7 AUTH-018 →
  SYS-001 (1737)** (the security summary is read; no passkey is verified there); 8 SYS-001 (1737).
- J-04: 1 AUTH-002 (1655); 2 AUTH-004 (1657); 3 AUTH-003 (1656); 4 AUTH-004 (1657); 5 AUTH-018 (1671); 6 AUTH-007
  (1660); 7 AUTH-004 (1657); 8 SYS-001 (1737). Step 7 keeps AUTH-004 deliberately: the B7 note ("does not reveal lock
  cause") is the generic wording the lockout page needs, so the locked-page code fits after re-reading; the sentence now
  says so.
- J-05: 1–2 AUTH-004 (1657); 3 AUTH-009 (1662); 4 AUTH-010 (1663); 5 AUTH-009 (1662); 6 SYS-001 (1737); 7 AUTH-002
  (1655); 8 SYS-001 (1737).
- J-06: 1–2 AUTH-009 (1662); 3 AUTH-010 (1663); **4 ORG-003 → VAL-001 (1649)** (submitting the new-account form is a
  field-validation step, not the "pending invitation exists" state; the reviewer's reading was right); 5 AUTH-002
  (1655); 6 AUTH-007 (1660); 7 ORG-005 (1687); 8 SYS-001 (1737).

Every sentence is at least six words and states what the user sees; a 5xx row names `system`, so the existing
5xx-versus-user-path rule still holds.

**F-12b: format and heuristic checks (tests first).** The cell format is now
`ERR-XXX-nnn: <what the user sees and why the code fits>`. New parsers `error_descriptions()` (B7 title plus note) and
`screen_names()` (B12.1 name), and a `content_words()` helper (tokens of five or more letters without a short stop
list), feed three rules: a sentence of at least six words must follow the code; it must share a content word with the
cited code's B7 title or note; and it must share a content word with that step's `User action`, `System response` or
screen name. The module doc now states that this is a heuristic catching blatant mismatches and that the reviewer's
reading covers the rest. Red: `docs/evidence/P01/T-0016-f12-red.txt`, 4,215 bytes, sha256
`df81b66a5c0a71079cca7dc25aacbaefbb90993211ec7f0d53c2be45e695ab75`, `Summary [0.123s] 5 tests run: 1 passed,
4 failed` (the passing fixture passes trivially before the checks exist). Fixtures: `ERR-AUTH-002` on the confirmation
step fails the step-fit rule; a short sentence fails; a sentence unrelated to the B7 text fails; a fitting
`ERR-AUTH-002` password sentence passes.

**F-12d: mutation demonstrations:** `docs/evidence/P01/T-0016-negative-demos-round2.txt`, 1,582 bytes, sha256
`27f9ef9aa06a70a8b10cc977748547d85e9c4714f27939911d197f9f3d2800b8`. Three mutations each make `ux-docs` FAIL:
`ERR-AUTH-002` put back on J-02 step 6 (no B7 word matches); a four-word sentence; a sentence unrelated to its code.
The three files were restored and their SHA-256 values equal the originals.

**Checks (round 2):** commands and real result lines (full output: `docs/evidence/P01/T-0016-verify-round2.txt`,
28,155 bytes, sha256 `b9944791555f2cc6c79da84411786c5701cf4d666a1888d8fbd53e96726fbef6`):

- `cargo fmt --all --check` → `(exit 0)`
- `cargo clippy --workspace --all-targets -- -D warnings` → `(exit 0)`
- `cargo nextest run -p hdd-xtask --no-fail-fast` → `Summary [7.185s] 220 tests run: 220 passed, 0 skipped`
- `cargo xtask ux-docs` → `ux-docs: PASS`
- `cargo xtask claims-lint` → `claims-lint: scanned 158 files with 34 phrases` / `claims-lint: PASS`
- `cargo xtask verify --only rules spec-check tasks-check ux-docs claims-lint` → `verify: 5 PASS, 0 FAIL, 0 UNVERIFIED`

**UNVERIFIED:** none for F-12. J-07 to J-12 remain undelivered in this pass (the assignment's fallback allows this);
the check still iterates `JOURNEYS_IN_SCOPE = [J-01 .. J-06]`, and the general journey checks are ready for the second
delivery. The full gate `cargo xtask verify` remains Claude's.

### 2026-10-19 · DeepSeek Harness · T-0016 round 3

Status: second delivery complete — **J-07 to J-12 written**, `JOURNEYS_IN_SCOPE` extended to J-01..J-12, J-04 step 6
reworded, and the new `Cutover safety` rule implemented tests-first. Local checks PASS; not committed; `STATUS.md`,
`HANDOFF.md`, the matrix files and `INDEX.md` untouched.

**Documents:**

- `docs/UX/journeys/J-07.md` to `J-12.md` (new). Every file has the exact B3 title, the persona links of its matrix
  row, a trigger and the seven required sections. J-07 has eight steps; J-10, J-11 and J-12 have eight each; **J-08 and
  J-09 have twelve each** and both name `Time to first domain in monitor mode` and `Completion rate of the add-domain
  wizard` under `Instrumentation`. Every error path follows F-12 (`ERR-...: <sentence>`); the sentences were written
  for their step and re-read after writing, and the step-fit heuristic passes. Screens used: S-035/S-040 (J-07),
  S-041/S-042/S-099/S-043 (J-08), S-041/S-042/S-099/S-043 (J-09), S-042/S-099/S-043 (J-10), S-042/S-099/S-043 (J-11),
  S-052/S-043 (J-12). Spec-mentioned ids: J-07 S-035, S-040; J-08 S-042; J-09, J-10 and J-11 name no screen; J-12 none;
  every mentioned `AC-` id is in `Success and checks` (AC-37 for J-07/J-09/J-10/J-11, AC-37/AC-02/AC-03 for J-08,
  AC-17/AC-37 for J-12).
- `docs/UX/journeys/J-04.md`: step 6 no longer says a user is "asked for the device cookie"; the step is now "Trusts
  the remembered device", the response describes the trusted-device check and the second factor, and the error sentence
  says the check fails, the session must be renewed and the second factor is asked for again.
- `docs/UX/spec-patches.md` is unchanged: S-149 is already needed by J-08 and J-09 (and J-14/J-15), and both delivered
  journeys now list it under `Missing screens`, so the citation rule passes. No journey needed a missing error code:
  B8 gaps (no domain, origin or ownership audit events) are stated in the instrumentation sections, not invented as
  ids, and the real audit ids cited are `AUD-dns.parity_acknowledged`, `AUD-waf.mode_changed` and `AUD-auth.signup`.
- `JOURNEYS_IN_SCOPE` is now the twelve ids J-01..J-12.

**Cutover safety (new rule, tests first):** J-08 and J-09 each carry a `Cutover safety` table
`Step | What could break the live site | Guard | Undo`, eight rows each, one for every step whose action or response
mentions DNS, nameservers, delegation, proxy, routing, a zone or a CNAME. The check requires the section, the exact
header, at least four non-empty rows, a real step per row, a spec control named in every `Guard` and `Undo` (preview,
parity, rollback, undo, the R-19 return path, TTL, dry-run and similar), and a row for every DNS/routing step.
Red: `docs/evidence/P01/T-0016-cutover-red.txt`, 5,178 bytes, sha256
`474bb6f41b937f9266d175dc91d538111d77e36c5b3d6eb099dc7b516d9fc28f`: `Summary [0.205s] 4 tests run: 0 passed,
4 failed, 220 skipped`; the tests cover a missing section, fewer than four rows, a guard/undo without a spec control,
and a missing row for a DNS-changing step. The fixture generator now writes twelve journeys, J-08/J-09 with their
cutover rows and both measures, and the fake spec gained the J-07..J-12 headings and the `AUD-domain.*` events.
The module doc and the `ux-docs` label name the cutover rule.

**Commands and real result lines** (full output: `docs/evidence/P01/T-0016-verify-round3.txt`, 28,740 bytes, sha256
`36e0afdefaf9d41ff042766c4eb431b67b949522fa744d8d0a15bd26b6e2c43a`):

- `cargo fmt --all --check` → `(exit 0)`
- `cargo clippy --workspace --all-targets -- -D warnings` → `(exit 0)`
- `cargo nextest run -p hdd-xtask --no-fail-fast` → `Summary [7.365s] 224 tests run: 224 passed, 0 skipped`
- `cargo xtask ux-docs` → `ux-docs: PASS`
- `cargo xtask claims-lint` → `claims-lint: scanned 167 files with 34 phrases` / `claims-lint: PASS`
- `cargo xtask verify --only rules spec-check tasks-check ux-docs claims-lint` → `verify: 5 PASS, 0 FAIL, 0 UNVERIFIED`

**Mutation demonstrations:** `docs/evidence/P01/T-0016-negative-demos-round3.txt`, 3,682 bytes, sha256
`b16ce8e6e9ac80c33144a5356c880c519e9a85eedce14909fff0e01ce50672ea`. Ten mutations each make `ux-docs` FAIL: a
cutover row removed for a DNS-changing step; an empty guard; the section removed; a bad `ERR-NOPE-999`; a bad
`ATK-999`; a changed title; a removed persona link; an eleven-step J-08 table; a screen missing from `spec-patches.md`;
and an error sentence unrelated to its code. All five touched files were restored and their SHA-256 values equal the
originals.

**Acceptance:** A1 at least eight steps and a failure path per step (twelve for J-08/J-09); A2 every step names a screen
or the `email` screen; A3 every error path cites a real B7 code with a step-fitting sentence; A4 trust, security,
accessibility and cutover-safety tables exist and cite real C5 ids and spec controls; A5 proposed screens are absent from
B12.1 and needed by a delivered journey. `claims-lint` and the B11.12 voice rules pass.

**UNVERIFIED:** none. The full gate `cargo xtask verify` remains Claude's. The B8 audit-event gaps recorded in the
instrumentation sections (no domain, origin or ownership events) are a spec gap for the reviewer, not an invented id.


## Review findings (closed tasks)


### 2026-10-19 · Claude · review of T-0012 (round 1)

Independently re-run by Claude: `cargo fmt --all --check` OK; `cargo clippy --workspace --all-targets -- -D warnings` clean;
`cargo nextest run -p hdd-xtask` 127 passed; `cargo xtask ux-docs` PASS. The personas, the matrix and the checks read well; the
`AC-`, `S-`, `J-` ids referenced exist in the specification. Two findings:

1. **F-1 (Claude's own slip, must be repaired): `docs/UX/personas/adversary.md` has lost its ATK ids.** While repeating the
   mutation check, Claude ran a global replace of every `ATK-nnn` with `ATK-998` in that untracked file and kept no backup.
   There are 16 occurrences (the abuse-story table rows 1 to 14 and two prose mentions, lines 32 to 45, 62 and 70). Restore
   the original mapping: each abuse story must map to the C5 coverage-matrix row it really belongs to (use the C5 table in
   `docs/SPEC.md` and your own earlier version of the file), with at least ten distinct ids, every one present in the registry.
   Do not invent ids. Re-run `cargo xtask ux-docs` and `cargo xtask claims-lint`, and re-run mutation 7 (only 7 distinct ids)
   and mutation 8 (`ATK-999`) of your negative demos to show they still fail.
2. **F-2: stale label.** The `ux-docs` step text in `crates/hdd-xtask/src/verify.rs` (function `step_ux_docs`) still describes
   only T-0011. Update it to name the persona, matrix and registry checks of T-0012. Text only; keep `fmt` and `clippy` clean.

3. **F-3: mojibake.** `docs/UX/personas/adversary.md` (3 places) and `docs/UX/personas/vi.md` (1 place) contain the byte
   sequence for the characters a-circumflex, euro sign (the result of reading a UTF-8 em dash as cp1252) instead of an em
   dash. Replace each with a plain comma, colon or " - ", search every file you created for `â€` and `Ã`, and add a small test
   to `ux_docs` that fails when a persona or matrix document contains such a sequence (write the test first, show it fails on
   a file that contains it, then fix the files). Write files as UTF-8 without a byte-order mark.

Reply under Reports, then stop. Do not touch anything else.

### 2026-10-19 · Claude · review of T-0012 (round 2: logic review of `ux_docs.rs`)

Round 1 fixes verified by Claude (fmt, clippy `-D warnings`, 129 tests, `ux-docs` PASS; adversary table maps each abuse story to the
right registry row; no mojibake left). A source and logic review of the new checks found two defects that the tests do not catch:

4. **F-4: `is_measurable` accepts a vacuous outcome.** Claude changed the first scenario of `maya.md` to
   `Measurable outcome: it works well for everyone, see J-02.` and `cargo xtask ux-docs` still printed PASS, because any ASCII digit
   counts and `J-02` has digits (the same would happen with `S-040` or `ATK-001`). Required: remove identifiers of the forms `J-nn`,
   `S-nnn`, `ATK-nnn`, `T-nnnn`, `Q-nnn` and `B<n>.<n>` references before looking for a number; accept an outcome only if it then
   names (a) an `AC-nn`, `AUD-...` or `MET-...` id, or (b) a number that is attached to a unit or comparator (`3 minutes`, `5 clicks`,
   `100%`, `at most 2`, `under 10 s`, `within 1 day`, `zero`, `0 errors`). Tests first, saved to `docs/evidence/P01/T-0012-f4-red.txt`:
   `see J-02` fails; `it works well` fails; `within 3 minutes` passes; `AUD-domain.activated is written` passes; `AC-37 passes` passes;
   `10 of 10 attempts` passes. Then check that every outcome in the seven shipped personas still passes; fix a persona only where its
   outcome is genuinely vacuous, never by weakening the rule.
5. **F-5: accessibility criteria are counted, not validated.** `criteria_tokens` accepts any text shaped like `d.d.d`, so
   `9.9.9` and `1.4.4` count the same (A3 says the needs must map to the B11.11 criteria). Required: read the table of spec B11.11
   (`docs/SPEC.md`, heading `### B11.11`, the "Criterion" column; entries look like `1.4.3 / 1.4.11`, `2.1.x`, `1.3.x`; the `x`
   entries cover every criterion with that prefix) and make each cited criterion count only if it is covered by that table; report
   each cited criterion that is not covered as a finding. Tests first (`docs/evidence/P01/T-0012-f5-red.txt`): `9.9.9` is reported;
   `1.4.4` and `2.1.1` (covered by `2.1.x`) are accepted; a persona citing fewer than two covered criteria fails. Read the spec through
   `spec::load_master` like `attack_registry`. Verify every shipped persona; if one cites an uncovered criterion, say so under Reports
   rather than editing the spec.

Minor, fix while there (no separate tests needed unless the behavior changes): in `primary_persona_findings` the row is matched by
the words `persona` and `primary` anywhere in any table row of the register; restrict the match to the row of the section titled
`Primary persona for the pilot` so a future row that merely mentions both words cannot be bound by mistake (add one test).

Reply under Reports (heading `### ... DeepSeek Harness · T-0012 round 3`), then stop. Same rules: no commit, no `STATUS.md` or `HANDOFF.md`.

### 2026-10-19 · Claude · review of T-0012 (round 3: content logic of the matrix)

Round 3 verified by Claude (fmt, clippy, 136 tests, `ux-docs` PASS; probes of the new measurable rule and the `9.9.9` rule behave as
described). A cross-check of the matrix against spec B1.1 to B1.6 found a real content error that no check catches:

6. **F-6: `persona-journey-matrix.md` omits a link the specification declares.** Spec B1.1 lists Maya's key journeys as
   `J-02, J-07, J-08/J-09, J-12, J-15, J-16, J-22/J-23, J-25`. `maya.md` lists J-22 (correct) but the matrix row for J-22 names only
   Vi, not Maya. Fix the J-22 row so Maya is linked (give her reason as the owner whose visitors file appeals), and keep the J-23
   row as it is. All other declared key journeys (Dan, Sara, Omar, Vi, Alex) were checked by Claude and are present.
7. **F-7: the check cannot see this class of error.** Add to `ux_docs.rs` (tests first, `docs/evidence/P01/T-0012-f6-red.txt`):
   - `key_journeys(spec, persona_heading)`: read the `Key journeys` row of the B1.1 to B1.6 tables through `spec::load_master`;
     expand `J-a/J-b` and `J-a to J-b` forms into a set of ids; B1.7 (the adversary) has no row and is exempt.
   - `check()` reports, for each persona, every declared key journey that is missing from (a) the persona file's `Journeys and
     screens` list or (b) the matrix row of that journey. The persona file's own list must also be a subset of the matrix: if a
     persona file lists `J-nn` the matrix row for `J-nn` must link that persona. (The matrix may link more personas than the files
     list; that direction is allowed.)
   - Tests: a fixture where the matrix row omits a declared persona fails and names persona and journey; a fixture with a range
     (`J-29 to J-31`) and a slash (`J-08/J-09`) expands correctly; a persona file that lists a journey whose matrix row omits it
     fails; the shipped tree passes after F-6 is fixed. Show the shipped tree failing before the F-6 edit (save that run to
     `docs/evidence/P01/T-0012-f6-red.txt` together with the new failing tests) and passing after.
   Keep `fmt`, `clippy -D warnings` and all tests green. Add a mutation demo (remove Maya from the J-22 row, expect FAIL; restore,
   expect PASS and an unchanged SHA-256) to `docs/evidence/P01/T-0012-f6-demos.txt`.

Reply under Reports (heading `### ... DeepSeek Harness · T-0012 round 4`) and stop. Same rules: no commit, no `STATUS.md` or `HANDOFF.md`.

### 2026-10-19 · Claude · review of T-0013 (round 1)

Re-run by Claude: `cargo fmt --all --check` OK, clippy `-D warnings` clean, 157 tests pass, `ux-docs` PASS. The 14 topics, the 20
requirements and their screens read well; every `S-` id exists and each requirement points at a screen that fits it (checked row by
row against the B12.1 names). The self-copy rewording of two persona sentences is accepted. Two logic defects:

8. **F-8: component match is a substring match.** `design_requirement_findings` accepts a component when
   `target_cell.contains(name)`. Claude changed the target cell of DR-03 from `S-047, DataTable` to `DataTableOfDoom` and
   `cargo xtask ux-docs` still printed PASS. Short names such as `Link`, `Tabs`, `Toast`, `Kbd` would match inside ordinary words
   the same way. Required: match a component name only as a whole token (not preceded or followed by a letter, digit or `_`), so
   `DataTableOfDoom` and `Linked` fail and `DataTable`, `` `DataTable` `` and `Tabs, S-042` pass. Tests first, red output in
   `docs/evidence/P01/T-0013-f8-red.txt`: `DataTableOfDoom` fails; `Linked` fails; `DataTable` passes; ``DataTable`` in backticks
   passes; a row with one valid screen id and an invented word passes (the screen is enough). Then confirm the shipped document still
   passes; if a shipped row only passed through a substring, name its real component or screen instead of weakening the rule.
9. **F-9: the honesty-test review is not checked.** T-0013 step 7 requires the document to be reviewed against the charter's five
   honesty tests; the check only needs the heading to exist. Required in `patterns_findings`: the `## Honesty-test review` section
   must exist; its table must have exactly five rows; each row's `Answer` cell must be `Yes` or `No` (case-insensitive) and its `Reason`
   cell non-empty; any `No` is a finding (the charter says a "no" blocks the change, so a document that fails a test cannot ship).
   Tests first (`docs/evidence/P01/T-0013-f9-red.txt`): four rows fails; an answer `Maybe` fails; an empty reason fails; one `No`
   fails; the five-yes table passes; a missing section fails. Mutation demos for F-8 and F-9 on the shipped documents go to
   `docs/evidence/P01/T-0013-negative-demos-round2.txt` (restore each time; show the SHA-256 is unchanged).

Reply under Reports (heading `### ... DeepSeek Harness · T-0013 round 2`) and stop. Same rules: no commit, no `STATUS.md` or `HANDOFF.md`.

### 2026-10-19 · Claude · review of T-0014 (round 1)

Re-run by Claude: fmt OK, clippy `-D warnings` clean, 179 tests pass, `ux-docs` and `claims-lint` PASS. Claude also cross-checked
`routes.toml` against the specification with an independent script: every B12.1 screen appears (S-010 to S-013 are a range row in the
spec), no unknown screen, every B2.2 pattern is present (the tab paths are relative in the spec and appear under their base), every
`PERM-` id exists in B4.2, and each route's permission equals the permission of its screen's primary endpoint except S-134, which is
deliberate (public variant and domain variant). The transcription is accurate. Three logic gaps: the checks validate each key in
isolation but not the combinations, so a wrong-but-valid row passes. Claude changed the shipped file and `ux-docs` printed PASS for each:

10. **F-10: no consistency rules between the route keys.** Add these rules to `routes_findings` (tests first, red output in
    `docs/evidence/P01/T-0014-f10-red.txt`):
    a. `permission = "public"` is not allowed on the `admin` or `api` surface, and on the `app` surface only when the route's
       `rate_limit_class` is `auth` or `public` (pre-login pages). Claude set `/admin` (S-100) to `public`: PASS today, must FAIL.
    b. A `PERM-platform.*` permission is allowed only on the `admin` surface (it is a platform-staff permission); and an `admin`
       surface route must carry a `PERM-platform.*` permission, or `public` only if its class is `auth` (the admin login page).
       Claude moved S-100 to the `public` surface while keeping `PERM-platform.infra.read`: PASS today, must FAIL.
    c. A route whose methods include anything other than `GET` or `HEAD` must have class `write`, `auth` or `export`; a route with only
       `GET`/`HEAD` must not have class `write`. Claude added `DELETE` to `/admin` (class `read`): PASS today, must FAIL. If the shipped
       file has a legitimate exception (a `POST` that only reads, such as a dry-run), keep it only if IA.md lists it under a new
       section `Rate-class exceptions` (pattern, method, reason) and the check verifies that every listed exception matches a real
       route and that no unlisted route violates the rule. Prefer fixing the data over adding exceptions.
    Tests: one failing and one passing fixture per rule (a, b, c), plus the exception-list round trip. Then run the shipped file; fix
    wrong rows only from the spec, and list every changed row in your report with the spec line that justifies it.

Reply under Reports (heading `### ... DeepSeek Harness · T-0014 round 2`), add mutation demos for a, b and c to
`docs/evidence/P01/T-0014-negative-demos-round2.txt` (restore after each; SHA-256 unchanged), and stop. Same rules: no commit, no
`STATUS.md` or `HANDOFF.md`.

### 2026-10-19 · Claude · review of T-0015 (round 1)

Re-run by Claude: fmt OK, clippy `-D warnings` clean, 196 tests pass, `ux-docs` and `claims-lint` PASS. An independent script found the
elements table accurate: 13 sidebar items, 9 tabs, 7 top-bar controls, every route exists in `routes.toml` and every permission equals
the route's. The mobile, focus and restricted-item sections read well. One substantive accuracy problem in the shortcut section, which
the check cannot see because it only compares keys against the reserved table:

11. **F-11: A5 is claimed but not true for several shortcuts.** A5 says the shortcut map has no conflicts with browser or
    screen-reader defaults. The shipped map conflicts in fact, and the document says nothing about it:
    - `Ctrl/Cmd+K` is the browser's own shortcut in several browsers (focus the address or search bar), and B2.3 mandates it for the palette.
    - `/` opens quick find in some browsers when no field has focus.
    - Single letters (`g`, `c`) and `?` are captured by screen readers in browse (virtual cursor) mode as quick-navigation keys, so
      they reach the page only in focus mode.
    The specification fixes these shortcuts, so the answer is not to rebind them but to be honest about the limits (charter honesty
    test 2) and to guarantee that no function depends on them. Required:
    a. A new section `Documented conflicts` in `NAVIGATION.md`: a table `Keys | Owner of the default | Effect | Mitigation`. One row each for
       `Ctrl/Cmd+K`, `/`, and the single-letter and `?` shortcuts (group the letters in one row if the reason is the same, but name
       every key). The `Mitigation` cell must name a way to reach the same function without the shortcut that exists in the elements
       table (for example the search control, the sidebar item) and state that the user can turn shortcuts off. Add a sentence in
       `Command palette and shortcuts` that shortcuts are conveniences and never the only path (WCAG 2.1.4 and 2.1.1).
    b. Check (tests first, red output in `docs/evidence/P01/T-0015-f11-red.txt`): every shortcut in the map that is `Ctrl/Cmd+K`, `/`, `?`
       or a single letter must appear in `Documented conflicts` (whole-key match); every row there must have a non-empty `Effect` and a
       `Mitigation` that names an element that exists in the `Navigation elements` table (match a name from the first column after
       `Sidebar · `, `Tab · `, `Top bar · `, or the words `search control`/`command palette`); a documented-conflict row whose keys are not
       in the map is reported as stale. Test fixtures: a map with `/` and no row fails; a row with an empty mitigation fails; a
       mitigation naming a non-existent element fails; a stale row fails; the complete fixture passes.
    c. Re-word the A5 claim wherever the document makes it (the review checklist, the opening paragraph): the reserved table lists keys the
       product never binds, and the conflicts table lists the keys it does bind despite a default, with their mitigations.
    d. Mutation demos in `docs/evidence/P01/T-0015-negative-demos-round2.txt`: remove the `/` row, empty one mitigation, rename a
       mitigation element, add a stale row (restore each time; SHA-256 unchanged).

Also noted, not for you to fix: B2.2 `.../settings` (domain settings) has no screen id in B12.1, so `routes.toml` records it as `support`. That is
a gap in the specification, recorded under Findings outside the current assignment.

Reply under Reports (heading `### ... DeepSeek Harness · T-0015 round 2`) and stop. Same rules: no commit, no `STATUS.md` or `HANDOFF.md`.

### 2026-10-19 · Claude · review of T-0016 (round 1: J-01 to J-06)

Re-run by Claude: fmt OK, clippy `-D warnings` clean, 215 tests pass, `ux-docs` and `claims-lint` PASS. The structure, titles, personas, screens
and ids are right. Claude then read every error path against its step, and many are filler chosen to satisfy the check (the code exists, but it
does not belong to the step). A structural check cannot see that, so this is the main finding:

12. **F-12: error codes that do not fit the step.** Examples Claude found (read the B7 titles at `docs/SPEC.md` line 1643 onward):
    - J-02 step 6 ("Continues after the confirmation", S-022) cites `ERR-AUTH-002` (email or password is incorrect): no password is typed there.
    - J-03 step 4 (reaches the recovery-codes page) cites `ERR-VAL-001` (invalid request body); step 7 (returns to the security summary)
      cites `ERR-AUTH-018` (passkey verification failed): no passkey is verified on that step.
    - J-01 step 8 ("Reads the form before typing anything") cites `ERR-RATE-001`; J-01 step 1 and 2 use 503 codes where a plain page load is
      the step: acceptable only if the row says what the visitor sees.
    - J-04 step 7 (locked account page, S-034) cites `ERR-AUTH-004`: check B7 for the code that describes a disabled or locked account and use
      it if it fits (B7 notes that a lock cause must not be revealed to the visitor, so the generic wording is part of the design).
    - J-06 step 4 (submits the new-account form, S-020) cites `ERR-ORG-003` (pending invitation exists): an invitation is being accepted here;
      step 5/6 and 7 deserve the same reading (`ERR-ORG-005`, `ERR-AUTH-007`).
    Required:
    a. Re-read every row of J-01 to J-06 and give each step an error path that is a real failure of THAT step, with a code from B7 whose
       title or note matches it. If B7 has no fitting code for a step, write `system` and the closest honest code (or add the gap to
       `docs/UX/spec-patches.md` as a proposed error code with the step that needs it) rather than borrowing an unrelated code. Do not
       change the number of steps below eight.
    b. Change the `Error path` format to `ERR-XXX-nnn: <what the user sees and why this code fits this step>` (the sentence is at
       least six words). Add checks (tests first, red output in `docs/evidence/P01/T-0016-f12-red.txt`): the sentence exists; it shares
       at least one content word (five or more letters, not a stop word from a short list in the code) with the B7 title or note of the
       cited code; and it shares at least one content word with that step's `User action`, `System response` or the title of its screen.
       Fixtures: `ERR-AUTH-002` on a step about confirming an address fails the step-fit rule; an `ERR-AUTH-002` row whose sentence mentions
       a wrong password on a sign-in step passes; a sentence of three words fails; a sentence unrelated to the code's B7 text fails.
       State in the module doc that this is a heuristic that catches blatant mismatches and that Claude's review covers the rest.
    c. List in your report every row you changed (journey, step, old code, new code, B7 line justifying it).
    d. Mutation demos (`docs/evidence/P01/T-0016-negative-demos-round2.txt`, restore each time, SHA-256 unchanged): put `ERR-AUTH-002` back on
       J-02 step 6, shorten one sentence, make a sentence unrelated to its code.

Then, in the same pass if you can, deliver J-07 to J-12 (the second delivery you described): same rules, J-08 and J-09 with at least twelve
steps, error paths written with F-12 in mind from the start, extend `JOURNEYS_IN_SCOPE`, extend `spec-patches.md` where a journey needs a missing
screen or error code. If you cannot finish both, finish F-12 first and report; Claude will assign J-07 to J-12 separately.

Reply under Reports (heading `### ... DeepSeek Harness · T-0016 round 2`) and stop. Same rules: no commit, no `STATUS.md` or `HANDOFF.md`.

### 2026-10-19 · Claude · review of T-0016 (round 2) and the second delivery

Round 2 verified by Claude (fmt, clippy, 220 tests, `ux-docs`, `claims-lint`). Every error path of J-01 to J-06 was re-read; the new sentences
are step-aware. J-01 to J-06 are accepted and committed as partial progress (commit `b9b5d61`; the task stays open). Remaining small wording
issue to fix while you are in the files: J-04 step 6 says the page "asks for the device cookie again", but a user cannot be asked for a
cookie; say that the trusted-device check fails and the second factor is asked for again.

**Assignment, second delivery of T-0016:** write `docs/UX/journeys/J-07.md` to `J-12.md` under exactly the same rules as the first delivery plus
the F-12 rules, extend the in-scope set to J-01..J-12, and extend `spec-patches.md` (screens or error codes the journeys need and B12.1/B7 lack).
J-08 and J-09 need at least twelve steps each and both name the two measures `Time to first domain in monitor mode` and `Completion rate of the
add-domain wizard` under `Instrumentation`. Because these two journeys gate adoption, add one extra table to each file, `Cutover safety`:
`Step | What could break the live site | Guard | Undo`, one row per step that changes DNS or routing, the guard and the undo each naming a control
that exists in the spec (for example preview, parity check, the instant return path of rule R-19); the check requires at least four rows and no
empty cell. Before you write a journey, read its text in the spec and list every `S-`, `AC-` and `ATK-` id it mentions; each `S-` id must appear
in the `Screen` column or in `Missing screens`, each `AC-` id in `Success and checks`. Write each error sentence for the step it sits on; reread
every row once more at the end, as the reviewer will. Tests first for the new rule (`Cutover safety`), red output in
`docs/evidence/P01/T-0016-cutover-red.txt`, mutation demos for it and a sample of the old rules on the new files in
`docs/evidence/P01/T-0016-negative-demos-round3.txt`. Do not stop after the checks: deliver all six journeys.

Reply under Reports (heading `### ... DeepSeek Harness · T-0016 round 3`) and stop. Same rules: no commit, no `STATUS.md` or `HANDOFF.md`.

## Closed assignment: batch B1 (T-0022, T-0024 to T-0027), committed 648160f

Status: CLOSED (verified and committed by Claude), PARALLEL BATCH B1 (assigned 2026-10-20 by Claude). T-0012 to T-0019 are CLOSED (verified and committed by Claude); history in
`docs/COLLAB-HISTORY.md`. The user asked for several tasks at once using DeepSeek's subagents. Read the Lessons above first: every defect found so far was
a semantic one (filler values, substring matches, vacuous rules, unchecked tables).

**Batch B1 = five independent tasks: T-0022, T-0024, T-0025, T-0026, T-0027** (all P01, all `[DOC]`). Start ONE subagent per task. The main agent coordinates and
integrates; it does not do a task itself except the wiring step.

**Parallel rules (to prevent two agents overwriting each other):**

1. Each subagent owns ONLY: its deliverable documents, its own new check module `crates/hdd-xtask/src/ux_docs/<module>.rs` with its unit tests INSIDE that same file
   (`#[cfg(test)] mod tests { ... }`, fixtures built locally and small), and its evidence files `docs/evidence/P01/T-00nn-*`. Modules: `a11y.rs` (T-0022), `responsive.rs`
   (T-0024), `security_ux.rs` (T-0025), `onboarding.rs` (T-0026), `dataviz.rs` (T-0027). Each exports `pub fn check(root: &Path) -> Vec<Finding>` that reads the master spec
   through `crate::spec::load_master` and its own documents. Re-use helpers already in `ux_docs.rs` (`slug`, `cells`, `section_table`, `prose_lines`, `finding`, ...);
   if you need a helper that does not exist, put a private copy in your module (do not edit `ux_docs.rs`).
2. Subagents must NOT edit: `ux_docs.rs`, `ux_docs/tests.rs`, `docs/COLLAB.md`, `docs/OPERATOR-QUESTIONS.md`, `STATUS.md`, `HANDOFF.md`, the matrix files, `INDEX.md`, another task's files.
   Questions for the operator go into your subagent's return message; the main agent adds them to the register.
3. Tests first per module: write the failing tests (a failing and a passing fixture per rule, whole-token matching, probe wrong-but-valid values), run
   `cargo nextest run -p hdd-xtask <module>` and save the full red output to `docs/evidence/P01/T-00nn-red.txt`. Until the main agent wires the module, call your
   module's `check` from your tests only. Keep fmt and clippy `-D warnings` clean for your file (`cargo clippy -p hdd-xtask --all-targets`). Cargo builds may wait for each
   other's lock; that is normal. If a build fails with `os error 4551` (Windows Application Control), touch your module file and retry; never change system settings.
4. Mutation demos per task into `docs/evidence/P01/T-00nn-negative-demos.txt` (back up first into a scratch directory, restore, show the SHA-256 is unchanged). Because the
   shipped documents are checked by your module only after wiring, run the demos AFTER the main agent has wired the modules (step 6), or run them against your module through a
   temporary test that points `check` at a copy of the repository files in a temp directory.
5. Each subagent returns to the main agent: files created, test counts, real result lines, what is UNVERIFIED, operator questions, and the lines the main agent must add to
   the wiring. Honest partial results are fine; say what is missing.
6. Main agent, after all subagents finished: (a) add `mod a11y; mod responsive; mod security_ux; mod onboarding; mod dataviz;` to `ux_docs.rs` and one
   `out.extend(<module>::check(root));` per module to `check()`; (b) add the operator questions to `docs/OPERATOR-QUESTIONS.md` under `## Questions added by T-00nn`
   sections (state `OPEN`); (c) run fmt, clippy `-D warnings`, the whole `hdd-xtask` suite, `cargo xtask ux-docs`, `cargo xtask claims-lint`; fix integration breakage
   without weakening any check; (d) run the mutation demos; (e) save the real output to `docs/evidence/P01/T-0022-27-verify.txt`; (f) append ONE report under Reports
   (heading `### <date> · DeepSeek Harness · batch B1 final`) with a section per task and per subagent, then stop. Do not commit.

**Task briefs (the task blocks are in `docs/tasks/P01/T-00nn.md`; read yours in full):**

- **T-0022 Accessibility strategy and test plan** (`ACCESSIBILITY.md`, `a11y-checklists/*.md`). Add the criteria list to the repo as `docs/UX/wcag22-criteria.toml`
  (id, name, level A or AA) for the WCAG 2.2 A and AA success criteria, noting in the file header that it is transcribed from the standard without fetching it and is
  `UNVERIFIED(no source fetched)`; the check asserts the mapping covers exactly this list (A1) and that every row names an owner component of B11.8 (whole-token) or
  `not applicable` with a reason. Name 12 critical flows from the journeys (ids J-nn that exist) with one checklist file each; every manual check needing a human is marked
  `human_step_pending` with instructions (A4); severity scheme with explicit gate rule (A3); accessibility statement draft that claims nothing beyond what is tested (A5: the check
  rejects absolute-conformance wording and requires a known-gaps section).
- **T-0024 Responsive and device strategy** (`RESPONSIVE.md`). The device matrix as a table (the seven viewports of the task, light and dark, LTR and pseudo-RTL) used by T-0090;
  a small-screen behavior row for every screen CATEGORY of the B12.1 headings (derive the category list from the spec, check each is covered); numeric performance budgets per
  device class; print rules for reports and audit exports (S-073, S-074, S-084 exist); tablets and landscape phones covered; a rule that security-critical controls are never
  hidden on small screens (list them, cross-check against the dangerous actions of `docs/UX/journeys/*.md` Safeguards).
- **T-0025 Security UX** (`SECURITY-UX.md`, `dangerous-actions.md`; also a new `i18n/en/security-ux.ftl`). At least 20 dangerous actions, table with all fields (risk, safeguard
  kind, undo path, audit event that exists in B8 or an explicit gap, copy key). Every copy key exists in `security-ux.ftl` with real English text that passes the Fluent
  style rules and the claims scanner (reuse `ux_docs::ftl_style` functions if public, else your own check). Self-lockout guard requirements numbered and testable; each
  time-boxed feature states the revert behavior when the browser closes; abuse cases of the UI link to ATK-285 to ATK-300 (all exist in C5, whole-token); every `Safeguards`
  row of the journeys J-13..J-24 has a matching dangerous-action entry (cross-check by step verbs, document the rule).
- **T-0026 Onboarding and activation** (`ONBOARDING.md`, `READINESS-MODEL.md`). The readiness model must agree with the readiness table of `docs/UX/journeys/J-25.md` (same
  checks, same weights, sum 100, Unknown never counts as pass; the check compares the two documents); the footnote equals the B13 `readiness-footnote` text exactly; the
  next-best-action rules are an ordered decision list in a restricted grammar (`rule N: if <conditions> then <action>`) with unique priorities and an example table
  (at least eight input to expected-action rows) that your module EVALUATES to prove the examples (a small evaluator in your module; the decision list is a pure function);
  nudges carry a frequency cap and an opt-out; every onboarding stage names its screen (exists in B12.1); local counters only for measures (names from `MEASURES.md`).
- **T-0027 Data visualization** (`DATAVIZ.md`, `metrics-dictionary.md`). Every KPI/metric: definition, unit, aggregation, window, source; every `MET-` id used exists in the
  spec (whole-token); every chart has a text alternative and an Unknown behavior; annotations list includes mode changes, rule changes and bans; downsampling rules numeric
  (maximum points, method); every screen of the task list (S-040, S-043, S-054, S-065, S-070 to S-072, S-100, S-127) exists and has at least one question and one metric;
  never chart interpolated data (state it, and check that no chart row says `interpolat` without `never`).

## Archived assignment: batch B2 (verified 2026-10-23, commit 3f2a29b)

Status: OPEN, PARALLEL BATCH B2 (assigned 2026-10-20 by Claude). Batch B1 (T-0022, T-0024 to T-0027) is CLOSED: verified and committed by Claude (648160f); its
findings F-14 to F-29 are the examples of what review looks for. T-0012 to T-0019 are in `docs/COLLAB-HISTORY.md`. Read the Lessons above first: every defect found so far
was semantic (filler values, wrong ids, contradictions between documents, rules that cannot catch the defect, claims the text does not support).

**Use Agent Team, not subagents:** the lead creates one team member per task, can message each member, checks each member's work while it runs, sends corrections to the
member, and only then integrates. Name the members `t0020`, `t0023`, `t0210`, `t0215`.

**Batch B2 = four independent tasks: T-0020, T-0023 (both `[DOC]`, P01) and T-0210, T-0215 (both code, P11).** Read each task block in full in `docs/tasks/P*/T-nnnn.md` first;
the Acceptance lines A1.. are the checklist. Do not claim anything the evidence does not show; a check that cannot run here ends `UNVERIFIED(reason)`.

**Ownership rules (parallel safety).**

1. Each member owns only its own deliverables, new module or crate, tests, and evidence files `docs/evidence/<phase>/T-nnnn-*`.
2. The LEAD alone edits the shared files: workspace `Cargo.toml` (members), `Cargo.lock`, `docs/vetting.toml`, `deny.toml`, `ARCHITECTURE.md`, `OPERATIONS.md`,
   `crates/hdd-xtask/src/ux_docs.rs`, `ux_docs/tests.rs`, `docs/COLLAB.md`, `docs/OPERATOR-QUESTIONS.md`. Register the new crates in the workspace FIRST (before the
   members start), so nobody edits `Cargo.toml` concurrently. A member that needs a shared-file change or a new external crate messages the lead with the exact text; every new
   crate needs a `docs/vetting.toml` entry (exists, maintained, licence, MSRV, API; never assert a version from memory) and an ADR if it is FFI, unsafe API or unmaintained.
3. Nobody edits `STATUS.md`, `HANDOFF.md`, `AGENTS.md`, the matrix files, `INDEX.md`, or another member's files. Nobody commits.
4. Tests first for every rule or function (a failing and a passing case; probe wrong-but-valid values; whole-token matching, no substring matches); save the real red output to
   `docs/evidence/<phase>/T-nnnn-red.txt`. After the code is green run mutation demos (back up, mutate, FAIL, restore, SHA-256 unchanged) into `T-nnnn-negative-demos.txt`.
5. Lint rules of the repo apply: no `unwrap`, `expect`, `panic`, indexing, `dbg!`, `print_stdout` outside tests; no placeholder code, no `todo!()`. Every outbound connection goes through
   `hdd-common::egress`. If a build fails with `os error 4551` (Windows Application Control), touch a source file and retry; never change system settings.
6. The lead checks each member's work before integrating and sends corrections to the member itself. The lead then runs `cargo fmt --all --check`,
   `cargo clippy --workspace --all-targets -- -D warnings`, `cargo nextest run --workspace` (or `-p` per crate when the workspace run is blocked), `cargo xtask ux-docs`,
   `cargo xtask claims-lint`, saves the real output to `docs/evidence/P01/T-0020-23-verify.txt` and `docs/evidence/P11/T-0210-T-0215-verify.txt`, appends ONE report under Reports
   with the heading `### <date> · DeepSeek Harness · batch B2 final` (a section per task: files, test counts, real result lines, UNVERIFIED items, operator questions, deviations),
   and stops. Honest partial results are fine.

**Task briefs.**

- **T-0020 Error-handling UX model** (`docs/UX/ERRORS.md`; module `ux_docs/errors.rs`). Map the nine error classes to UI patterns with decision rules; each class has an example
  from the ERR catalog (the ERR codes must exist in the spec, whole token, and the class must fit the code's family: do not use a filler code; J-nn tables show how this went wrong
  before, see F-12). Request ID display and copy pattern (what support can do with it); retry and idempotency table that separates safe from unsafe actions (classify real API
  actions of B7 by method and idempotency key rules, cross-check by script); the visitor error pages S-140 to S-148 constraints as testable statements (no rule names, no stack
  traces, no internal hostnames, no tenant leakage: each statement names how a test would detect it, and the check scans the B13/copy-deck strings of those pages against the
  statements); offline and flaky-network behavior for HTMX partial updates; long-running job failure surfacing; client-side logging is none, server-side is structured; accessibility
  per pattern (focus, `role="alert"`, text not colour only) consistent with `docs/UX/ACCESSIBILITY.md` and `docs/UX/SECURITY-UX.md`; security notes (no enumeration, no stack traces).
  Cross-document rules to check by script: the error patterns agree with the journeys' `Error path` ERR codes and with `i18n/en/copy-deck.ftl`; the permission-denied class
  does not reveal whether a resource exists (R-20).
- **T-0023 Internationalization and localization strategy** (`docs/UX/I18N.md`; module `ux_docs/i18n_plan.rs`). Fluent, key naming with at least ten real examples taken
  from the existing `.ftl` files (check each exists), file layout `i18n/<locale>/<area>.ftl` agreeing with the files that exist now (`copy-deck.ftl`, `security-ux.ftl`,
  `onboarding.ftl`), fallbacks, pseudo-locale (accented, 40 percent expansion: define the exact transform and give worked examples that the module EVALUATES), RTL readiness list
  (CSS logical properties and a mirrored-icons list that names real icons of the design inventory if one exists, else says so), locale negotiation order, formatting rules for date, time,
  number, relative time and units, what is and is not translated (Ray IDs, rule IDs, API ids, log lines are never translated), email localization, translator workflow without
  an external service, launch locales from the profile `locales` key (check it in `hdd.live.example.yaml`), criteria to add a locale, test strategy including pseudo-locale overflow.
  Deliberately do not claim the `xtask i18n check` exists (it is a stub until T-0082).
- **T-0210 `hdd-canary`** (`crates/hdd-canary`, `hddctl canary generate|verify` in `crates/hddctl`, `CANARY.md`, a systemd unit template under `deploy/` or the path the task names;
  read spec section C16.1 for the exact file list). A static server that serves only the canary files and the `echo-headers` JSON, 1 KB request line and 8 KB header limits, no
  directory listing, fixed response headers, read-only filesystem access, no reflection of any input. Hostile-client tests (long header, odd methods, bodies, path tricks such as
  `..`, encoded slashes, query strings) must show uniform behavior; fuzz the request parser with a bounded test (property test or `cargo fuzz`-free approach: no new tool without
  vetting). `canary verify` reports PASS or UNVERIFIED with a reason and uses only `hdd-common::egress`. Manifest hashes are real SHA-256 over the generated files (A1). The systemd
  sandbox options are recorded (A4) and untested where systemd is not available here: say `UNVERIFIED(environment_unsupported)`. Windows is the dev host: keep it portable.
- **T-0215 `hdd-acceptance` skeleton** (`crates/hdd-acceptance`; docs under the path the task names). Core: profile loading and validation, `TargetGuard`, egress allowlist
  enforcement, five load profiles with a shared token-bucket limiter (the `functional` profile at 20 req/s and 5 minutes, measured by a test with a controllable clock, A2), the
  kill-switch watcher (abort within 1 s, cleanup runs, A3), lifecycle rules (production refuses destructive checks), the `Check` trait with dependency ordering and a `finally`
  cleanup stack, per-check timeouts, the reporter (JSON and Markdown, one status line per AC id, secrets redacted, SHA-256 of saved logs), `InspectGate` (refuses to send when
  `would_block` is false or the config revision changed, A5), the registry of AC-00 to AC-62 each `UNVERIFIED(stage_not_reached)` (A4: check the ids against the spec by script, whole
  token), and the documentation. Out-of-band control-plane access and vantage points (steps 4 and 6): implement the typed interfaces and the checks that run without a network
  (runner IP not in `admin_cidrs`, ssh command construction without running it) and mark anything that needs a real SSH or WireGuard peer `UNVERIFIED(capability_not_supplied)`.
  Safety first: no code path may send attack-shaped traffic anywhere that is not in the allowlist derived from the live profile; the guard is tested before any send function exists
  (A1: a test proves nothing leaves for a non-allowlisted target, using a recording sender, not a real socket).

