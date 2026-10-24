# G00 progress notes (NOT the gate report)

> **Superseded on 2026-10-18** by the gate report [G00.md](G00.md) (Appendix E5.1 format, evidence with sha256 in `evidence/G00/`). This file keeps the session-1 record; `python tools/bootstrap/...` commands quoted below no longer exist (DEV-V5-000 closed).

When this file was written, gate G00 had **not** been attempted (it has since: not passed, see G00.md). This file records the real command output behind the states claimed in `STATUS.md` for T-0001 to T-0004 and T-0008.
The gate report itself (`docs/gates/G00.md`, Appendix E5.1 format) is written by T-0010. Full logs: `acceptance-verify/*.log` and `acceptance-env/*.log`
(git-ignored) with `SHA256SUMS`; hashes below are the first 16 hex characters. Date 2026-10-18, Windows 11 builder, `rustc 1.98.1`, `cargo 1.98.1`, Track L.

## Commands run

| # | Command | Exit | Output tail | Log sha256 (prefix) |
| --- | --- | --- | --- | --- |
| 1 | `cargo check --workspace` | 0 | `Checking hdd-proxy v0.0.0 ... Finished dev profile ... target(s) in 0.59s` | a66e238af1304d0a |
| 2 | `cargo clippy --workspace --all-targets -- -D warnings` | 0 | `Finished dev profile` (no warnings) | 1b804c9927d44a01 |
| 3 | `cargo fmt --all --check` | 0 | (no output) | 19eaf43821a7660e |
| 4 | `cargo deny check` | 0 | `advisories ok, bans ok, licenses ok, sources ok` (plus warnings: allowed licences not yet encountered, because no third-party crate is used) | d2094b0bea229bc2 |
| 5 | `python tools/bootstrap/spec_bootstrap.py check` | 0 | `A1 concatenation equals SPEC.md: True` / `A2 index lists T-0001..T-0599 exactly once: True 599` / `task headings in SPEC.md: 599 == index rows: True` / `A4 no split file above 3000 lines: True` / `RESULT: PASS` | c10bd2fdc0627501 |
| 6 | `cargo xtask` | 2 | `hdd-xtask: not implemented yet (first task: T-0005); see ARCHITECTURE.md` (expected: stub) | ef1190527e9e26f9 |
| 7 | `cargo run -q -p hdd-proxy -- --version` | 0 | `hdd-proxy 0.0.0` | 1bff84354ebc3e08 |
| 8 | `cargo tree -p hdd-proxy -e normal` | 0 | single line `hdd-proxy v0.0.0`; `hdd-vulnlab` count in the output: 0 | be7d954b4c0e3145 |
| 9 | `git check-ignore -v hdd.live.yaml acceptance-x/foo secrets/k .env target/x a.pem` | 0 | all six paths matched an ignore rule | 9d13773de4a4a718 |
| 10 | `wc -l AGENTS.md` | 0 | `76 AGENTS.md` | 3bc536e2b70204cb |
| 11 | lint demo: append `Some(1).unwrap()` to `hdd-common`, `cargo clippy -p hdd-common -- -D warnings`, then revert | 101 | `error: used 'unwrap()' on an 'Option' value` / `could not compile 'hdd-common' (lib)` | b9bff9a0f683a526 |
| 12 | lint demo: append an `unsafe {}` block to `hdd-common`, `cargo check -p hdd-common`, then revert | 101 | `error: usage of an 'unsafe' block` | f77c0770c782ede9 |

Both demos were reverted (`crates/hdd-common/src/lib.rs` is back to the scaffold; `cargo check -p hdd-common` passes again).

## Task evidence

| Task | State | Criterion | Status | Evidence |
| --- | --- | --- | --- | --- |
| T-0001 | verified | A1 concatenation hash equals SPEC.md | PASS | row 5 |
| T-0001 | | A2 599 rows, no duplicates or gaps | PASS | row 5 |
| T-0001 | | A3 every phase has a split file whose first line is its marker | PASS | row 5 (checks the first line of every split file) |
| T-0001 | | A4 no split file above 3000 lines | PASS | row 5 (largest: `E1.md`, about 2,000 lines) |
| T-0001 | | A5 commit contains only docs, README and `.gitkeep` | **not applicable as stated**: nothing is committed yet, and the foundation includes build files from T-0004. Commit history should split them when the operator asks for a commit. | |
| T-0002 | verified | A1 AGENTS.md at most 150 lines | PASS | row 10 (76) |
| T-0002 | | A2 STATUS lists all 599 tasks as todo except T-0001/T-0002 | **differs by design**: T-0003, T-0004 are `green` and T-0008 is `designing` because they were also worked in this session (ASM-005). | `STATUS.md` |
| T-0002 | | A3 DEVIATIONS has the seeded entries with dates | PASS | `docs/DEVIATIONS.md` (DEV-V5-000 to -007) |
| T-0002 | | A4 `git check-ignore` confirms the ignore rules | PASS | row 9 |
| T-0002 | | A5 a reviewer can find the next task and the stop conditions from AGENTS.md alone | PASS (self-read; not independently reviewed) | `AGENTS.md` |
| T-0003 | green | A1 every R-05 item has a row with PASS/FAIL/UNVERIFIED(reason) | PASS | `docs/ENV.md` |
| T-0003 | | A2 no command writes outside scratch dirs or changes state | PASS (read-only commands; logs only in `acceptance-env/`) | `docs/ENV.md` |
| T-0003 | | A3 degradation statement for every non-PASS row | PASS | `docs/ENV.md` |
| T-0003 | | A4 outbound checks touched only allowlisted hosts | PASS (no outbound request was made; no allowlist exists yet) | `docs/ENV.md` |
| T-0003 | | A5 no secrets or key paths printed | PASS (self-checked) | |
| T-0003 | | Test: run discovery twice, identical except timestamps | PASS (`diff` of two runs, timestamp line masked) | `tools/bootstrap/env_discovery.py` |
| T-0004 | green | A1 `cargo check --workspace` | PASS | row 1 |
| T-0004 | | A2 an `.unwrap()` makes clippy fail | PASS | row 11 |
| T-0004 | | A3 `cargo deny check` runs | PASS | row 4 |
| T-0004 | | A4 `hdd-vulnlab` absent from a shipped binary's graph | PASS for `hdd-proxy`; other binaries not individually checked | row 8 |
| T-0004 | | A5 `forbid(unsafe_code)` in every crate except `hdd-xdp-ebpf`, checked by an xtask grep rule | PARTIAL: verified by hand (all scaffold files carry it); the xtask rule does not exist yet | T-0005 |
| T-0004 | | Test: compile-fail test with `trybuild` | **not done** (needs a vetted dependency); row 12 shows the same effect by hand | |
| T-0008 | designing | Steps 1 to 4, 6 to 7; ADR stubs 0001 to 0024 plus 0025 | done | `docs/adr/` |
| T-0008 | | Step 5 / A2: `xtask verify` flags a dependency addition lacking vetting | **not done** | T-0005 |

## Not done in this session

T-0005, T-0006, T-0007, T-0009, T-0010 and every task after them. The `local`/`hosted` runtime code, the UI, the data and control planes: nothing exists beyond scaffolds.
