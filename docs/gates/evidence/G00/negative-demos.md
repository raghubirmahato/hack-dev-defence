# Negative demonstrations of `cargo xtask verify`

Generated (and, for the vulnlab-graph demo, repeated by hand) on 2026-10-18T16:45:39Z by a throw-away script (not part of the repository). Each demo applies one temporary mutation,
runs `cargo xtask verify --only <steps>`, and restores the file. The exit code is the one of `cargo xtask`.

## fmt: badly formatted code

Steps: `fmt`. Exit code: **1**.

```
    |
    |          ^^^^^^^^^^^^^^^
    |
[01] fmt                  FAIL  (log 01-fmt.log, sha256 924e614b802373a3)
       | $ cargo fmt --all --check
       | Diff in \\?\D:\Hack Dev Defence\crates\hdd-xtask\src\util.rs:330:
       |      }
       |  }
       |  
       | [31m-pub fn   badly_formatted ( ){ }
       | [0m[32m+pub fn badly_formatted() {}
       | [0m 
       | 
       | (exit 1)
```

## clippy: an unwrap in non-test code (R-01)

Steps: `clippy`. Exit code: **1**.

```
[02] clippy               FAIL  (log 02-clippy.log, sha256 83eed3b010fa66bc)
       |    |
       |    = note: if this value is `None`, it will panic
       |    = help: for further information visit https://rust-lang.github.io/rust-clippy/rust-1.98.0/index.html#unwrap_used
       |    = note: requested on the command line with `-D clippy::unwrap-used`
       | 
       | error: could not compile `hdd-common` (lib) due to 1 previous error
       | warning: build failed, waiting for other jobs to finish...
       | error: could not compile `hdd-common` (lib test) due to 1 previous error
       | 
       | (exit 101)
verify: 0 PASS, 1 FAIL, 0 UNVERIFIED; logs in D:\Hack Dev Defence\acceptance-verify\20261018T164549Z-verify
```

## nextest: a failing test

Steps: `nextest`. Exit code: **1**.

```
[03] nextest              FAIL  (log 03-nextest.log, sha256 aabcb6aa57d3b4e9)
       |         PASS [   1.577s] (204/207) hddctl::preflight full_preflight_runs_the_probes_but_only_through_the_allowlist
       |         PASS [   1.588s] (205/207) hddctl::preflight a_complete_profile_passes_profile_only_preflight
       |         PASS [   1.587s] (206/207) hddctl::preflight a_missing_file_prints_every_required_field_and_how_to_provide_it
       | ────────────
       |      Summary [   2.628s] 206/207 tests run: 205 passed, 1 failed, 0 skipped
       |         FAIL [   0.059s] (191/207) hdd-xtask::bin/hdd-xtask util::demo_failing::demo_failing
       | warning: 1/207 tests were not run due to test failure (run with --no-fail-fast to run all tests, or run with --max-fail)
       | error: test run failed
       | 
       | (exit 100)
verify: 0 PASS, 1 FAIL, 0 UNVERIFIED; logs in D:\Hack Dev Defence\acceptance-verify\20261018T164606Z-verify
```

## doc-tests: a failing doc test

Steps: `doc-tests`. Exit code: **1**.

```
[04] doc-tests            FAIL  (log 04-doc-tests.log, sha256 bbe911aabe5ac2e8)
       |    Compiling tokio-rustls v0.26.6
       |    Compiling hdd-common v0.0.0 (D:\Hack Dev Defence\crates\hdd-common)
       |     Finished `test` profile [unoptimized + debuginfo] target(s) in 7.07s
       |    Doc-tests hdd_analytics
       |    Doc-tests hdd_auth
       |    Doc-tests hdd_challenge
       |    Doc-tests hdd_common
       | error: doctest failed, to rerun pass `-p hdd-common --doc`
       | 
       | (exit 101)
verify: 0 PASS, 1 FAIL, 0 UNVERIFIED; logs in D:\Hack Dev Defence\acceptance-verify\20261018T164636Z-verify
```

## deny: a banned crate (itoa) in the graph

Steps: `deny`. Exit code: **1**.

```
[05] deny                 FAIL  (log 05-deny.log, sha256 84da6a742956f14e)
       |       ├── schannel v0.1.30
       |       │   └── rustls-native-certs v0.8.5
       |       │       └── hdd-common v0.0.0 (*)
       |       ├── socket2 v0.6.5
       |       │   └── tokio v1.53.3 (*)
       |       ├── tempfile v3.27.0 (*)
       |       └── tokio v1.53.3 (*)
       | 
       | 
       | (exit 2)
verify: 0 PASS, 1 FAIL, 0 UNVERIFIED; logs in D:\Hack Dev Defence\acceptance-verify\20261018T164656Z-verify
```

## vet, machete, dependency-vetting: a new dependency that is unaudited, unused and has no vetting entry

Steps: `vet machete dependency-vetting`. Exit code: **1**.

```
[07] vet                  FAIL  (log 07-vet.log, sha256 33c21e58f0fb5a33)
       | $ cargo vet --locked
       | Vetting Failed!
       | 
       | 1 unvetted dependencies:
       |   hex:0.4.3 missing ["safe-to-deploy"]
       | 
       | (exit -1)
[11] machete              FAIL  (log 11-machete.log, sha256 7d4d6028f0ac2306)
       | [package.metadata.cargo-machete]
       | ignored = ["prost"]
       | 
       | You can also try running it with the `--with-metadata` flag for better accuracy,
       | though this may modify your Cargo.lock files.
```

## unsafe-scan: a crate root without forbid(unsafe_code)

Steps: `unsafe-scan`. Exit code: **1**.

```
[08] unsafe-scan          FAIL  (log 08-unsafe-scan.log, sha256 88026593c293e995)
       | first-party unsafe scan (substitute for cargo-geiger, ADR-0018): forbid(unsafe_code) at every crate root, inherited workspace lints
       | dependency unsafe counts: not measured (cargo-geiger viability is decided by T-0517)
       | [rules] crates/hdd-dns/src/main.rs: crate root lacks `#![forbid(unsafe_code)]` (T-0004 A5)
       | 1 finding(s)
verify: 0 PASS, 1 FAIL, 0 UNVERIFIED; logs in D:\Hack Dev Defence\acceptance-verify\20261018T164717Z-verify
```

## vulnlab-graph: a shipped binary depending on the Vuln-Lab

Steps: `vulnlab-graph`. Exit code: **1**.

The first attempt of this demo added the path dependency to `hdd-proxy` only and the check passed with exit 0: Cargo ignores a dependency on a crate
without a library target (`warning: ... ignoring invalid dependency hdd-vulnlab which is missing a lib target`), so the Vuln-Lab (binary only) cannot
enter a graph today and there was nothing for the check to find. The demo was repeated with a temporary `lab/vulnlab/src/lib.rs` (removed afterwards),
which makes the dependency real:

```
[09] vulnlab-graph        FAIL  (log 09-vulnlab-graph.log, sha256 2f18b8c7aa4c70c0)
       | Vuln-Lab isolation: no default workspace member reaches hdd-vulnlab through normal or build dependencies (section 2.8, T-0004 A4)
       | [rules] hdd-proxy: reaches hdd-vulnlab through its dependency graph (section 2.8, T-0004 A4)
       | 1 finding(s)
verify: 0 PASS, 1 FAIL, 0 UNVERIFIED
```

After restoring, the same step passes again (`[09] vulnlab-graph PASS`), and `lab/vulnlab/src/` holds only `main.rs`.

## rules: a TODO comment and a direct socket outside hdd-common::egress (R-01, R-22)

Steps: `rules`. Exit code: **1**.

```
[10] rules                FAIL  (log 10-rules.log, sha256 011028d9729c9365)
       | grep rules: R-01 placeholders, R-22 egress path, AGENTS.md size
       | [rules] crates/hdd-dns/src/main.rs:22: R-01: `// TODO`/`// FIXME` comment (no placeholders)
       | [rules] crates/hdd-dns/src/main.rs:23: R-22: `TcpStream::connect` outside hdd-common::egress (add a listed exception in docs/lint-rules.toml with a reason, or use the egress client)
       | 2 finding(s)
verify: 0 PASS, 1 FAIL, 0 UNVERIFIED; logs in D:\Hack Dev Defence\acceptance-verify\20261018T164728Z-verify
```

## spec-check: a split file edited by hand (T-0005 A2)

Steps: `spec-check`. Exit code: **1**.

```
[12] spec-check           FAIL  (log 12-spec-check.log, sha256 840a1b9292ad56bf)
       | spec check (docs/SPEC.md vs docs/spec/)
       | [spec] docs/spec/P00.md: differs from a fresh split of docs/SPEC.md (edit the master spec, then run `cargo xtask spec split`)
       | 1 finding(s)
verify: 0 PASS, 1 FAIL, 0 UNVERIFIED; logs in D:\Hack Dev Defence\acceptance-verify\20261018T164734Z-verify
```

## tasks-check: an invalid task state in STATUS.md

Steps: `tasks-check`. Exit code: **1**.

```
[13] tasks-check          FAIL  (log 13-tasks-check.log, sha256 360b7d89478cf7c5)
       | tasks check (index, order, per-task files, STATUS rows)
       | [tasks] INDEX.md: is stale; run `cargo xtask tasks index`
       | [tasks] STATUS.md: T-0011: invalid state "finished"
       | 2 finding(s)
verify: 0 PASS, 1 FAIL, 0 UNVERIFIED; logs in D:\Hack Dev Defence\acceptance-verify\20261018T164739Z-verify
```

## adr-check: an ADR missing from the index

Steps: `adr-check`. Exit code: **1**.

```
[14] adr-check            FAIL  (log 14-adr-check.log, sha256 7b1b7ba3295e76de)
       | adr check (numbers, index, deciding task, rollback plan)
       | [adr] docs/adr/0003-ui-stack-askama-htmx-islands-vs-leptos-ssr.md: not referenced from docs/adr/INDEX.md
       | 1 finding(s)
verify: 0 PASS, 1 FAIL, 0 UNVERIFIED; logs in D:\Hack Dev Defence\acceptance-verify\20261018T164745Z-verify
```

## profile-check: the generated schema file is stale

Steps: `profile-check`. Exit code: **1**.

```
[16] profile-check        FAIL  (log 16-profile-check.log, sha256 598b4dfa9e637fc8)
       | profile check (docs/profile.schema.json and hdd.live.example.yaml are current; the example fails only where expected)
       | [profile] docs/profile.schema.json: differs from the schema generated from hdd-common::profile::Profile; run `cargo xtask profile schema`
       | 1 finding(s)
verify: 0 PASS, 1 FAIL, 0 UNVERIFIED; logs in D:\Hack Dev Defence\acceptance-verify\20261018T164751Z-verify
```

## secret-scan: a private key block in a file (T-0005 A4)

Steps: `secret-scan`. Exit code: **1**.

```
[17] secret-scan          FAIL  (log 17-secret-scan.log, sha256 2028b2a32b2ac55f)
       | secret scan (private keys, provider tokens, credential assignments, high entropy, .env files)
       | [secrets] docs/_demo_secret.md:1: private key block: ----… (31 chars)
       | 1 finding(s)
verify: 0 PASS, 1 FAIL, 0 UNVERIFIED; logs in D:\Hack Dev Defence\acceptance-verify\20261018T164756Z-verify
```

## claims-lint: a forbidden phrase (T-0005 A3)

Steps: `claims-lint`. Exit code: **1**.

```
[18] claims-lint          FAIL  (log 18-claims-lint.log, sha256 67d86793a01b7a30)
       | claims-lint: scanned 68 files with 34 phrases
       | [claims] README.md:58: forbidden phrase "unhackable" (section 4.2)
       | 1 finding(s)
verify: 0 PASS, 1 FAIL, 0 UNVERIFIED; logs in D:\Hack Dev Defence\acceptance-verify\20261018T164804Z-verify
```

## rust-share: hand-written Python lines push Rust below 90%

Steps: `rust-share`. Exit code: **1**.

```
[19] rust-share           FAIL  (log 19-rust-share.log, sha256 6dc09c57e1ce6c81)
       |   design/prototypes/** [other]                       0  labelled design artifacts, excluded from builds (R-16)
       |   tests/fixtures/** [other]                          0  tagged payload fixtures, not product code
       |   lab/vendor/** [vendored]                           0  digest-pinned third-party lab material (section 2.8)
       | non-programming languages (documents and configuration, excluded by definition):
       |   JSON             2387
       |   Markdown            0
       |   TOML             1369
       |   YAML              109
       | [rust-share] workspace: Rust is 40.27% of programming lines (minimum 90%)
       | 1 finding(s)
verify: 0 PASS, 1 FAIL, 0 UNVERIFIED; logs in D:\Hack Dev Defence\acceptance-verify\20261018T164811Z-verify
```

## matrix-check: a task marked done with no test and no evidence (T-0010 A2)

Steps: `matrix-check`. Exit code: **1**.

```
[20] matrix-check         FAIL  (log 20-matrix-check.log, sha256 9f9b19fab465696a)
       | matrix check (R-07: every REQ maps to a test or an explicit deferral; done rows link evidence)
       | [matrix] docs/CAPABILITY-MATRIX.md:T-0007: done: no linked test and no explicit deferral (R-07)
       | [matrix] docs/CAPABILITY-MATRIX.md:T-0007: done: no evidence linked
       | [matrix] docs/CAPABILITY-MATRIX.md:T-0007: done: no passing run record (a verify summary JSON without FAIL) among the evidence
       | [matrix] docs/CAPABILITY-MATRIX.md: is stale; run `cargo xtask matrix generate`
       | 4 finding(s)
verify: 0 PASS, 1 FAIL, 0 UNVERIFIED; logs in D:\Hack Dev Defence\acceptance-verify\20261018T164820Z-verify
```

## Not demonstrated

- `audit`: a failing run needs a crate with a published advisory; none is in the dependency graph. The classification of the tool's exit code and of an unreachable advisory database is covered by the unit test `verify::tests::exit_codes_map_to_statuses`.
- `attack-matrix-check`, `contrast-check`, `i18n-check`, `routes-check`: stubs by design (T-0005 step 1); they report UNVERIFIED(stage_not_reached).

## Restoration check

sha256 of every touched file before and after the demos:

```
all 14 touched files are byte-identical to their state before the demos
```

## Note on timing

These demonstrations ran before the fixes listed in `hostile-review.md`. The guarded behavior of every demonstrated step is unchanged by those fixes; `rules` gained the check that STRIDE.md cites only existing tests, and `secret-scan` now also decodes UTF-16 and NUL-padded text and reports unreadable files. `hook-demo.txt` has the same timing. The final full run (`verify/`) executed all steps against the fixed code.
