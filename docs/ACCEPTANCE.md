# Acceptance runner (`hdd-acceptance`)

Status: **skeleton delivered by T-0215 (P11, `REQ-WSK-09`)**. The runner carries every acceptance check of Appendix E3. This
skeleton contains the parts that must exist before a check may send anything: the status taxonomy, the profile load and
validation, the target and egress allowlists, the five rate/load profiles and their shared limiter, the kill switch, the
lifecycle gates, the check framework with dependency ordering and a `finally` cleanup stack, the reporter, the inspect-first
gate, the control-plane interfaces, the registry of AC-00 to AC-62 and the dry run. **No live check is implemented and this
crate contains no real sender**, so a report from this tree can only be `UNVERIFIED(stage_not_reached)` for real checks; the
send seam and the checks themselves arrive with T-0216 and T-0491.

## Commands

```bash
cargo nextest run -p hdd-acceptance --no-fail-fast          # unit, property, golden and CLI tests
cargo fmt -p hdd-acceptance -- --check
cargo clippy -p hdd-acceptance --all-targets -- -D warnings

cargo run -p hdd-acceptance -- registry                     # the registry table (63 rows)
cargo run -p hdd-acceptance -- run --dry-run --out acceptance-dryrun
cargo run -p hdd-acceptance -- run --profile hdd.live.yaml --config-revision <rev> --out acceptance-pilot
cargo run -p hdd-acceptance -- run --profile hdd.live.yaml --load-profile load \
  --run-id <run-id> --operator-approval "run=<run-id>; window=<maintenance window>"
cargo run -p hdd-acceptance -- run --profile hdd.live.yaml --config-revision <rev> \
  --resume acceptance-<previous> --out acceptance-resumed
```

`--dry-run` needs no profile and writes a report in which every registered id is `UNVERIFIED(stage_not_reached)`. A run whose
report is marked invalid by a safety-envelope denial writes its report and exits with the documented refusal code **3** (review
item N-1); resuming an invalid previous report is refused with the same code. A run with
`--profile` validates the profile, the rate/load-profile/mode matrix, the egress allowlist, the target set, the load approval,
the run-id-bound approval and the runner-IP rule first; if any of them fails the run is refused with exit code 3 and nothing is
written into an `acceptance-*/` directory. A run in this skeleton then writes the same `stage_not_reached` report plus the
environment facts; it sends nothing. `--config-revision` records the control plane revision the report is bound to (review item
R-2); `--run-id` names this run and the approval ticket must name the same id (review item R-13).

## Status taxonomy (E3.1 rule 1)

Exactly three statuses exist, implemented in `src/status.rs`:

| Status | Meaning | Serialised |
| --- | --- | --- |
| `PASS` | The check passed and carries **at least one evidence artifact with a SHA-256**. A PASS without a hashed artifact is not representable through `StatusLine::new`, and both renderers refuse a report that contains one; because the status-line fields are public, the renderer is the enforcing gate. | `{"status":"pass"}` |
| `FAIL(reason)` | The check ran and failed, or was aborted (kill switch, signal, timeout, panic). | `{"status":"fail","reason":"…"}` |
| `UNVERIFIED(reason_code)` | The check could not decide. The reason code set is closed. | `{"status":"unverified","reason":"stage_not_reached"}` |

The reason set is **closed to exactly eight codes** (spec section 0, E3.1 rule 1; round-2 correction): `capability_not_supplied`,
`human_step_pending`, `environment_unsupported`, `oracle_unavailable`, `tool_unavailable`, `stage_not_reached`, `stage_forbids`,
`skipped_by_operator`. There is no "skipped" or "pending" status outside the set, and the round-1 additions `no_hdd_evidence`
and `dependency_not_met` are **removed** (the taxonomy test asserts the closed eight and that neither parses). A check that
needs HDD evidence it does not have is `UNVERIFIED(capability_not_supplied)` with a detail saying which evidence is missing; a
check whose dependency did not end `PASS` is `UNVERIFIED(stage_not_reached)` with a `detail` naming the dependency id, and it
does not run. A check interrupted by the kill switch or a signal records the abort and the remaining checks of the run are
`UNVERIFIED(skipped_by_operator)`. A caught panic is counted on the executor and carried into the `RunReport` (R-09) and
becomes a `FAIL` naming the panic; the cleanup stack still runs. A PASS is accepted only when the executor has re-read and
re-hashed its evidence files (review item R-4); a check cannot fabricate one.

## How the safety limits are enforced

All limits are code, not documentation, but **the crate-private constructors are a compile-time convention, not a security
boundary** (round-3 scope note): the threat model is a check written by us that makes a mistake, so every hole that needs no
hostile intent is closed, while code compiled into this crate is outside the guarantee. What actually runs at runtime is the
run's shared state, the one inspect gate and the evidence write records. The enforcement chain for one attack-shaped request is
`Attempt -> Connector::prepare -> PlannedRequest -> Sender::send`; only a `PlannedRequest` is accepted by a `Sender`, and its
constructor is private to `src/guard.rs`, so there is no path from an unchecked target to the send seam.

| Layer | What it enforces | Source of truth |
| --- | --- | --- |
| Target guard | The target must be in the set derived from the live profile: `test_hostname` and `sandbox_hostname` in `live` mode, the lab host and `lab.cidr` in `lab` mode. The repo's `hdd_common::egress::TargetGuard` is reused, including its CNAME and resolved-address checks, so the runner cannot disagree with the rest of HDD. | section 2.1, `TargetGuard::from_profile` |
| Payload class | C is never sent live. B is sandbox (or lab) only. A is read-only (`GET`/`HEAD`) on `test_hostname`; a class A request with a body goes to the sandbox. | section 2.2 |
| Egress allowlist | Infrastructure destinations (control plane, CA, resolvers, feeds) must match `egress_allowlist` scheme, host, port and path. An empty list denies everything (`EgressGate::from_profile`). | section 2.1, `EgressGate::check` |
| Lifecycle | `pilot` allows destructive checks with a warning in the report. `production` refuses them unless this specific run carries a recorded approval (run id plus maintenance window). **One coherent rule (R-13):** the lifecycle policy is the only production gate; it is consulted by the executor per check and by the connector per send, both with the run's id, and an approval that names another run is refused at run start and refused again at the gate. A class B payload implies destructive, whatever the check's spec flag says. | section 2.7, `LifecyclePolicy::allows_destructive_for` |
| Load profile | `load` additionally needs `load_profile_approved: true` **and** a recorded approval for that specific run; it targets the sandbox only. The 5 x 2 profile/mode matrix of section 2.3 is enforced in `RunnerConfig::build` **and** in `Connector::new` (R-1): `lab` only in lab mode; `protocol-abuse` and `load` only in live mode (sandbox host); `functional` and `burst` in either. | section 2.3, `LoadProfile::allows_mode` |
| Runner IP | Before a run, `PROF-RUNNER-ADMIN` from the profile validator must not fail: the runner IP may not be inside `admin_cidrs`. `auto` is `UNVERIFIED(stage_not_reached)` until the canary echo reports the address. | section 2.4, `control::runner_bannable` |
| Inspect-first gate | Before a live attack-shaped request, `POST /api/v1/waf/inspect` must answer `would_block=true` and an unchanged `config_revision`; otherwise the gate issues no ticket and nothing is sent. Transport and malformed answers fail closed. The gate and its client are created only by the executor; a check reaches the gate through `CheckContext::inspect` and cannot implement a client and mint a ticket (S-2). | section 2.2, `InspectGate` |
| Kill switch | The file `/var/run/hdd-acceptance.stop` (or `hdd-acceptance.stop` in the temp directory off Unix) aborts a running check within one second; the cleanup stack runs. The switch is latched, and the aborting check plus the rest of the run are `UNVERIFIED(skipped_by_operator)` (spec 2.8 step 5, review item A-8). | section 2.3, 2.8 step 5, `hdd_common::egress::KillSwitch` |
| Signal latch | One persistent listener for the whole run (`ctrl_c`, SIGTERM on Unix) latches the stop; the executor consults it before every check and the connector before every send, so a signal between checks is not lost. The listener is **primed in the executor constructor** (its first poll is what registers the OS handler), so a signal between `with_signals` and the first check is not delivered to the default handler (R-9). | review item A-9/R-9, `runner::AbortLatch` |
| Single-use request | A `PlannedRequest` is not `Clone` and `Sender::send` takes it by value: one `prepare` authorises exactly one send. It also carries a short send window and is refused when stale, and `Sender::send` receives the addresses that passed the guard so the sender cannot re-resolve the name (R-7: DNS rebinding). | review items A-1, R-7, `guard::PlannedRequest` |
| Shared budget | The connector spends from the same `RateBudget` as `CheckContext::acquire` (the run's one shared limiter plus the check's own profile limiter), and the token is spent **at send**, not at prepare, so prepared requests cannot be held across a second boundary and then released in a burst (R-7); a refusal from either consumes nothing. | review items A-2/A-3/R-7, `limits::RateBudget` |
| Path validation | The request target must be origin-form: one leading `/`, no `//host`, no whitespace, control characters or backslashes, so the userinfo trick and CR/LF smuggling cannot form a request. | review item A-4, `guard::validate_path` |
| Resolution | Every `prepare` resolves the target and validates every address and CNAME (`check_resolved`); the request carries the addresses that passed and redirects are never followed, so a rebinding answer on a later hop is refused. | review item A-4, `TargetGuard::check_resolved` |
| Inspect-first ticket | Every attack-shaped class (A and B) needs a matching `InspectTicket` (site, method, actual HTTP verb, path, class, a digest of body and headers, `config_revision`) for a site in `block` mode with safe mode off. The ticket is **single-use** (the first `prepare` consumes it; a reuse is refused), has a short TTL (30 s; an expired ticket is refused), binds the actual verb as well as the `Method` shape, and the `config_revision` is re-read at send time and compared again, so a control-plane change between prepare and send refuses the send (R-5). The ticket is consumed only **after** the revision, enforcement, resolution and abort re-checks (S-10), so a late refusal does not burn it. | review items A-5, R-5/S-10, `InspectGate`/`Connector` |
| Executor gates | Before the body runs the executor enforces `CheckSpec.destructive` (production + this run's approval; otherwise `UNVERIFIED(stage_forbids)` with the refusal as detail) and rejects a check whose profile exceeds the run's; the destructive flag comes from the spec, never from the attempt. The run starts only when **AC-00 is planned and ends PASS**: a plan without AC-00 is `PlanError::MissingSelfTest`, AC-00 runs first, and a non-PASS AC-00 (a FAIL, an `UNVERIFIED` or an unmet dependency) stops the run with the remainder `UNVERIFIED(stage_not_reached)`. The AC-00 rule is evaluated **before** the unmet-dependency skip (S-4), and AC-00 always re-runs - a resumed AC-00 PASS never satisfies the self-test (S-5). Every safety-envelope denial latches `run_invalid`, writes an audit line and appears in the `RunReport` even if the check swallows the error, and the run stops after the latch (R-8, S-8). Caught panics, including a panic from `spec()`, are counted and carried into the report (S-10). | review items A-3, R-8, S-4, S-8, S-10, `runner::Executor` |
| Rate/load profiles | One shared token-bucket limiter for every check of a run, with the hard ceilings below. A check may request lower caps (`RequestedCaps`) and is refused when it asks for more; a zero rate on a profile rate lane is refused instead of becoming an unlimited total bucket (S-9). Expired grants are popped from the front of the window on every acquisition, so the deque never grows beyond one second's allowance; a 300k-grant lab run is a fast test (R-10). The window is **closed**: a grant counts while `now - grant <= 1000 ms`, so no closed 1000 ms interval contains more than N. A refund does not restart the duration clock (S-9). | section 2.3, E3.1 rule 5 |
| Check-context scope (S-1, S-2, S-3, S-6) | The executor owns the validated `RunnerConfig.profile` and the run's one inspect gate. `CheckContext::connector()` takes **no profile argument**, so a check cannot build a connector for another host (S-1), and `CheckContext::inspect` is the only way to obtain a ticket (S-2). `ConnectorParts` fields, `Connector::new`, `InspectGate::new`, `RateBudget::new`, `Limiter::new`, `AbortLatch::new`, `RunInvalidLatch::new`, `CheckContext::new` and `EvidenceRef::new` are `pub(crate)`; `EvidenceRef`'s fields are private and the latches no longer implement `Default` (S-6). These are **crate-private conventions against accidental misuse**, held by eight `compile_fail` doc-tests; they are not a security boundary against code compiled into this crate. | review items S-1/S-2/S-3/S-6, `lib.rs` doc-tests |
| Evidence re-verification and binding (R-4, S-6) | `EvidenceStore::save_for` hashes the bytes it wrote and records `(check id, run id, name, hash)`; the executor re-reads and re-hashes the file and requires that record before accepting a PASS, so another check's file, a leftover from an earlier run or a fabricated hash is `FAIL(evidence invalid)`. Only `EvidenceStore` may build an `EvidenceRef`; a non-empty `--out` is refused (round 4, N-4: always, and an in-place resume is refused explicitly). | review items R-4/S-6, `EvidenceStore`/`Executor` |

A rate profile enforces **at most N requests in any closed 1000 ms interval** (review items A-10 and S-9): a grant counts while
`now - grant <= 1000 ms`, so 20 at t=0 and 20 more at t=0.9 s cannot pass as "20 req/s", and a request at exactly t=1.0 s is
still refused; the next allowance is at 1.000001 s. The duration cap is **half-open**: grants are allowed while
`elapsed < duration`, and a request at exactly the boundary is refused. The limiter takes an injectable
`hdd_common::kv::clock::Clock`, so the `functional` ceiling is **measured** in tests with a manual clock at non-aligned
instants (t=0, 0.5 s, 0.999 s, 1.0 s and over the whole 300 s): 20 acquisitions per window, the 21st in that window refused,
exactly 6,000 grants over 300 s, and refusal at exactly 300 s. A refused request consumes nothing, the check-level budget is
refunded when the shared limiter refuses, and a refund does not reset the duration clock (S-9).

### The five profiles and their ceilings

Only some of these numbers are in the specification. The table marks every field as `spec` (section 2.3 states it) or
`authored guard rail` (the specification gives no number; this task chose one, tightenable and never loosenable without the
operator).

| Profile | Field | Ceiling in code | Provenance |
| --- | --- | --- | --- |
| `functional` | rate | 20 req/s sustained | `spec` - section 2.3 "up to 20 req/s sustained" |
| `functional` | duration | 300 s | `spec` - section 2.3 "up to 5 minutes continuous" |
| `functional` | window allowance | 20 per 1000 ms (the `burst` field is the same 20) | `spec` - the rate is the window limit; A-10 removed the separate bucket capacity |
| `burst` | HTTP total | 100 requests, one capped burst | `spec` - section 2.3 |
| `burst` | DNS total | 500 queries, one capped burst | `spec` - section 2.3 |
| `burst` | duration and bucket shape | 60 s, capacity equals the total, no refill | **authored guard rail** - section 2.3 gives no duration or bucket shape for `burst` |
| `protocol-abuse` | connections / frames / bytes | 5 / 2,000 / 10 MiB | `spec` - section 2.3; sandbox only, no HTTP request lane |
| `load` | rate / bucket / duration | 100 req/s / burst 100 / 600 s | **authored guard rail** - section 2.3 says `load` "has its own hard caps in the profile", but the v5 profile schema has only `load_profile_approved` (operator question below). The approval gate itself is `spec`. |
| `lab` | rate / duration | 500 req/s per client process / 600 s | `spec` - section 2.3 defaults |
| `lab` | window allowance | 500 per 1000 ms (the `burst` field is the same 500) | `spec` - the rate is the window limit; A-10 removed the separate bucket capacity |

The port-scan variant of `functional` (20 pps, TCP top-1000 plus 53/80/443) belongs to `hdd-scan`, not to this HTTP lane; it
is not implemented here.

Operator question (also sent to the lead): the v5 profile has no numeric `load` cap fields. Until the profile schema carries
them (or a later task adds a `load_caps` block), the runner's 100 req/s and 600 s are authored ceilings, not profile values;
the operator must not read them as the profile's own caps.

### Operator approval and resume

`--operator-approval <ticket>` is the flag the specification names (T-0492 step 7, section 2.7). The runner checks the ticket
format `run=<run-id>; window=<maintenance window>`: both keys are required, values must be non-empty, keys may be reordered,
and an unknown, duplicate or missing key refuses the run with exit code 2. The ticket is **bound to the run it names** (R-13):
`--run-id` gives this run its id (default `run-<utc stamp>`), the executor consults the lifecycle policy with that id, and an
approval that names another run is refused at run start with exit code 3 and again at the per-check gate. The ticket text is
recorded as the run's approval; it is not a digital signature and the runner does not claim to verify one.

`--resume <previous-run-dir>` implements the rule of spec 2.8 step 5 at check granularity, hardened (R-2 and S-5). The executor
and the report path use the **same** `validate_resume`: it refuses a report from another mode/stage/load profile, another
`config_revision` or target host set, a report older than 24 hours, a report dated in the future beyond a small skew, and a
previous run that was marked invalid. A `PASS` line is kept only after **re-hashing every evidence file inside the resume
directory** (path containment: the file name is joined to the resume directory, the canonical parent must be that directory, and
a `..` or symlink escape is refused) and comparing the hash and size with the recorded values; the resumed line carries the
**verified** path, not the path printed in the previous report. A hand-edited `PASS` line with a 64-hex string that does not
match a file is therefore refused, not reused. A resumed `PASS` counts as executed and satisfies a dependency that is not in the
new plan (`order_with_satisfied`), so a resumed run neither fails with `UnknownDependency` nor re-sends traffic — **except
AC-00, which always re-runs**: a resumed AC-00 PASS never satisfies the self-test. A `--resume` without a readable previous
report is a usage error (exit code 2) and a mismatch is a refusal (exit code 3).

Round 4 (review items N-3 and N-4) tightened resume and output handling: the CLI and the executor use **one** selection
function (`report::select_resumed_lines`), so the two paths cannot disagree about AC-00; the resumed evidence is **copied
into the new run directory** (re-hashed before and after the copy) and the line points at the copy, so a resumed run
directory is self-contained and can itself be resumed; each resumed line keeps the timestamp it was first produced at and the
24 h age limit is applied **per line**, so a chain of resumes cannot extend a PASS; `--out` must be a new or empty directory
(a non-empty one is refused with exit code 2), and resuming **in place** (`--out` equal to `--resume`) is refused explicitly
(exit code 2) instead of failing later on `create_new`. **Honest limit:** the binding fields
(`config_revision`, host names, timestamp, mode/stage/profile) are self-asserted JSON with no MAC, so the guarantee is against a
stale or accidentally edited report, not against a deliberate forger who can rewrite the JSON. Resuming *inside* a check
(deterministic run ids and partial evidence) is T-0491 step 7 and is not implemented in the skeleton.

## The check framework

A check is a `CheckSpec` plus one async body:

```rust
let spec = CheckSpec {
    id: "AC-03",                       // exactly AC- plus two digits
    title: "Authoritative DNS (real path)",
    requirements: &["REQ-WSK-12"],
    destructive: false,
    profile: LoadProfile::Functional,
    dependencies: &["AC-00"],
    timeout: Duration::from_secs(120),
    tier: "nondestructive",
};
```

* `runner::order` sorts a plan so every dependency runs first and keeps the input order among independent checks; a missing
  dependency, a cycle, a duplicate id, a bad id or a zero timeout is a typed `PlanError`, never a silent skip.
  `runner::order_with_satisfied` additionally accepts a dependency resumed as `PASS` from a previous run, so a resumed plan does
  not need to re-run or re-send it (R-2).
* Each check runs inside an `Executor` that races the check against its timeout, the kill switch and the signal source. All
  four exits — completion, panic, abort, timeout — drain the cleanup stack LIFO before the status line is produced.
* Cleanup actions are registered with `CheckContext::on_cleanup` (`unban <ip>`, `remove temporary rule`, ...). An action that
  panics does not stop the others and is recorded as `(cleanup action panicked; recorded)`.
* Checks take rate budget through `CheckContext::acquire`, which spends from the run's one shared limiter **and** the check's
  own profile limiter; they cannot create their own limiter with higher caps.
* The executor enforces the static gates before the body (review item A-3): a check whose `profile` exceeds the run's ends
  `UNVERIFIED(stage_forbids)` and a destructive check in `production` ends `UNVERIFIED(stage_forbids)` without running.
* A per-check timeout fails **that check only**; the run continues. A check whose dependency did not end `PASS` is
  `UNVERIFIED(stage_not_reached)` with a detail naming the dependency and does not run — except AC-00, whose rule (planned and
  PASS) is evaluated first, so an AC-00 with an unmet dependency stops the run (S-4). The run starts only when AC-00 is in the
  plan; AC-00 always re-runs (a resumed AC-00 PASS is ignored, S-5) and a non-PASS AC-00 (FAIL or `UNVERIFIED`) stops the run,
  the remaining lines being `UNVERIFIED(stage_not_reached)`. A safety-envelope denial latches the run invalid and stops it the
  same way (S-8). A kill switch or signal abort marks the rest of the run `UNVERIFIED(skipped_by_operator)` (spec 2.8 step 5).

### Adding a check (the procedure T-0491 will use)

1. Read the AC row in `docs/SPEC.md` / `docs/spec/E3.md` E3.5 and the task that implements it. The typed catalog in
   `hdd_common::buildplan::ACCEPTANCE_CHECKS` and E3.5 must stay identical (E3.1 rule 8), so the registry row is not edited
   by hand; this crate is projected from that table and a test parses the specification and compares ids and titles.
2. Add the `Check` implementation in its own module with a `CheckSpec` whose id, title and tier match E3.5. Give it the
   requirement ids (R-07), the safety class, the lowest profile it needs and its dependencies.
3. Write the tests first: the happy path and every refusal path. A live attack-shaped request must go through
   `Connector::prepare` and the `InspectGate`; a test that sends must use a recording sender (the A1 pattern).
4. Evidence: save artifacts through `EvidenceStore` (path, SHA-256 and size are recorded in the status line) and the full log
   through `EvidenceStore::save_log` (the report embeds the redacted tail and the hash of the saved bytes).
5. Run the crate's green commands and the dry run; a check that cannot run here ends `UNVERIFIED(reason)` with one of the
   eight codes. Never mark a check PASS without a hashed artifact.

## Reporter and evidence layout

`Report` renders JSON and Markdown with **one status row per registered id**, evidence blocks (DNS answers, HTTP status and
headers, event ids, timestamps), notes, and, per saved log, the path, byte count, SHA-256 and the last 20 lines. The renderer
refuses a PASS without hashed evidence, a duplicate id and an id that is not `AC-nn`.

Redaction is structural (review items A-6, R-6, R-12 and S-7): an evidence field whose name is a secret marker (`Authorization`,
`X-API-Key`, `Cookie`, `Set-Cookie`, `session`, `token`, ...) is replaced whatever its value, and free-form values are redacted
by marker before serialisation. Every marker on a line is handled; a separator may be followed by spaces or tabs, a quoted value
(single or double quotes) is removed whole while the rest of the line survives, and an unquoted value fails closed to the end of
the line, so `password = hunter2`, `password="my pass phrase"`, `token = abc def` and `secret=a<TAB>b` leak no tail. A marker is
also matched inside a quoted JSON key (`{"password":"hunter2"}`), after `_`/`-` suffixes (`aws_secret_access_key`,
`secret_key`, `session_id`), in camelCase (`accessToken`), in the `--flag value` form and at **every** occurrence
(`the token was valid; token=abc123`), and exact secrets are replaced longest first so `pass1234` cannot half-eat
`pass1234567`; `add_secret` refuses a value shorter than four bytes with an error instead of silently dropping it (S-7). Redaction
is applied to **field values before serialisation** and never as a string replacement over the finished JSON document, so a
short registered secret cannot rewrite keys, ids, the word `pass` or a substring of a SHA-256; a minimum length of four
characters keeps a one-letter probe from shredding the document. Evidence field names and `block.check` are escaped in
Markdown, so a newline, a lone `\r` (a CommonMark line break) or a pipe in a hostile value cannot inject a heading or a table
row, a backtick in a log path is rendered in a longer code span, and `CONIN$`/`CONOUT$`/`COM¹`-`COM³` join the reserved device
names (S-10). Evidence values are capped at
**exactly 512 bytes including the `[truncated]` marker** (R-25, R-11) **after** redaction, on a UTF-8 boundary, in **both**
renderers, so a secret spanning the boundary loses no prefix. The Markdown fence around a log tail is longer than any backtick
run in the tail (review item A-11), and `EvidenceStore` refuses an absolute or `..` evidence name, a Windows reserved device
name (`NUL`, `aux`, `con`, `com1…`, `lpt1…`) or an NTFS alternate data stream (`name:stream`), and **never overwrites** an
existing artifact, instead of writing outside the run directory or recording a hash for a file it replaced (R-11). SHA-256
digests are never treated as secrets (the report needs them).

Run artifacts are written under `acceptance-<UTC stamp>-<mode>/` in the current directory; `.gitignore` excludes
`acceptance-*/`. A dry run writes `report.md`, `report.json` and `run.log`. A later task adds reading a run directory
back for resume and comparison (T-0491); the committed evidence for this task is the small `docs/evidence/P11/T-0215-*.txt` set.

```text
acceptance-20261020-…-live/
  report.md        # one status row per AC id, evidence blocks, log tails
  report.json      # the same report, machine-readable (E3.4 shape: lines, evidence, logs, notes)
  run.log          # full run log, redacted, SHA-256 recorded in the report
```

## Control plane, vantage points and what is not supplied

* **Out of band.** `control::ssh_command` builds an argv vector for an SSH command (`ssh -o BatchMode=yes -o
  StrictHostKeyChecking=yes -o ConnectTimeout=10 -o IdentitiesOnly=yes -i <key> <user>@<host> -- <program> <args>`). It never
  executes anything and never builds a shell string, so a remote argument such as `; rm -rf /` stays one argv element. A
  test asserts no shell (`-c`) is present and that hostile arguments are not split.
* **Runner IP is bannable.** `control::runner_bannable` reads the validator's `PROF-RUNNER-ADMIN` finding instead of
  re-implementing the rule, so the runner and `hddctl preflight` cannot disagree. A runner IP in `admin_cidrs` refuses the
  run, and while `test_runner.public_ip` is still `auto` (the canary echo has not reported the address) every attack-shaped
  send is refused with `RunnerNotBannable` instead of guessing (review item A-11).
* **Vantage points (step 6).** `control::VantagePlan` reads `vantage_points` (names only), records the count in the report and
  selects `SequentialWithUnban` when none is configured (E3.1 rule 2). Live use of a vantage needs an SSH or SOCKS peer that
  is not supplied in this environment: it is `UNVERIFIED(capability_not_supplied)`.
* **WireGuard.** The profile selects `test_runner.control_plane_access`; `ssh_command` refuses the WireGuard selection with a
  typed error. WireGuard peer management is not implemented and is `UNVERIFIED(capability_not_supplied)`.
* **No send function exists.** There is no socket, HTTP client or process execution in `crates/hdd-acceptance/src`; a test
  scans the sources for those constructions. When the first real sender arrives (T-0491), it must be built on
  `hdd_common::egress::Client`, take only `PlannedRequest` values and keep the `Connector::prepare` order.

## Testing and test doubles ([QA])

The crate test suite is deterministic and needs no service. A real service is not involved because this task ships no sender and no live check: the A1 criterion itself requires the guard to be tested with a **recording sender**, not a socket, and the A5 criterion requires a scripted inspect client. Those are the only doubles in the tree; there is no mock of a product behaviour and no fabricated evidence. Everything the suite writes goes to a process-unique temporary directory; the dry run the verify evidence quotes writes into the git-ignored `acceptance-*/`. Property tests cover report parsing, the redactor, `tail_lines`, the Markdown fence and profile parsing (arbitrary and
truncated text never panic). The scripted resolver (`test_support::ScriptedResolver`) supplies the two answers of the
DNS-rebinding fixture; the recording sender remains the only send double, because the crate still ships no sender.

## What is UNVERIFIED in this task

**Review item A-1 does not reproduce as a runtime test failure on the reviewed tree.** The defect was the type signature
(`Clone` plus a by-reference `send`), and the absence of a trait is only observable by the compiler. The final shape is
enforced by the compiler (a `clone()` of a `PlannedRequest` does not type-check); the runtime half — one rate-budget token per
send — is tested by `a1_one_prepared_request_covers_exactly_one_send_and_one_token`, and the mutation demo removes the token
consumption to show that test fail. This is recorded rather than fabricated.

| Item | Status | Why |
| --- | --- | --- |
| Every live AC check (AC-00 to AC-62) | `UNVERIFIED(stage_not_reached)` | The checks are implemented in T-0216/T-0491; the registry exists so the full list can be dry-run from P11 (E3.3). |
| Literal SIGINT/SIGTERM delivery | `UNVERIFIED(environment_unsupported)` on this Windows builder | A test cannot press its parent console's Ctrl-C honestly. The abort and cleanup path is tested through the injected `SignalSource`; the production `Signals` source uses `tokio::signal::ctrl_c` plus SIGTERM on Unix. |
| Live SSH tunnel / WireGuard peer | `UNVERIFIED(capability_not_supplied)` | No peer or key is supplied here; only the typed argv construction and the refusals are tested. |
| Live vantage-point use | `UNVERIFIED(capability_not_supplied)` | Same: the count and strategy are recorded; no connection is made. |
| Numeric `load` caps | authored, not read from the profile | The v5 profile schema has no load cap fields (operator question above). |
| `burst` duration | authored (60 s) | Section 2.3 gives no duration for `burst`. |
| Functional port-scan caps (20 pps) | not implemented in this crate | The scan belongs to `hdd-scan` (E4 table, T-0487). |
| `dependency_not_met` reason code | removed (round-2 correction) | It is not in the closed eight-code set of E3.1 rule 1. A dependent of a non-PASS dependency is now `UNVERIFIED(stage_not_reached)` with a detail naming the dependency. The DEVIATIONS entry is withdrawn by the lead. |
| Resume inside a check | not implemented | `--resume` keeps PASS lines at check granularity and re-runs the rest (spec 2.8 step 5), hardened by re-hashing and binding (R-2). Deterministic run ids and partial evidence per check are T-0491 step 7. |

## Evidence for this task

| Path | Contents |
| --- | --- |
| `docs/evidence/P11/T-0215-red.txt` | The acceptance tests failing before the safety seams were wired (42 failures in the 119-test suite at the time of that run; A1 to A5 among them. The suite is 121 tests now, with the profile-parsing property tests added afterwards). |
| `docs/evidence/P11/T-0215-verify.txt` | The green commands: nextest, fmt check, clippy, the registry, the dry run and the report hashes. |
| `docs/evidence/P11/T-0215-negative-demos.txt` | Five mutation probes: raise the functional ceiling, drop the allowlist check, ignore `would_block`, shorten the registry, disable exact-secret redaction. Each fails its test, and every file is restored byte-identically (SHA-256 before = after). |
| `docs/evidence/P11/T-0215-b2r1-red.txt` | The batch-B2 review defects reproduced: one section per finding A-1..A-11 with the command and the failure lines (A-1 is the compile-time property described above). |
| `docs/evidence/P11/T-0215-b2r1-negative-demos.txt` | The post-fix mutation demos for A-1..A-11: each mutation makes its own new test fail, restore is byte-identical (SHA-256 before = after). |
| `docs/evidence/P11/T-0215-b2r1-verify.txt` | The green commands on the fixed tree (tests, fmt, clippy, registry, dry run, resume, approval-ticket refusals). |
| `docs/evidence/P11/T-0215-b2r2-red.txt` | The batch-B2 round-2 review defects reproduced: the correction (closed eight-code set) and R-1..R-13, with the command and the failure lines. Where the round-2 fix was already implemented before the test, the red is a re-created demonstration: the specific seam is reverted, the test is run, and the revert is restored (documented per section). |
| `docs/evidence/P11/T-0215-b2r2-negative-demos.txt` | One mutation demo per R-item: the seam is mutated, the named test fails with the expected message, the file is restored byte-identically and the SHA-256 before = after is recorded. |
| `docs/evidence/P11/T-0215-b2r2-verify.txt` | The green commands on the fixed tree (nextest, fmt check, clippy `-D warnings`, doctests, registry, dry run, CLI refusals, resume and approval-ticket checks). |
| `docs/evidence/P11/T-0215-b2r3-red.txt` | The batch-B2 round-3 review items S-1..S-10: one re-created red section per finding (the exact seam is reverted, the named test is run, the real failure is captured, the file is restored byte-identically). |
| `docs/evidence/P11/T-0215-b2r3-negative-demos.txt` | One mutation demo per S-item: the seam is mutated, the named test fails with the expected message, the file is restored byte-identically and the SHA-256 before = after is recorded. |
| `docs/evidence/P11/T-0215-b2r3-verify.txt` | The green commands on the round-3 tree (nextest, fmt check, clippy `-D warnings`, doctests, workspace check, CLI refusals including the non-empty `--out` refusal). |
| `docs/evidence/P11/T-0215-b2r4-red.txt` | The batch-B2 round-4 review items N-1..N-10: one re-created red section per finding (the exact seam of the fix is reverted, the named test is run, the real failure is captured, and the file is restored byte-identically). N-10 is a documentation item and says so with the check that shows the known-limits table. |
| `docs/evidence/P11/T-0215-b2r4-negative-demos.txt` | One mutation demo per N-item: the seam is mutated, the named test fails with the expected message, the file is restored byte-identically and the SHA-256 before = after is recorded. |
| `docs/evidence/P11/T-0215-b2r4-verify.txt` | The green commands on the round-4 tree (nextest, fmt check, clippy `-D warnings`, doctests, workspace check, CLI refusals). The run happened on a Windows host where Smart App Control intermittently blocked freshly built unsigned test executables (`os error 4551`); a local test-signing workaround was used only to execute the test binaries, no repository source file was changed by it, and a clean rebuild regenerates the artifacts. Full detail: `docs/DEVIATIONS.md` ASM-048. |

## Round-2 review items and their tests

| Finding | What changed | Failing test |
| --- | --- | --- |
| Correction | `ReasonCode::DependencyNotMet` removed; `ALL: [ReasonCode; 8]`; dependents `UNVERIFIED(stage_not_reached)` with a detail naming the dependency; `docs/ACCEPTANCE.md` corrected. | `status::tests::the_reason_set_is_closed_and_round_trips_by_code`, `runner::tests::a8_a_dependent_of_a_failed_check_is_unverified_stage_not_reached_naming_the_dependency` |
| R-1 | The 5 x 2 profile/mode matrix in `RunnerConfig::build` and `Connector::new`. | `config::tests::r1_every_profile_mode_pair_is_refused_or_accepted_by_the_specification_table`, `guard::tests::r1_the_connector_enforces_the_profile_mode_matrix` |
| R-2 | Resume re-hashes evidence inside the resume dir, binds the report to `config_revision`/target hosts/24 h age, refuses mismatches; a resumed PASS satisfies dependencies (and the AC-00 gate). | `report::tests::r2_*`, `runner::tests::r2_a_resumed_pass_satisfies_a_dependency_outside_the_plan`, `cli::a_resume_refuses_a_hand_edited_pass_line_with_a_fake_hash`, `cli::a_resume_keeps_a_previous_pass_line_with_matching_binding_and_evidence` |
| R-3 | Constructors `pub(crate)`/sealed; `CheckContext::connector` built by the executor; four `compile_fail` doc-tests. | the `lib.rs` `compile_fail` doc-tests |
| R-4 | Only `EvidenceStore` builds an `EvidenceRef`; the executor re-reads and re-hashes evidence before a PASS. | `runner::tests::r4_a_pass_backed_by_a_real_artifact_is_accepted`, `runner::tests::r4_a_fabricated_evidence_hash_is_turned_into_a_fail` |
| R-5 | Single-use ticket with TTL, digest of verb/path/body/headers, revision re-read at send. | `guard::tests::r5_*` |
| R-6 | Markers handle spaces after the separator and quoted values; since round 4 (N-6) an unquoted value ends at the next delimiter and quotes stay around `[REDACTED]`. | `report::tests::r6_redaction_handles_spaces_quotes_and_tabs` |
| R-7 | Request expiry at send, token spent at send, sender receives pinned addresses. | `guard::tests::r7_*`, `guard::tests::a2_twenty_tokens_spent_through_the_check_context_make_the_next_prepare_refuse` |
| R-8 | Run starts only with AC-00 PASS; run-invalid latch with audit; panics in the `RunReport`. | `runner::tests::r8_*`, `runner::tests::a8_a_failing_ac00_stops_the_run` |
| R-9 | Signal listener primed in the constructor. | `runner::tests::r9_the_signal_listener_is_primed_in_the_constructor` |
| R-10 | Expired grants popped from the front; 300k-grant lab test. | `limits::tests::r10_the_limiter_pops_expired_grants_and_300k_lab_grants_finish_quickly` |
| R-11 | Store refuses overwrite/reserved names/streams; exact 512-byte cap including marker; non-vacuous test. | `report::tests::r11_*`, `report::tests::a7_both_renderers_cap_evidence_after_redaction_on_a_utf8_boundary` |
| R-12 | Redaction on field values before serialisation; short secrets cannot corrupt JSON; Markdown escapes field names and `block.check`. | `report::tests::r12_*` |
| R-13 | Class B implies destructive; one production rule; approval bound to the run id and window. | `guard::tests::r13_a_class_b_send_implies_destructive`, `runner::tests::r13_the_destructive_gate_is_bound_to_the_run_id`, `config::tests::r13_the_approval_is_bound_to_the_run_id_and_the_run_is_refused_otherwise` |

## Round-3 review items and their tests

| Finding | What changed | Failing test |
| --- | --- | --- |
| S-1 | The executor holds the validated profile; `CheckContext::connector()` takes no profile argument. | `runner::tests::s1_a_check_cannot_widen_the_allowlist`, `lib.rs` compile_fail doc-test |
| S-2 | The executor owns the inspect gate; `InspectGate::new`/`check` are crate-internal and `ctx.inspect` is the only way to a ticket. | `runner::tests::s2_the_executor_owns_the_inspect_gate`, `lib.rs` compile_fail doc-test |
| S-3 | `PlannedRequest` carries verb/body/headers; `GET`/`HEAD` need an empty body and matching verb; header CTLs are refused; the header digest is length-prefixed. | `guard::tests::s3_*` |
| S-4 | The AC-00 rule is evaluated before the unmet-dependency skip. | `runner::tests::s4_ac00_with_an_unmet_dependency_stops_the_run` |
| S-5 | One resume path (executor uses `validate_resume`), invalid/future reports refused, AC-00 always re-runs, the verified path is copied, no-MAC limit documented. | `report::tests::s5_*`, `runner::tests::s5_the_executor_uses_the_report_resume_checks`, `runner::tests::r2_a_resumed_pass_satisfies_a_dependency_outside_the_plan` |
| S-6 | `EvidenceRef` fields private; the store records `(check, run, name, hash)` and the executor requires it; non-empty `--out` refused without `--resume`; `Default` removed from the latches. | `runner::tests::s6_evidence_from_another_check_or_run_is_refused`, `report::tests::s6_the_evidence_store_records_check_and_run`, `cli::s6_a_non_empty_output_directory_is_refused_without_resume`, `lib.rs` compile_fail doc-tests |
| S-7 | Markers inside quoted JSON keys, after `_`/`-` suffixes, camelCase, every occurrence and `--flag value`; longest-first exact secrets; `add_secret` refuses short secrets. | `report::tests::s7_*`, `report::tests::r12_short_secrets_do_not_corrupt_the_json_document` |
| S-8 | Every safety-envelope denial latches `run_invalid`; the run stops after the latch. | `guard::tests::s8_every_safety_envelope_denial_marks_the_run_invalid`, `runner::tests::r8_a_guard_denial_marks_the_run_invalid_and_records_the_audit_line` |
| S-9 | A refund keeps the duration clock; the window is closed; a zero rate on a rate lane is refused. | `limits::tests::s9_*`, `limits::tests::r10_*` |
| S-10 | `\r`/backticks escaped in Markdown, console/superscript device names refused, ticket consumed at the end of prepare, `take_cleanup` releases the mutex, `spec()` is caught, the unreachable `check_ticket` early return removed. | `report::tests::s10_*`, `runner::tests::s10_*`, `guard::tests::s10_a_late_prepare_refusal_does_not_consume_the_ticket` |

## Security notes (STRIDE delta for the lead)

* **Elevation / spoofing (target selection):** the target set is derived only from the validated profile, and a non-allowlisted
  target aborts before the send seam; the guard is tested with a recording sender before a real sender exists (A1).
* **Tampering (evidence):** saved logs are hashed over the bytes written and the report embeds the hash and tail; the renderer
  refuses an unbacked PASS, so a hand-edited status line cannot produce a green report.
* **Information disclosure:** evidence is bounded at 512 bytes and redacted before saving; planted secrets are tested absent
  from both report formats and from the saved log; SHA-256 digests are deliberately not treated as secrets.
* **Denial of service (self-inflicted):** one shared limiter with hard ceilings, the check timeout, the kill switch and the
  latched switch stop a runaway check; a refusal never consumes budget.
* **Repudiation:** every report records the mode, stage, load profile, vantage count and the notes that explain what did not
  run; remaining checks after an abort are `UNVERIFIED(skipped_by_operator)` rather than omitted.
* **Hostile input:** report parsing is bounded (4 MiB, unknown fields refused), profile parsing reuses the budgeted YAML
  parser, and proptest covers report parsing, the redactor and `tail_lines`, which never panic on arbitrary bytes.

## Round-4 review items and their tests

| Finding | What changed | Test |
| --- | --- | --- |
| N-1 | The run-invalid latch stores `(check id, run id, detail)`; `prepare` and `send` refuse once it is set (`Denial::RunInvalid`); the check that trips it ends `FAIL(run invalid: <denial>)`; the report names the check in JSON and Markdown (`Report::apply_run_report`); the CLI writes the report and exits 3. | `guard::tests::n1_the_run_invalid_latch_stops_prepare_and_send`, `runner::tests::n1_the_check_that_trips_the_latch_ends_fail_run_invalid`, `report::tests::n1_the_report_carries_the_run_invalid_record_into_json_and_markdown`, `cli::n1_an_invalid_previous_run_is_refused_with_code_3` |
| N-2 | `InspectRequest::for_attempt` carries the headers, cookies and body (UTF-8 text or base64 when not UTF-8, spec T-0260) to the inspect API; the digest remains the ticket binding; a body over 64 KB is refused before any ticket or send. | `guard::tests::n2_the_inspect_request_carries_content_and_the_body_cap_is_refused` (including a non-UTF-8 body described as base64 and a digest that changes with the body) |
| N-3 | One shared `report::select_resumed_lines` used by both `Report::resume_with` (CLI) and `Executor::set_resume`; AC-00 is always excluded and always re-runs. | `report::tests::a8_resume_keeps_pass_lines_and_reruns_everything_else`, `report::tests::n4_resume_copies_evidence_and_resume_twice_keeps_the_line_age`, `cli::a_resume_keeps_a_previous_pass_line_with_matching_binding_and_evidence` (AC-00 stays UNVERIFIED in the resumed JSON) |
| N-4 | Resumed evidence is copied into the new run directory and the line points at the copy; each line keeps its original timestamp and the 24 h age limit is applied per line; a chain of resumes cannot extend it; `--out` must be a new/empty directory and resuming in place is refused. | `report::tests::n4_resume_copies_evidence_and_resume_twice_keeps_the_line_age`, `cli::n4_resuming_in_place_is_refused`, `cli::a_resume_keeps_a_previous_pass_line_with_matching_binding_and_evidence` (the copied artifact exists in the new run directory) |
| N-5 | Redaction covers escaped nested JSON, uppercase no-separator names (`DBPASSWORD`, `AWSSecretAccessKey`), escaped quotes in quoted values, and URL-encoded, `\/`-escaped and base64 forms of exact secrets; `Redactor::with_secrets` returns the length error and the CLI (`--redact-secret`) propagates it; evidence paths, `config_revision` and field names are redacted in the renderer. | `report::tests::n5_escaped_uppercase_and_encoded_secret_forms_are_redacted`, `report::tests::n5_the_renderer_redacts_evidence_paths_and_the_config_revision`, `cli::n5_a_short_redact_secret_is_a_usage_error` |
| N-6 | An unquoted value ends at the next delimiter (space, `,`, `&`, `;`, `}`, `]`), except behind a `Bearer`/`Basic` scheme word; secret field names are matched as whole tokens split on `_`/`-`/camelCase; the line is lowercased once (linear); each embedded tail line is capped at 2 KB after redaction; quotes stay around `[REDACTED]` and the redacted JSON stays valid. | `report::tests::n6_delimiters_bearer_and_valid_json`, `report::tests::n6_redaction_is_linear_on_one_megabyte` |
| N-7 | `Executor::from_config(RunnerConfig, ...)` is the only public builder; it derives the profile, stage, run profile, lifecycle, run id, gate revision, revision source and resume binding in one place, and refuses a limiter profile mismatch, a lifecycle-stage mismatch, an empty revision or a revision source that disagrees. | `runner::tests::n7_from_config_refuses_mismatches` |
| N-8 | Sender-owned headers (`Content-Length`, `Transfer-Encoding`, `Host`, `Expect`, `Upgrade`, `Connection`, `X-HTTP-Method-Override`) are denied; at most 64 headers / 8 KB are accepted; values with leading/trailing whitespace are refused. | `guard::tests::n8_sender_owned_headers_and_header_caps_are_refused` |
| N-9 | Tests that could not fail were fixed: the S-5 resume test now proves the selector reuses exactly one non-self-test PASS (a selector that reuses nothing, or one that wrongly reuses AC-00, fails it), the closed-window cadence has explicit 999 ms / 1000 ms / 1001 ms cases, and the compile-fail snippets are checked for their exact error code. rustdoc's `compile_fail` has no error-code form (a `compile_fail,EXXXX` annotation is ignored, so the doctest would pass on any compile error); the exact codes are asserted by the `tests/compile_fail_codes.rs` integration test, which compiles each crate-root snippet with the same compiler and requires `error[E0624]`, `E0061`, `E0451` or `E0277` (review item N-9; the eight doctests still prove "does not compile"). | `runner::tests::s5_the_executor_uses_the_report_resume_checks`, `limits::tests::s9_a_closed_one_second_window_cannot_contain_two_allowances`, `compile_fail_codes::the_compile_fail_doctests_fail_for_their_exact_error_code`, the eight `lib.rs` doc-tests |
| N-10 | This section: the known limits and the threat model. | `docs/ACCEPTANCE.md` (this section) |

## Known limits (review item N-10)

The threat model is **a check written by us that makes a mistake, not a hostile check** (round-3 scope note). The
crate-private constructors and the latch/state checks below are compile-time and runtime **guards against accidental misuse**;
they are not a security boundary against code compiled into this crate.

| Limit | What is not covered | Why it is accepted |
| --- | --- | --- |
| Forged `report.json` on `--resume` | The resume binding (`config_revision`, host names, mode/stage/profile, timestamps) is self-asserted JSON with **no MAC**, and the per-line evidence record is not cryptographically bound to a check or run (the executor's `(check, run, name, hash)` records are in memory only). A deliberate forger who can rewrite the JSON can therefore make a stale or edited report look resumable. | The goal is to refuse stale/accidentally edited reports; signing the report needs a key and a spec decision, which is out of scope for this skeleton (documented, not claimed). |
| A check obtaining the `EvidenceStore` clone | `EvidenceStore` is `Clone` and shared so a check can save evidence; a check that saves a reference and returns it under another check id is refused by the executor's records, but code inside the crate could clone the store and write records directly. | The threat model is accidental misuse; the executor still re-reads and re-hashes every file and requires the `(check, run, name, hash)` record, and a hostile in-crate check is outside the guarantee. |
| A check calling `ctx.abort().trip()` | `CheckContext::abort()` exposes the run's abort latch; a check can deliberately trip it (stopping the run as if the operator or kill switch did). | Exposed so a check can run cleanup-aware code and honour an abort; a deliberate self-abort is a check bug or hostility, both outside the accidental-misuse guarantee. |