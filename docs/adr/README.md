# Architecture Decision Records

An ADR makes a design decision explicit, reviewable and scheduled (T-0008).

**When an ADR is required.** Before adding any crate that is FFI, unmaintained for over a year, or has `unsafe` in its public API (R-08). Always for
a substitution of a fixed stack choice in section 6. The queue in [INDEX.md](INDEX.md) names the task that decides each one.

**Lifecycle.** `proposed` (queued) -> `spiking` (a time-boxed experiment, linked) -> `accepted` (decision plus consequences, security impact and rollback plan
filled in, spike link or stated reason present) -> optionally `superseded by ADR-NNNN`. Numbers are monotonic and never reused.

**How to propose.** Copy [0000-template.md](0000-template.md) to the next free number, fill every section, add a row to [INDEX.md](INDEX.md). When an ADR is
`spiking`, link its number in the Open risks table of `STATUS.md`.

**Dependency-vetting lint (not built yet).** T-0008 step 5 adds a check to `cargo xtask verify` that flags a new dependency in a `Cargo.toml` without an ADR
reference or vetting note. Until T-0005 and that lint exist, reviewers apply the rule by hand.
