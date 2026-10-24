# Where to find what in the split specification

The registries are seed catalogs inside the split files (no copy is kept here, so there is exactly one source of truth). Look up by ID with a search, for example
`grep -rn "ERR-AUTH-" docs/spec/`. A task that needs a new entry adds it to the registry in the same change (section 0.9); `xtask names check` (later) enforces this.

## Section to file map

| Section | Content | File |
| --- | --- | --- |
| 0 | How to read, loading strategy, roles, status taxonomy, task lifecycle, definition of done by tag, milestones, slices, conventions, glossary | `docs/spec/A0.md` |
| 1 to 4 | Role and vision, safety envelope (2.1 to 2.11), execution rules R-01 to R-34, claims policy | `docs/spec/A1.md` |
| 5 to 9 | Rust-first policy, technology stack, repository layout, live profile (`hdd.live.yaml`), first response protocol | `docs/spec/A2.md` |
| B1 to B4 | Personas, information architecture, user journeys (B3), roles and permissions (B4, `PERM-`) | `docs/spec/B1.md` |
| B5 | Data model (PostgreSQL) and Redis keys | `docs/spec/B2.md` |
| B6 | API catalog | `docs/spec/B3.md` |
| B7 to B10 | Error catalog (`ERR-`), audit events (`AUD-`), metrics (`MET-`), configuration (environment variables) | `docs/spec/B4.md` |
| B11, B13 | Design system specification, copy deck | `docs/spec/B5.md` |
| B12 | Screen catalog (`S-nnn`) | `docs/spec/B6.md` |
| C1 to C4 | Defense in depth, request lifecycle, Vulnerable-Origin Shield, SQL injection doctrine | `docs/spec/C1.md` |
| C5 | Attack coverage matrix (`ATK-001` to `ATK-390`) | `docs/spec/C2.md` |
| C6 to C10 | Ban/jail/appeal, challenge and bots, data protection, hardening baseline, STRIDE summary | `docs/spec/C3.md` |
| C11 to C17 | Volumetric DDoS, application bugs, DNS, proxy and TLS, kernel firewall, tooling, integration modes | `docs/spec/C4.md` |
| C18, C19 | Runtime profiles (local and hosted), defense completeness (access gate, API discovery, business flows, coverage map) | `docs/spec/C5.md` |
| C20 to C22 | Sentinel (learned detection), Bypass Guard, known-vulnerability coverage | `docs/spec/C6.md` |
| D | The 599 tasks: preamble in `D.md`, one file per phase `P00.md` to `P34.md` | `docs/spec/D.md`, `docs/spec/Pnn.md` |
| E1, E2 | Fixtures and payload seeds; benign corpus specification | `docs/spec/E1.md`, `docs/spec/E2.md` |
| E3 | Acceptance matrix `AC-00` to `AC-62` | `docs/spec/E3.md` |
| E4 to E6 | Default numeric thresholds, gate report template and gate table, hostile review checklists | `docs/spec/E4.md` |
| E7, E8 | Canonical names registry, open questions for the operator | `docs/spec/E7.md` |
| E9 to E12 | Delta from v4.1, risk register, cutover and release checklists, requirement traceability | `docs/spec/E9.md` |
| E13, E14 | Milestones/phases/gates matrix and delivery slices, generated task index | `docs/spec/E13.md` |
| E15 | Coverage map | `docs/spec/E15.md` |

## Identifier families (counts measured by regular expression on 2026-10-18; indicative, not a substitute for the registries)

| Family | Pattern | Distinct IDs found | Range |
| --- | --- | --- | --- |
| Tasks | `T-nnnn` | 599 | T-0001 to T-0599 (exact, checked against E14) |
| Attack classes | `ATK-nnn` | 390 | ATK-001 to ATK-390 |
| Acceptance checks | `AC-nn` | 63 | AC-00 to AC-62 |
| Journeys | `J-nn` | 34 | J-01 to J-34 |
| Screens | `S-nnn` | 142 referenced (139 rows in the B12 table) | S-001 to S-148 |
| Error codes | `ERR-<AREA>-nnn` | 119 | |
| Audit events | `AUD-<area>.<verb>` | 90 | |
| Metrics | `MET-<name>` | 127 | |
| Permissions | `PERM-<area>.<verb>` | 101 | |
| Operator questions | `Q-nnn` | 58 | Q-001 to Q-058 |
| Hosting checks | `HC-nn` | 23 | |

**Open reconciliation (for T-0011 / T-0053):** gate G03 says "all 143 screens", while the counts above find 139 table rows and 142 referenced IDs. The screen catalog is the authority;
the first UX task that lists the screens must reconcile the number and record the result in `docs/DEVIATIONS.md` if it differs.
