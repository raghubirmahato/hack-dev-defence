<!-- Appendix E5.1 gate report template, verbatim. Copy to docs/gates/Gnn.md. -->
# Gate Gnn: <phase name>

- Phase / milestone: Pnn / Mx   - Commit: <git sha>   - Date: <UTC>   - Author role: <agent role>
- Environment: stage=<pilot|production> mode=<live|lab|ci> host=<id> kernel=<uname -r> toolchain=<rustc -V>

## 1. Commands run (with output tails)
| # | Command | Exit | Output tail (last 20 lines) | Full log sha256 |
| --- | --- | --- | --- | --- |

## 2. Acceptance criteria
| Task | Criterion | Status | Evidence ref | Notes |
| --- | --- | --- | --- | --- |
(one line per criterion A1..A5 of every task in the phase)

## 3. Acceptance checks (AC-xx) touched by this phase
| Check | Status | Reason code if UNVERIFIED | What the operator must supply | Evidence |

## 4. Metrics
rust-share | tokei totals | test count | coverage (lines/branches) | mutation score | clippy | audit | deny | vet | unsafe-scan | claims-lint | docs-test | a11y violations | perf deltas

## 5. Deviations and assumptions
New or changed entries in docs/DEVIATIONS.md (id, reason, approver, expiry) and assumptions made.

## 6. UNVERIFIED register
Every UNVERIFIED with its reason code and the exact operator action that resolves it.

## 7. Findings
| Id | Severity | Area | Summary | Status (fixed / accepted-with-owner / open) | Link |

## 8. Risks and open questions
Top 5 risks with mitigation; questions awaiting the operator.

## 9. Rollback
How this phase's changes (migrations, config, units) are rolled back and the test that proves it.

## 10. Next steps
Next 10 tasks (ids and titles) and their blockers.
