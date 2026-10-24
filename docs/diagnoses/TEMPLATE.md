# Diagnosis <task>-<n>: <short symptom>

Created on the third failed fix attempt for the same check (failure budget R-14, Appendix E5.3). The failure counter resets only when a root cause is recorded here.

- Task / check: T-nnnn / AC-nn or test name
- State set: `blocked(<reason>)`
- Date:

## Symptom

What fails, exactly, and where.

## Evidence

Exact commands and outputs (tails), log paths and sha256.

## Hypotheses tried

| # | Hypothesis | What the attempt changed | What was observed |
| --- | --- | --- | --- |
| 1 | | | |
| 2 | | | |
| 3 | | | |

## Options for the operator

| Option | Cost | Risk | Notes |
| --- | --- | --- | --- |

Recommended option:

## What unblocks the task

A fix never loosens a test, threshold or safety limit. The agent moves to the next unblocked task whose dependencies are met; this task stays listed as blocked in `STATUS.md`.
