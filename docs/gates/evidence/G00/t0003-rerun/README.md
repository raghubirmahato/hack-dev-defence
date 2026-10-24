# T-0003 re-run (2026-10-19)

The session-1 discovery script (removed with `tools/bootstrap/`, DEV-V5-000, sha256 8ed40d5dfca54f32034beaaf478cb51ab1e16c9e75e33440ca43e405058d60a3) was run twice from a copy in the
session scratchpad, outside the repository, so that `docs/ENV.md` and `acceptance-env/` were not touched. Read-only commands only (the script's own header).

- `run1-vs-run2.txt`: the 35 per-item logs of the two runs are byte-identical (`diff -r`), and `run1-SHA256SUMS` equals `run2-SHA256SUMS` (T-0003 test: "outputs identical except timestamps").
- `run2-ENV.md` against the committed `docs/ENV.md` (session 1): the differences are exactly the tools installed after vetting (cargo-vet 0.10.2, tokei 15.0.0, cargo-geiger 0.14.0, now PASS),
  the rustup listing order, free disk space and the NTP last-sync time. Nothing else changed; every non-PASS row still has its degradation statement (A3).
- No outbound request was made (A4); no secret appears in the logs (A5; the secret-scan step covers this directory).
