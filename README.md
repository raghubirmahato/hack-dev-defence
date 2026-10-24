# Hack Dev Defence (HDD)

A self-hosted **web application firewall + authoritative DNS + TLS-terminating reverse proxy**, with a complete web product around it (public site, sign-up and login with
MFA and passkeys, customer dashboard, per-domain security controls, platform admin panel), written in Rust and designed to keep protecting a site even when the origin
application itself is vulnerable.

**Status: foundation only.** The repository contains the governed workspace, the full build specification split into loadable pieces, one detailed file per task (599),
and the state files. This paragraph predates the HK1 hackathon track: the HK1 vertical slice described in [HK1 demo quickstart](#hk1-demo-quickstart-local-rehearsal) below is
now implemented in `crates/hdd-waf-core`, `crates/hdd-proxy`, `lab/demo/` and `scripts/`. Nothing here is a general security claim (specification section 4); the HK1
section states exactly what was demonstrated and what is still unverified.

## HK1 demo quickstart (local rehearsal)

The HK1 track builds one vertical slice: **a reverse proxy with an SQL-injection
detector that blocks injection on a login page**. It ships with a lab-only,
deliberately vulnerable login app so the whole slice can be rehearsed end-to-end on one
machine, and so the operator can point the same proxy at their own site afterwards.

Prerequisites: **Node.js 18+**, **Rust (cargo)** and **Python 3** for the lab origin.
No `npm install` is needed: the root `package.json` is private and has no dependencies.

```bash
npm run dev
```

One terminal starts, colour-labels and stops (Ctrl+C) all three parts:

| URL | Part | Notes |
| --- | --- | --- |
| `http://127.0.0.1:8081/login` | deliberately vulnerable lab origin | **lab only, loopback only, never expose**; SQL injection really works here |
| `http://127.0.0.1:8080/login` | HDD proxy (SQLi detector) | `demo/hdd-dev.yaml` (default port; the launcher prints the run endpoint), mode `block`; blocked requests get the block page + Ray ID and a ban |
| `http://127.0.0.1:9090/` | dashboard / admin UI | default port, printed by the launcher; first run: create the owner account at `/setup`; events, bans, mode switch |

The dev banner prints the three URLs, the `/setup` link, the /health checks, a one-line
attack command, and the lab app's randomly generated seed credentials (they change on
every start). The admin bootstrap token is generated for the dev run and printed masked;
the full local value is written to `hdd-data/dev-admin-token.txt` (git-ignored). The
stack is loopback-only. `cargo-watch`, if installed, restarts the proxy when
`crates/**` changes; otherwise the log says live reload is unavailable.

If proxy port **8080** or admin port **9090** is already held by another process (on the
HK1 build machine MiniTool ShadowMaker's `MTAgentService` holds TCP 8080), `npm run dev`
keeps the committed `demo/hdd-dev.yaml` unchanged, writes a generated profile for that run
under `hdd-data/`, uses the first free fallback pair (18080/19090, then 18081/19091, ...)
and prints one clear line with the actual URLs. `npm run attack` follows the endpoints of
the last dev run automatically, so the attack commands below keep working.

```bash
npm run attack                                     # through HDD: expect 403 + Ray ID + ban for all 12 payloads
npm run attack -- --target http://127.0.0.1:8081   # direct origin: which payloads reach /admin without HDD
npm run demo                                       # dev + the four scripted walkthrough observations
npm run tunnel                                     # demo only: public URL for the front-door demo (needs the OpenSSH client)
npm test                                           # node launcher tests + cargo fmt --all --check + clippy -D warnings + nextest
npm run lint                                       # node/lab-app/attack-script syntax + cargo fmt + clippy
npm run build                                      # cargo build (default members; lab/vulnlab excluded by rule)
```

**Front-door demo (Addendum 7).** `npm run tunnel` puts the loopback HDD proxy on the
internet through the free localhost.run SSH tunnel, prints `HDD_GATE_URL=...` and keeps it
warm with an 8 s `/healthz` heartbeat, so a Vercel app can keep its own address and still
have HDD decide every request (steps in [docs/DEMO.md](docs/DEMO.md), routing rules in
[OPERATIONS.md](OPERATIONS.md)). Treat it as demo-only: the tunnel is temporary, it
exposes the loopback proxy to the internet while it runs, the free service hands out a
new URL on every restart (update `HDD_GATE_URL` in Vercel and redeploy), and the permanent
answer for a live site is hosting HDD on a server. The helper never reads or prints
environment values or secrets.

The attack scripts (`lab/demo/attack.ps1` on Windows, `lab/demo/attack.sh` on
Linux/macOS) send only the 12 demo payloads (the six mandated SQLi payloads M1-M6 plus
the six auth-bypass forms) to the login endpoint, as login POSTs and GET query strings,
rate-capped at 2 req/s. They **refuse any non-loopback target host that is not listed in
`lab/demo/targets.allow`** (operator-created, one host per line; loopback is always
allowed) and never scan, never use another attack class and never touch a third-party
host. The vulnerable app and the scripts are lab-only and are not part of any shipped
binary.

The full 10-minute demo script, the Mermaid architecture picture, the known limitations,
the live-site checklist and the Vercel/serverless origin note are in
[docs/DEMO.md](docs/DEMO.md). Deployment examples (TLS terminator, origin lockdown,
Vercel edge middleware, systemd unit) are in `deploy/`.

**Honest limits.** This is not a claim that any live site is fully protected or secure.
The local stack is a rehearsal on loopback; the Rust gates are the authority for the
Rust crates; a site is not protected while its origin can be reached directly; and SQL
injection remains a bug in the origin application that HDD shields but does not fix
(virtual patch, R-11). The live-site details listed in `docs/DEMO.md` are still needed
from the operator before any live claim.

## State files (read these first)

| File | Purpose |
| --- | --- |
| [AGENTS.md](AGENTS.md) | Digest (at most 150 lines): rules, commands, current position, stop conditions |
| [STATUS.md](STATUS.md) | Current phase, task table, open risks, open questions, UNVERIFIED list |
| [HANDOFF.md](HANDOFF.md) | What the last session did, next 10 tasks, resume commands |
| [INDEX.md](INDEX.md) | All 599 tasks in execution order |
| [docs/DEVIATIONS.md](docs/DEVIATIONS.md) | Deviations and assumptions |
| [ARCHITECTURE.md](ARCHITECTURE.md) | Crate ownership and structural rules |
| [OPERATIONS.md](OPERATIONS.md) | Developer commands and (later) operator settings |

## Reading the spec

The specification is about 24,970 lines (2.4 MB) and is never held in context whole (spec section 0.1).

- `docs/SPEC.md` is the verbatim copy; its sha256 is in `docs/SPEC.sha256`. Do not edit it.
- `docs/spec/<id>.md` are the 59 pieces, cut at the `<!-- PART:id -->` and `<!-- PHASE:id -->` markers. `docs/spec/MANIFEST.tsv` lists them in order;
  concatenated in that order they reproduce `SPEC.md` byte for byte. `docs/spec/INDEX.md` maps every `T-nnnn` to its file and line.
- `docs/tasks/Pnn/T-nnnn.md`: one file per task with its metadata (phase, tags, dependencies, dependents, execution order, requirement ID, first delivery slice),
  the verbatim task block, the definition of done for its tags, the per-task protocol checklist and an evidence log.
- `docs/phases/Pnn.md`: phase goal, requirement prefix, gate pass condition and task table. `docs/gates/`: gate table and the report template.
- Parts: A (constitution, `A0`-`A2`), B (product definition, `B1`-`B6`), C (security architecture, `C1`-`C6`), D (the tasks, `D` + `P00`-`P34`), E (appendices, `E1`-`E15`).
- Session start: AGENTS.md, STATUS.md, HANDOFF.md, `git status`, `docs/spec/A0.md` once, then the phase file and the task in hand.

## Layout

See [ARCHITECTURE.md](ARCHITECTURE.md) section 5. Crates are in `crates/`; the Vuln-Lab (`lab/vulnlab`) is lab-only and is never part of a default build or a release.

## Build and check

```bash
cargo check --workspace
cargo clippy --workspace --all-targets -- -D warnings
cargo fmt --all --check
cargo deny check
cargo xtask verify                                 # the whole pipeline (T-0005); logs and sha256 under acceptance-verify/
```

Configuration: copy `hdd.live.example.yaml` to `hdd.live.yaml` (git-ignored) and `.env.example` to `.env` (git-ignored). Never put secret values in the profile; it holds
environment-variable names only.

## Safety

HDD is a security tool. It may only be pointed at domains, hosts and networks its operator owns; attack-shaped test traffic goes only to the allowlist derived from the live
profile; volumetric tests exist only in a closed lab. Read specification section 2 (`docs/spec/A1.md`) before running anything.
