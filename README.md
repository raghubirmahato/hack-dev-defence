# Hack Dev Defence (HDD)

**A reverse-proxy web application firewall that sits in front of your site, reads every request before your application does, and blocks SQL injection, attack tools and request floods, with an honest answer to the question "is my site actually protected right now?"**

HDD is written in Rust. It ships a pure detection library (`hdd-waf-core`), a reverse proxy with an admin API and a built-in web panel (`hdd-proxy`), and the tooling to put it in front of a real site, including sites on serverless hosts such as Vercel.

> HDD makes no general security claim. Every statement below is tied to something this repository tests or measures, and the [known limitations](#known-limitations) section says what is not covered. Detection is one layer; it does not replace fixing the vulnerable code.

---

## Contents

1. [How it works](#how-it-works)
2. [The request pipeline](#the-request-pipeline)
3. [Benefits](#benefits)
4. [Protecting a serverless site: the front door](#protecting-a-serverless-site-the-front-door)
5. [Honest protection state](#honest-protection-state)
6. [Quick start](#quick-start)
7. [The web panel](#the-web-panel)
8. [Repository map](#repository-map)
9. [Testing and verification](#testing-and-verification)
10. [Known limitations](#known-limitations)
11. [Safety rules](#safety-rules)

---

## How it works

```
                          ┌─────────────────────────────────────────────────────┐
                          │                      HDD proxy                      │
                          │                                                     │
  Browser / curl /        │  1 route by host        5 inspect   ┌─────────────┐ │        ┌──────────────┐
  scanner / bot  ───────► │  2 ban check            (waf-core)  │  verdict:   │ │ allow  │              │
                          │  3 rate guard   ──────►  normalize  │  allow /    │ ├──────► │  your origin │
                          │  4 read body            tokenize    │  monitor /  │ │ pooled │  (shop, API, │
                          │    (size capped)        H1–H8 rules │  block      │ │ + secret│   app)       │
                          │                         field policy└──────┬──────┘ │ header │              │
                          │                                            │ block  │        └──────────────┘
                          │   events (JSONL) ◄── bans ◄── findings ◄───┘        │
                          │        ▲                                            │
                          │        └──── admin API + web panel (loopback) ──────┤
                          └─────────────────────────────────────────────────────┘
```

HDD is a **reverse proxy**. Clients talk to HDD; HDD talks to your origin. Because every request passes through one place, HDD can decide *before your application sees the request* whether the request looks like an attack.

The pieces:

| Piece | Where | What it does |
| --- | --- | --- |
| **Detector** | `crates/hdd-waf-core` | A pure function: request fields in, verdict out. No network, no state, easy to test. |
| **Proxy** | `crates/hdd-proxy` | Accepts connections, runs the pipeline, forwards allowed requests over pooled keep-alive connections, writes events, serves the block page. |
| **Admin API + panel** | `crates/hdd-proxy` (embedded) | Sites, modes, events, bans, findings, users, the verify-protection check. The panel is the same API under the same authorisation. |
| **Front door** | `lab/demo/shop` (wrapper), `scripts/hdd-tunnel.mjs`, `scripts/hdd-live.mjs` | Lets a serverless site keep its normal public address while traffic is steered through HDD. |

## The request pipeline

For each request, in order:

1. **Route.** The site is chosen by the `Host` header, or by `X-HDD-Gate-Host` when the request arrives through the front door (honoured only from trusted proxies).
2. **Ban check.** A client that earned a ban receives the block page immediately. Bans are explainable (rule, field, redacted evidence, TTL step) and expire on a ladder of increasing durations.
3. **Rate guard.** A per-client limiter (600 requests per 10 seconds by default) answers `429` to floods before any parsing work is spent on them.
4. **Read the body**, with a size cap. Nothing outbound or inbound is unbounded.
5. **Inspect** with `hdd-waf-core`:
   - **Extract** every value the request carries: query string, form fields, JSON bodies, cookies, selected headers.
   - **Normalise**: URL-decode (repeatedly), strip comments and inline-comment obfuscation, fold case, collapse whitespace, decode common encodings.
   - **Tokenise** the result into SQL-shaped tokens rather than matching raw strings, so `UN/**/ION SEL%45CT` and `UNION SELECT` produce the same tokens.
   - **Rule families H1–H8** score token patterns: tautologies and false probes, `UNION` extraction, stacked queries, blind and time-based probes, error-based extraction, comment truncation, encoded and function-call forms.
   - **Field-kind policy** adjusts strictness by what the field is. `Balanced` tolerates attack-shaped text in password fields (a password may legitimately contain `' or 1=1 --`); `Paranoid` blocks it. Search boxes and ids are always strict.
   - **Attack-tool rule** (T1-001) recognises well-known scanner and exploit-tool user agents.
6. **Apply the site mode.**
   - `off`: forward everything, record nothing as blocked.
   - `monitor`: forward everything, record what *would* have been blocked.
   - `block`: stop attack-shaped requests, serve the block page with a Ray ID, record the event and escalate the ban ladder.
7. **Forward** allowed requests to the origin on a pooled connection (64 per origin, 20 s idle, safe retry of idempotent requests on a stale socket), adding the origin secret header when one is configured.
8. **Record.** Events go to an append-only JSONL log. Evidence is capped at 512 bytes and redacted; request bodies are never logged in full.

## Benefits

- **It protects an origin that is still vulnerable.** Fixing every injection point in a codebase takes time. HDD sits in front and stops the attack-shaped requests while that work happens. The vulnerability stays open until you patch it; HDD reduces exposure in the meantime and says so.
- **Blocks are explainable.** Every block and ban records which rule fired, in which field, with redacted evidence, and what the ban ladder did next. You can answer "why was this blocked?" from the panel, not from guesswork.
- **Honest about its own state.** The panel never shows "protected" while the origin can still be reached directly. See [honest protection state](#honest-protection-state).
- **Safe to adopt.** `off` → `monitor` → `block` lets you watch real traffic and false positives before enforcing. Blocking requires a verified lockdown or a typed, audited risk acceptance.
- **Low overhead.** Detection is a pure in-process function; upstream connections are pooled and kept alive. The measured proxy overhead on the local benchmark was about 6 % (see `docs/evidence/HK1/proxy-bench.txt`; your numbers will differ).
- **Covers more than SQL injection payloads.** Attack-tool user agents, scanners and floods are handled by separate guards, so a noisy tool is stopped before it can try thousands of payloads.
- **Self-contained.** The panel loads its fonts, scripts and styles from itself. It makes no third-party requests, and every response carries `Cache-Control: no-store`, so nothing from the panel is kept by a browser.
- **No secrets in the repository.** Admin tokens, origin secrets and API keys come from environment variables or are generated into git-ignored files. The optional DeepSeek explanation feature reads its key from `DEEPSEEK_API_KEY` only and never decides a block.
- **One code path.** There is no hidden "dev mode" with different decisions; the local rehearsal and a real deployment run the same pipeline.

## Protecting a serverless site: the front door

A site on a serverless host (for example Vercel) cannot sit behind a reverse proxy you run, because its public address belongs to the host. The front door solves this without moving the address:

```
 visitor ──► https://your-site.example  (host's edge, unchanged)
                  │
                  ▼
        small wrapper in your app  ──── X-HDD-Gate-Host ───►  HDD proxy ──► your app's real handler
        (pasted from the panel)                               (inspect, ban,
                                                               rate-limit)
```

- The panel generates a snippet for your framework (Node `module.exports`, ESM `export default`, Next.js `middleware`). You paste it once.
- The wrapper forwards requests to HDD, which inspects them and forwards the clean ones back with the origin secret header. The wrapper's handler only accepts requests that carry that secret once the lock is enabled, so a direct hit on the origin address is refused.
- If HDD is unreachable the wrapper **fails closed** (`503`) by default; `HDD_FAIL_OPEN=1` is an explicit opt-in for sites that prefer availability.
- For development, `npm run live` starts the proxy, opens a tunnel and publishes the tunnel address to a registry the wrapper reads, so the stack survives tunnel restarts.

## Honest protection state

HDD reports one of these per site and never rounds up:

| State | Meaning |
| --- | --- |
| **Off** | Requests pass through uninspected. |
| **Monitoring** | Attacks are detected and logged, not blocked. |
| **Blocking, not locked** | Requests that go through HDD are blocked, but the origin can still be reached directly, so a determined client can bypass HDD. Shown as *not protected*. |
| **Blocking, locked** | Blocking is on **and** a lockdown check proved that a direct request to the origin is refused. |

The **Verify protection** action sends harmless probes first, then attack-shaped probes to your own site, and reports pass or fail for each of three checks. A site is shown as protected only after they pass.

## Quick start

Requirements: **Node.js 18+**, **Rust (cargo)**, and Python 3 for the vulnerable lab origin. There are no npm dependencies to install.

```bash
npm run dev
```

This starts, colour-labels and stops together:

| URL | Part |
| --- | --- |
| `http://127.0.0.1:8081/login` | deliberately vulnerable lab origin (lab only, loopback only, never expose) |
| `http://127.0.0.1:8080/login` | HDD proxy in `block` mode |
| `http://127.0.0.1:9090/` | web panel; first run: create the owner account at `/setup` |

If a port is taken, the launcher picks the next free pair and prints the real URLs.

```bash
npm run attack                                     # through HDD: expect 403 + Ray ID for every payload
npm run attack -- --target http://127.0.0.1:8081   # direct to the lab origin: see what gets through without HDD
```

To protect your own site, add it in the panel (**Sites → Add site**), choose a mode, follow the lock steps for your host, then run **Verify protection**. To run the live stack with a tunnel for a serverless site:

```bash
npm run live
```

The step-by-step demo script (what to show, what to say, what the results mean) is in [docs/DEMO.md](docs/DEMO.md). A demo result is a measurement on a lab or on your own site, not a claim that any site is fully protected: a site counts as protected only when the panel's verify check says so.

A production-style deployment (reverse proxy in front, systemd unit, origin lockdown examples) is described in [OPERATIONS.md](OPERATIONS.md); example files live in `deploy/`.

## The web panel

Overview (counters, per-site state, guards), Events, Bans, Sites (add, mode, strictness, lock steps, verify), Console (inspect a request without sending it), Block page editor, Account, Users and roles, About. It is keyboard-operable, has light and dark themes, and works down to phone width. Everything the panel does is an admin API call under the same authorisation.

## Repository map

| Path | Contents |
| --- | --- |
| `crates/hdd-waf-core` | The detector: extract, normalise, tokenise, rule families, field-kind policy, explanations. |
| `crates/hdd-proxy` | Proxy, pipeline, ban ladder, rate guard, pooled forwarding, admin API, accounts, site wizard, lock snippets, embedded panel (`src/ui/`). |
| `crates/hdd-common`, `hdd-canary`, `hdd-acceptance`, others | Shared egress guard, acceptance tooling and the wider product crates from the build specification (most are not part of the demo track). |
| `lab/demo/shop` | The demo shop (computer hardware store) and the front-door wrapper. Fake data only. |
| `lab/` | Lab-only, deliberately vulnerable applications. Never shipped. |
| `scripts/` | `dev`, `demo`, `attack`, `live`, `tunnel`, test runners. |
| `deploy/` | Caddy, nginx and systemd examples, origin lockdown example. |
| `docs/` | Specification, ADRs, evidence under `docs/evidence/`, deviations, UX charter. |
| `xtask` (`crates/hdd-xtask`) | The verification gate: `cargo xtask verify`. |

Architecture notes: [ARCHITECTURE.md](ARCHITECTURE.md). Operations: [OPERATIONS.md](OPERATIONS.md). Security policy: [SECURITY.md](SECURITY.md).

## Testing and verification

```bash
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test -p hdd-waf-core -p hdd-proxy
npm run test:scripts          # launcher, tunnel and front-door scripts
cargo xtask claims-lint       # wording rules for security claims
cargo xtask verify            # the full gate
```

- The detector is tested against a corpus of attack payloads and a corpus of benign inputs (names, addresses, prose containing SQL words) so that widening detection cannot silently start blocking normal use.
- The proxy and panel have integration tests that start a real instance, and browser-driven checks run the panel in headless Chrome (layout, tap targets, contrast, no-cache headers, no third-party requests).
- Evidence from real runs (benchmarks, curl vectors, live end-to-end results) is kept in `docs/evidence/`. A check that cannot run ends `UNVERIFIED(reason)`; it is never reported as passing.

## Known limitations

- HDD inspects HTTP requests it receives. Traffic that reaches the origin another way is not inspected, which is why lockdown verification exists.
- Detection is heuristic. Novel encodings can be missed and unusual benign input can be flagged; use `monitor` first and review events.
- The detector targets SQL injection and known attack tools. Other classes (XSS, SSRF, path traversal, business-logic abuse) are not covered by the demo-track detector.
- Volumetric denial-of-service needs capacity upstream of any proxy; HDD's rate guard limits per-client request rates only.
- The front door depends on a wrapper in your application and a reachable HDD address; a tunnel is a development convenience, not a production transport.
- Most of the wider product described in the specification (authoritative DNS, TLS issuance, customer accounts, hosted mode) is planned and not part of the demo track. `STATUS.md` states what is done.

## Safety rules

- Attack-shaped traffic is sent only to sites you own and have added to HDD. Never point the attack scripts at someone else's site.
- The lab origin is deliberately vulnerable: loopback only.
- The admin listener is loopback-only by default.
- Secrets never go in the repository, in URLs or in logs.

Contributions follow the build specification in `docs/SPEC.md` (digest in `AGENTS.md`). Licence: all rights reserved (`UNLICENSED`) until the owner chooses one.
