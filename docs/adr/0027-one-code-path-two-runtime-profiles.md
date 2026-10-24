# ADR-0027: One code path, two runtime profiles

- Status: **accepted**
- Deciding task: [T-0561](../tasks/P33/T-0561.md) · Runtime profile model, capability matrix and the parity contract
- Date opened / decided: opened and decided 2026-10-19
- Deciders: agent (section 0.5), within rule R-31 of the specification

## Context

The operator needs HDD to run on a personal computer (`local`, live only while it runs) and on a server (`hosted`, 24/7). Two code
bases, or a `DEV_MODE` that skips checks, would let the personal-computer build drift from the product that is deployed and would
make the local tests prove less than they appear to. Rule R-31 therefore requires one code path with two runtime profiles and a
tested parity contract (AC-55).

## Options considered

| Option | Pros | Cons | Spike or evidence link |
| --- | --- | --- | --- |
| One code path; a profile may change only a closed list of things; enforced by a capability matrix, lints and a parity harness | Local tests exercise the shipped detection, bans, authentication and tenancy; drift is detected mechanically | Needs the store traits (T-0562) and an embedded database (T-0563) before the local walking skeleton | `crates/hdd-common/src/profile/capability/tests.rs`, `crates/hdd-xtask/src/profile_lint/tests.rs`, `crates/hdd-common/src/parity/tests.rs` |
| A `DEV_MODE` flag or `cfg` features that switch behavior | Quick to write | Forbidden by R-31; each switch is a way to weaken detection, bans or isolation, and the tested build differs from the shipped one | n/a |
| Local profile as a separate reduced product | Simple local binary | Two products to keep equal; the personal-computer build would prove nothing about production | n/a |

## Decision

Adopt one code path. Reason: R-31 requires it, and the alternatives above let the tested build differ from the shipped one. A runtime profile may change only:

1. service topology (one supervisor process tree versus separate services);
2. backing stores (embedded PostgreSQL and the in-process `KvStore`/`Bus`/`Limiter` versus external PostgreSQL and Redis);
3. bind addresses and ports;
4. TLS trust and HSTS policy (name-constrained local CA versus ACME);
5. whether the product surfaces are routed through the proxy (`dogfood`);
6. the client key of loopback clients (C18.5);
7. privileged host integrations (nftables, XDP, port 53);
8. uptime features (watchdog, backups, upgrades).

It may never weaken detection, bans, tenant isolation, authentication, CSP and CSRF, audit, the claims policy or the safety
envelope. There is no `DEV_MODE`. Enforcement:

- **One capability matrix** (`hdd_common::profile::capability`, C18.2) decides what a profile may do. Refusals carry `ERR-LOCAL-001`
  (or `ERR-LOCAL-002`, `ERR-HOSTING-001`); config load fails on a requested capability that is unavailable.
- **`cargo xtask profile-lint`** fails when the detection, pipeline, authentication or egress/network code looks at the runtime
  profile, when a profile `cfg` or feature appears there, when a capability is missing from `Capability::ALL`, or when the
  acceptance-check table drifts from Appendix E3.
- **`cargo xtask kv-lint`** fails when anything outside `hdd-common::kv` uses a Redis client.
- **`cargo xtask profile-parity`** compares decision fields and ban intent between the two profiles over the core corpus, the benign
  corpus, the BOLA suite and a ban lifecycle (AC-55). The harness (`hdd_common::parity`) exists and is tested; it reports
  UNVERIFIED(`stage_not_reached`) until the detection engine and the fixtures exist, never a vacuous pass.

## Consequences

Profile-dependent code is confined to `hdd-local`, `hdd-common::kv`, `hdd-common::profile`, `hdd-common::buildplan` (the build plan,
which describes the builder and not the product) and the `Enforcer` factory. Adding a capability means adding it to the matrix and
to `Capability::ALL`, or `profile-lint` fails. Tenancy has no crate of its own yet; its paths are added to
`docs/profile-lint.toml` when they exist.

## Security impact

The local profile cannot weaken the product: unavailable capabilities are refused rather than emulated (`saas`, open signup, port
53, kernel enforcement, ACME). LAN exposure needs the exact acknowledgement string. Environment variables are typed, never echoed in
full and never carry secrets.

## Rollback plan

The profile model is additive: `runtime.profile` defaults to `hosted`, so removing the lints and the matrix leaves hosted behavior
unchanged. To roll back, revert the commit of T-0561; no data is migrated by this decision.

## Links

- Task: [T-0561](../tasks/P33/T-0561.md)
- Related: [ADR-0002](0002-yaml-parser-or-toml-profile-format.md)
