# ADR-0028: Redis client (redis-rs instead of fred)

- Status: **accepted**
- Deciding task: [T-0562](../tasks/P33/T-0562.md) · `KvStore`, `Bus` and `Limiter` traits with Redis and in-process backends
- Date opened / decided: opened and decided 2026-10-19
- Deciders: agent (section 0.5), within rule R-08 and the Part A technology table

## Context

T-0562 step 2 says "Implement `RedisKv` on `fred`", and the technology table of Part A lists `fred`. R-08 requires a dependency to be
maintained, and an ADR when the latest release is older than a year. On 2026-10-19 the registry and the repository say:

| Crate | Latest release | Last push to the repository | Licence | MSRV |
| --- | --- | --- | --- | --- |
| `fred` 10.1.0 | 2025-02-27 | 2025-02-27 (46 open issues) | MIT | 1.75 |
| `redis` 1.7.1 (redis-rs) | 2026-09-25 | 2026-10-17 | BSD-3-Clause | 1.88 |

`fred` has been idle for about twenty months; `redis` is current. Both support Lua scripts, pipelining, TLS with rustls and
automatic reconnection. The hosted backend carries bans, sessions and rate counters, so a client that no longer receives fixes is
a risk that R-12 (HDD patches itself) says to avoid.

## Options considered

| Option | Pros | Cons | Spike or evidence link |
| --- | --- | --- | --- |
| `redis` 1.7.1 with `ConnectionManager`, `Script`, RESP3 push messages | Maintained; `Script` does `EVALSHA` and `NOSCRIPT` recovery; the manager reconnects and can resubscribe by itself; rustls without a bundled provider, so it uses the `ring` provider of ADR-0001 | BSD-3-Clause (already allowed); pulls `xxhash-rust` under the Boost licence (a per-crate exception in `deny.toml`, expiring 2027-04-19); about 45 more crates in the graph | `crates/hdd-common/src/kv/redis.rs`, compiled and unit-tested here; behavior against a server is UNVERIFIED on this builder |
| `fred` 10.1.0 (named in the specification) | Matches the specification text; rich API (pools, sentinel, tracing) | No release or push for twenty months; fails the "maintained" test of R-08 | `cargo info fred`, the GitHub API (`pushed_at` 2025-02-27) |
| `deadpool-redis` over `redis` | Connection pool | Another layer; the manager already multiplexes one connection | n/a |
| Own RESP client | No third-party code | Large, security-sensitive code that would need its own fuzzing and review | n/a |

## Decision

Use `redis` 1.7.1 with the features `aio`, `tokio-comp`, `tokio-rustls-comp`, `script` and `connection-manager`, behind the
`redis` feature of `hdd-common` (on by default). Reason: it is maintained and `fred` is not (R-08), the API surface HDD needs is
small (eval a script, publish, subscribe) and is covered by the shared conformance suite whichever client is used. This deviates
from the wording of T-0562 step 2 and of the technology table; it is recorded in `docs/DEVIATIONS.md` (ASM-017).

Connection policy enforced in code (`RedisConfig`): `rediss://` and a password are required; plain `redis://` is accepted only for
a loopback host and only through the test constructor. The URL is never logged or placed in an error.

## Consequences

`hdd-common` gains the optional dependency `redis` and its transitive crates (all exempted in `supply-chain/config.toml` by
`cargo vet regenerate exemptions`, 44 more entries). `xtask kv-lint` keeps every use of the client inside `hdd-common::kv`.
Switching clients later touches only `kv/redis.rs`.

## Security impact

Redis traffic is TLS (rustls, `ring`) and authenticated by policy. All named atomic operations are single Lua scripts. The
scripts use only integer arithmetic below 2^50 (enforced by request validation) so that Lua doubles are exact. Server errors are
mapped to store errors without the URL.

## Rollback plan

Disable the `redis` feature of `hdd-common` (the in-process backend and the traits are unaffected), or replace `kv/redis.rs` with
an implementation on another client; the conformance suite in `tests/kv_redis.rs` is client-independent and decides whether the
replacement is equivalent.

## Links

- Task: [T-0562](../tasks/P33/T-0562.md)
- Related: [ADR-0001](0001-crypto-provider-ring-vs-aws-lc-rs.md), [ADR-0027](0027-one-code-path-two-runtime-profiles.md)
