# ADR-0026: serde_path_to_error for profile key paths

- Status: **accepted**
- Deciding task: [T-0006](../tasks/P00/T-0006.md) · Live profile v5: schema, example file and validator
- Date opened / decided: opened and decided 2026-10-18
- Deciders: agent (section 0.5)

## Context

T-0006 A3 requires that an unknown key is rejected "with the key path", and the operator needs `runtime.local.ports.prots`, not just "unknown field `prots`". Serde reports the failing field name only. R-08 requires an ADR for any dependency whose latest release is more than a year old; `serde_path_to_error` 0.1.20 was last released on 2025-09-15, which is over a year before this decision (2026-10-18).

## Options considered

| Option | Pros | Cons | Spike or evidence link |
| --- | --- | --- | --- |
| `serde_path_to_error` 0.1.20 (MIT OR Apache-2.0, MSRV 1.61) | Tiny wrapper around any `Deserializer`; maintained by the author of serde; about 99 million recent downloads; no `unsafe`; no dependencies beyond serde | No release for over a year (the crate is feature-complete) | `a3_unknown_keys_are_rejected_with_the_full_key_path`, `wrong_types_and_enum_values_report_the_path` in `crates/hdd-common/src/profile/tests.rs` |
| Own path tracking (a `Deserializer` wrapper or schema walk) | No dependency | About 200 lines of subtle code that must itself be fuzzed; reports only the first error unless a schema validator is also written | n/a |
| Report only serde's message | No dependency | Fails A3 | n/a |

## Decision

Use `serde_path_to_error`. Reason: the age is the only R-08 trigger; the crate is small, widely audited, has no `unsafe` and its behavior is pinned by the tests above. Re-evaluate if a RustSec advisory appears (`cargo audit` runs in `xtask verify`).

## Consequences

One extra dependency in `hdd-common`. Error messages for the operator contain full key paths.

## Security impact

Parses nothing itself; it observes the path while serde deserializes values that already passed the YAML budget. No `unsafe`, no I/O.

## Rollback plan

Delete the dependency and call `serde_json::from_value` directly in `profile::parse_yaml`; the key path of non-unknown-key errors is then lost (test A3 would need the unknown-key path derived from the message only). The tests named above prove the behavior either way.

## Links

- Task: [T-0006](../tasks/P00/T-0006.md)
- Related: [ADR-0002](0002-yaml-parser-or-toml-profile-format.md)
