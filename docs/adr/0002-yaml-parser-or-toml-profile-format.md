# ADR-0002: YAML parser or TOML profile format

- Status: **accepted**
- Deciding task: [T-0006](../tasks/P00/T-0006.md) · Live profile v5: schema, example file and validator
- Date opened / decided: opened 2026-10-18 (queued by T-0008) / decided 2026-10-18
- Deciders: agent (decision authority: crate choice inside the Part A stack with an ADR, section 0.5); the operator may overrule

## Context

`serde_yaml` is archived. Section 8 and T-0006 require a profile that is read from untrusted-ish text (the operator edits it, but the parser must not be a way to exhaust memory or time) and a hostile-input stance: no anchor/alias bombs, depth limits, strict keys. If no YAML parser qualifies, the profile switches to TOML and `DEV-V5-004` is recorded.

Deciding task objective (verbatim from the specification): Make the operator's inputs machine-validated, with errors that say exactly what to fix.

## Options considered

Registry facts read on 2026-10-18 from the crates.io API and `cargo info` (not from memory).

| Option | Pros | Cons | Spike or evidence link |
| --- | --- | --- | --- |
| `serde-saphyr` 2.0.0 (MIT OR Apache-2.0, MSRV 1.89) | Last release 2026-10-13; `#![forbid(unsafe_code)]`; pure Rust (parser `granit-parser`); a `Budget` with limits on events, nodes, depth, flow nesting, aliases, anchors, merge keys and documents; duplicate-key and merge-key policies; strict booleans | Young crate (first release 2025-09); larger dependency tree than a bare parser (`annotate-snippets`, `encoding_rs_io`, `smallvec`, `num-traits`, `nohash-hasher`, `base64` after feature trimming) | `hostile_yaml_is_rejected_within_the_budget`, `a3_...`, `a4_...` in `crates/hdd-common/src/profile/tests.rs` |
| `serde_yaml_ng` 0.10.0 (MIT) | Drop-in successor API of `serde_yaml` | Last release 2024-05-26 (over a year: needs an ADR under R-08); built on `unsafe-libyaml` (a C-to-Rust translation full of `unsafe`); no budget API, so alias bombs must be refused by pre-scanning the text | registry facts above |
| `saphyr` 0.2.2 (MIT OR Apache-2.0) | Maintained (2026-10-15), safe Rust | A YAML AST/parser, not a serde deserializer: we would write our own deserialization and key-path reporting | registry facts above |
| TOML (`toml` 1.1.8, already a dependency of `xtask`) | Simple grammar, no anchors at all | Section 8 and every document, example and question of the specification show YAML; the operator already has the example; switching needs `DEV-V5-004` and operator buy-in | n/a |

## Decision

Use **`serde-saphyr`** with default features off (`deserialize` only), reading the file into a generic value under a tight budget and then into the typed profile with `serde_path_to_error` (ADR-0026) so that every error carries its key path.

Budget used for the profile (all in `profile::yaml_options`): no anchors, aliases or merge keys (the profile has no use for them, so alias bombs are impossible by construction), nesting depth 16, at most 20,000 events and 10,000 nodes, one document, duplicate keys rejected, strict booleans (`yes` is not `true`), input at most 256 KiB.

`DEV-V5-004` (TOML instead of YAML) is **not** triggered. Reason: a maintained parser that is safe Rust and has hostile-input limits exists. Spike: the tests listed above, run by `cargo xtask verify` (step `nextest`).

## Consequences

- `hdd-common` depends on `serde-saphyr`, `schemars`, `serde_path_to_error` (vetting entries in `docs/vetting.toml`).
- The generated schema is `docs/profile.schema.json`; `cargo xtask profile check` keeps it and `hdd.live.example.yaml` current.
- If the crate is abandoned, swap the two lines of `profile::parse_value`; the typed layer does not depend on it.

## Security impact

Attack surface is one file the operator controls, read at startup and by `hddctl preflight`. No `unsafe` in the parser crate. Budget and size caps bound CPU and memory; proptest feeds arbitrary text to the parser to show it never panics. No secret is ever parsed: secret-bearing fields accept environment variable names only (A4). No STRIDE entry changes beyond the profile being an input boundary (documented in `docs/STRIDE.md` by the task that owns that file's profile section).

## Rollback plan

Replace `serde_saphyr::from_str_with_options` in `profile::parse_value` by another parser that yields a `serde_json::Value`, or move the profile to TOML (record `DEV-V5-004`, port `hdd.live.example.yaml`). The test that proves it: the unchanged tests in `profile/tests.rs` (A1 to A5, hostile input) must still pass against the replacement.

## Links

- Task: [T-0006](../tasks/P00/T-0006.md)
- Related: [ADR-0026](0026-serde-path-to-error-for-profile-key-paths.md)
