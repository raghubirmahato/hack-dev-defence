# ADR-0001: Crypto provider (ring vs aws-lc-rs)

- Status: **spiking**
- Deciding task: [T-0354](../tasks/P18/T-0354.md) · TLS termination: crypto provider ADR, SNI resolver, policy and refusal behavior
- Date opened / decided: opened 2026-10-18 (queued by T-0008) / final decision is T-0354's; provisional use of `ring` started 2026-10-18 (T-0009)
- Deciders: operator + agent

## Context

Section 6: choose the rustls crypto provider explicitly; any FFI dependency (aws-lc-rs) needs an ADR.

Deciding task objective (verbatim from the specification): Terminate TLS correctly, quickly and with strict defaults.

T-0009 (egress client) is the first code that needs TLS and it runs long before T-0354. `rustls` cannot be built without a provider feature, so a provisional choice had to be made now. This ADR records that choice and keeps the decision open for T-0354, which decides it for the data plane with measurements.

## Options considered

| Option | Pros | Cons | Spike or evidence link |
| --- | --- | --- | --- |
| `ring` (via rustls feature `ring`) | Built and passed the whole test suite on the Windows Track L builder without extra tooling (no NASM, no CMake); small; widely deployed; ECDSA/RSA/Ed25519 and the TLS 1.2/1.3 suites the egress client needs | Contains C and assembly (BoringSSL-derived), so it counts as FFI under R-08; fewer algorithms (no post-quantum key exchange) | `crates/hdd-common/src/egress/` test suite (real local TLS servers with generated certificates), `cargo deny check` accepts its licence expression |
| `aws-lc-rs` | FIPS-capable build, post-quantum hybrid key exchange, faster on some CPUs | FFI to aws-lc (C), needs CMake/NASM-class build tooling on some targets (not verified on this builder), larger build | not spiked (T-0354) |

## Decision

**Provisional:** `ring` for `hdd-common::egress` and its tests. This is explicitly not the final data-plane decision: T-0354 compares both providers on the data-plane workload (handshake rate, memory, post-quantum needs, build on every supported OS) and records the result here. Until then the status stays `spiking`.

Reason for proceeding without the final decision: the provider is a Cargo feature of `rustls`, swapping it changes no API used by the egress module, and the egress client only needs standard client-side TLS with certificate verification.

## Consequences

- `rustls`, `tokio-rustls` and `rcgen` are flagged `ffi = true` with `adr = "0001"` in `docs/vetting.toml` because `ring` is behind them.
- When T-0354 decides, the egress module's provider is switched together with the data plane's so that one provider exists in the binary.

## Security impact

Both options are FFI. `ring` is a smaller audited surface; neither is memory-safe throughout. Supply-chain exposure is tracked by `cargo audit`, `cargo deny` and `cargo vet` (all three run in `cargo xtask verify`). TLS verification can never be disabled in the egress client (T-0009), independent of the provider.

## Rollback plan

Change the `rustls`/`tokio-rustls`/`rcgen` features from `ring` to `aws-lc-rs` in `crates/hdd-common/Cargo.toml` and re-run the egress test suite (real TLS servers), `cargo deny check` and `cargo xtask verify`; no source change is needed because the module uses only rustls' public API and `ClientConfig::builder_with_provider`-free defaults.

## Links

- Task: [T-0354](../tasks/P18/T-0354.md)
- First use: [T-0009](../tasks/P00/T-0009.md)
