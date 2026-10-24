# ADR-0025: `unsafe` in `hdd-xdp-ebpf` (stub created by T-0004)

- Status: **proposed**
- Deciding task: [T-0466](../tasks/P25/T-0466.md) (related: T-0004 step 3, T-0465)
- Date opened / decided: opened 2026-10-18 / not decided
- Deciders: operator + agent

## Context

Every workspace crate carries `#![forbid(unsafe_code)]` except `hdd-xdp-ebpf`, the kernel packet-filter program, which cannot be written
without `unsafe`. It is excluded from the default workspace build and uses a pinned nightly toolchain plus `bpf-linker` (see ADR-0017).
Decision logic lives in `hdd-xdp-logic` (no_std, no unsafe), so `unsafe` is confined to packet access and map plumbing.

## Options considered

| Option | Pros | Cons | Spike or evidence link |
| --- | --- | --- | --- |
| (to be filled by T-0466) | | | |

## Decision

Not decided. The crate must ship with verifier and packet-level tests (T-0466) before `accepted`.

## Consequences

(to be filled by T-0466)

## Security impact

The only `unsafe` in first-party code; runs in the kernel under the BPF verifier. The dead-man detach timer (`HDD_XDP_DETACH_SECS`) limits lockout risk.

## Rollback plan

`HDD_XDP_MODE=off` and the nftables backend; detach on timer.

## Links

- [ADR-0017](0017-aya-loader-and-pinned-nightly-hdd-xdp-ebpf.md)
