# ADR-0017: Aya loader and pinned nightly (hdd-xdp-ebpf)

- Status: **proposed**
- Deciding task: [T-0466](../tasks/P25/T-0466.md) · `hdd-xdp-ebpf`: the kernel program, `aya` and nightly toolchain ADR, and the single `unsafe` crate
- Date opened / decided: opened 2026-10-18 (queued by T-0008) / not decided
- Deciders: operator + agent

## Context

aya needs a pinned nightly and bpf-linker; kernel support varies; nftables is the fallback.

Deciding task objective (verbatim from the specification): Compile the verdict logic into a verifier-friendly XDP program with minimal unsafe surface and a reproducible build.

## Options considered

| Option | Pros | Cons | Spike or evidence link |
| --- | --- | --- | --- |
| (to be filled by T-0466) | | | |

## Decision

Not decided. Do not mark `accepted` without a spike link or a stated reason.

## Consequences

(to be filled by T-0466)

## Security impact

(to be filled by T-0466)

## Rollback plan

(to be filled by T-0466)

## Links

- Task: [T-0466](../tasks/P25/T-0466.md)
