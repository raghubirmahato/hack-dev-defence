# ADR-0013: Hickory server customization (RRL, cookies, CNAME flattening)

- Status: **proposed**
- Deciding task: [T-0387](../tasks/P20/T-0387.md) · ADR: DNS server core (hickory-server customization versus own packet loop) and workspace wiring
- Date opened / decided: opened 2026-10-18 (queued by T-0008) / not decided
- Deciders: operator + agent

## Context

Spike whether hickory-server allows EDNS cookies, RRL, CNAME flattening and minimal responses; otherwise a custom loop over hickory-proto.

Deciding task objective (verbatim from the specification): Decide, with evidence, how `hdd-dns` receives, parses and answers packets, so every later task builds on a justified core.

## Options considered

| Option | Pros | Cons | Spike or evidence link |
| --- | --- | --- | --- |
| (to be filled by T-0387) | | | |

## Decision

Not decided. Do not mark `accepted` without a spike link or a stated reason.

## Consequences

(to be filled by T-0387)

## Security impact

(to be filled by T-0387)

## Rollback plan

(to be filled by T-0387)

## Links

- Task: [T-0387](../tasks/P20/T-0387.md)
