# ADR-0016: Pingora vs own proxy core

- Status: **proposed**
- Deciding task: [T-0353](../tasks/P18/T-0353.md) · Listener and accept loop; proxy-core decision (Pingora versus own)
- Date opened / decided: opened 2026-10-18 (queued by T-0008) / not decided
- Deciders: operator + agent

## Context

Pingora is allowed only with an ADR and a spike showing custom SNI resolver, per-request pipeline and h2 limits.

Deciding task objective (verbatim from the specification): Finalize the proxy core and build the accept layer that sheds load gracefully.

## Options considered

| Option | Pros | Cons | Spike or evidence link |
| --- | --- | --- | --- |
| (to be filled by T-0353) | | | |

## Decision

Not decided. Do not mark `accepted` without a spike link or a stated reason.

## Consequences

(to be filled by T-0353)

## Security impact

(to be filled by T-0353)

## Rollback plan

(to be filled by T-0353)

## Links

- Task: [T-0353](../tasks/P18/T-0353.md)
