# Acceptance report

| Field | Value |
| --- | --- |
| Generated | 2026-10-20T09:00:00Z |
| Mode | live |
| Stage | pilot |
| Load profile | functional |
| Vantages | 0 |

## Summary

3 checks: 1 PASS, 1 FAIL, 1 UNVERIFIED

## Checks

| ID | Tier | Status | Title |
| --- | --- | --- | --- |
| AC-00 | smoke | PASS | Preflight and safety-envelope self-tests |
| AC-01 | nondestructive | FAIL(a would not block) | Authentication and admin isolation |
| AC-02 | pilot-full | UNVERIFIED(stage_not_reached) | Zone import and parity |

## Evidence

### AC-00 / http_response

- status: 403
- header.content-type: text/html

## Logs

- `acceptance-x/run.log` (42 bytes, sha256 `bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb`)

```text
line one
line two
```

## Notes

- a note
