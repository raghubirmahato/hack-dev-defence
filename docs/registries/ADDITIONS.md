# Registry additions

The master specification is verbatim and checksum-locked, so entries that a task adds to a registry (section 0.9) are recorded
here with the owning task until `xtask names check` exists and merges them. Every row needs an owner and a reason.

## Metrics (B9)

| Name | Type | Labels | Meaning | Owner | Reason |
| --- | --- | --- | --- | --- | --- |
| `hdd_kv_rehydrate_rows` | gauge | `kind` (`ban`, `offence`, `session`) | Rows loaded into the in-process store from Postgres at start-up | T-0562 | Step 4 asks for a metric for rows loaded |
| `hdd_kv_rehydrate_seconds` | gauge | | Time the rehydration took | T-0562 | Step 4 asks for a metric for time taken |
