# STRIDE

> **Partial.** The full threat model is written by the tasks T-0135, T-0519, T-0531 and T-0579. Until then this file holds the **deltas** that
> `[SEC]` tasks add (definition of done, section 0.7). Nothing here claims completeness; each delta lists the threats considered for that task
> and the test that exercises the mitigation.

- Owning or contributing tasks: T-0135, T-0519, T-0531, T-0579 (full model); T-0006, T-0008, T-0009 (deltas below)
- Task details: `docs/spec/INDEX.md` maps each task ID to its file; `docs/tasks/` holds one file per task
- Status: deltas for P00 recorded 2026-10-18; full model not started

## Delta T-0006: live profile and `hddctl preflight`

Trust boundary: the operator-edited file `hdd.live.yaml` and `hddctl`'s output.

| STRIDE | Threat | Mitigation | Test |
| --- | --- | --- | --- |
| Spoofing | A value in a name field is a pasted secret that later gets used as if it were a name | `EnvVarName` accepts only UPPER_CASE names and rejects credential prefixes, long single words and segments that look like random key material (a digit followed by a letter inside a word, very long runs). This is a heuristic: it catches pasted tokens and base32/base62 keys, not every conceivable secret | `a4_no_secret_value_can_be_parsed_only_environment_variable_names`, `names_that_look_like_random_key_material_are_rejected`, `token_looking_values_are_rejected` |
| Tampering | A mistyped or unknown key silently changes nothing (a security setting is ignored) | `deny_unknown_fields` everywhere; error names the full key path | `a3_unknown_keys_are_rejected_with_the_full_key_path` |
| Repudiation | Not applicable (local file) | none | n/a |
| Information disclosure | `hddctl preflight` output or logs reveal a secret value or a key file location | `SecretPath` prints the file name only (and `<redacted>` for something that cannot be a file name); validator messages show a 6-character preview of a rejected value, never the whole; serde messages are scrubbed of the offending value; printed profiles drop credentials and queries from URLs | `printing_a_profile_never_shows_secret_file_locations`, `a4_a_token_in_a_name_field_is_rejected_and_never_echoed`, `rejected_values_are_scrubbed_out_of_parse_errors`, `rejected_values_are_never_repeated_in_full`, `a_secret_pasted_into_a_path_field_is_not_echoed_as_a_file_name` |
| Denial of service | A hostile or accidental file (alias bomb, deep nesting, huge file, duplicate keys) exhausts memory or time | YAML budget (no anchors/aliases/merge keys, depth 16, 20,000 events), 256 KiB cap, one document; rejected at stage one, before the schema is consulted | `hostile_yaml_is_rejected_by_the_budget_not_by_the_schema` (each hostile document has an accepted control), `the_parser_returns_quickly_on_hostile_input`, proptests that parsing never panics |
| Elevation of privilege | The acceptance runner ends up on the never-ban list and can no longer be banned (section 2.4) | `PROF-RUNNER-ADMIN` fails when the runner IP is inside `admin_cidrs` | `a2_the_runner_ip_inside_admin_cidrs_fails_with_the_documented_message` |

Residual: reachability of the SMTP relay and nameserver names is checked only by the explicit probes of `hddctl preflight`, never by the pure validator.

## Delta T-0008: dependency vetting lint

Trust boundary: the dependency graph that builds HDD.

| STRIDE | Threat | Mitigation | Test |
| --- | --- | --- | --- |
| Spoofing / Tampering | A dependency is added without anyone checking that it exists, is maintained, fits the licence policy and the MSRV | step `dependency-vetting` of `cargo xtask verify` flags a crate with no entry in `docs/vetting.toml`; `cargo deny`, `cargo audit`, `cargo vet` cover the transitive graph | `adding_a_crate_without_vetting_is_flagged` and the other tests of `deps::tests` |
| Elevation of privilege | An FFI crate, a crate with `unsafe` in its API, or an abandoned crate enters without a decision | the same lint requires an existing ADR for those cases | `ffi_and_unmaintained_crates_need_an_existing_adr` |

Residual: the entry is written by the person adding the dependency; the lint proves that an entry exists and is well-formed, not that its content is true. `cargo vet` currently has no audit imports (every crate is exempted).

## Delta T-0009: egress client, SSRF guard, target guard, kill switch

Trust boundary: everything HDD sends to hosts it does not control, including user-supplied URLs.

| STRIDE | Threat | Mitigation | Test |
| --- | --- | --- | --- |
| Spoofing | DNS rebinding: a name resolves to a public address when checked and to loopback or an internal address when used | every address of every resolution is validated; the connection goes to the validated address; each request and each redirect hop resolves and validates again | `a2_a_name_that_resolves_public_then_loopback_is_rejected_at_connect_time`, `one_bad_address_among_good_ones_rejects_the_whole_answer` |
| Spoofing | A spoofed DNS answer injects extra records | records whose owner is not on the question's CNAME chain are ignored; random id; connected UDP socket | `records_for_names_outside_the_chain_are_ignored` |
| Tampering | A TLS man in the middle; a switch that disables verification | verification is always on; the only trust inputs are the OS roots and explicit extra roots | `tls_verification_rejects_a_certificate_for_another_name`, `there_is_no_way_to_turn_verification_off` |
| Tampering | A redirect carries credentials or a body to another host | every caller header except `accept` / `accept-language` is dropped when scheme, host or port change; a 307/308 that would replay a body to another origin is denied | `caller_headers_are_dropped_when_a_redirect_changes_the_origin`, `headers_survive_a_same_origin_redirect_but_a_cross_origin_307_never_replays_a_body` |
| Repudiation | A denied attempt leaves no trace, or the trace itself floods the log or leaks a webhook secret | every denial is counted and recorded (destination reduced to `scheme://host:port/…`, never the path or query, because webhook URLs carry secrets there; reason, caller, class); emission is rate limited, reports what it suppressed, and a broken stderr cannot panic the caller | `denied_events_never_contain_query_strings_or_credentials`, `a1_a_host_not_on_the_allowlist_is_denied_before_any_socket_is_opened`, `the_log_is_rate_limited_but_nothing_is_lost_from_the_counters` |
| Information disclosure | SSRF reads cloud metadata or internal services | public-unicast-only policy for user URLs, port allowlist, mapped-address unwrapping, translation prefixes refused; for allowlisted hosts the baseline refuses metadata (`169.254.169.254`, `fd00:ec2::/32`, `100.100.100.200`, `168.63.129.16`), link-local, multicast, unspecified and broadcast, judging an IPv4 address inside NAT64 / 6to4 / Teredo by the address it stands for; none of these is reachable even when listed or exempted | `classification_table`, `embedded_ipv4_is_extracted_from_translation_prefixes`, `translation_prefixes_and_cloud_metadata_in_ordinary_ranges_are_unreachable_even_when_listed`, `the_user_url_client_refuses_literals_ports_and_tricky_hosts`, `a3_a_redirect_to_the_metadata_address_is_not_followed` |
| Tampering | A request path escapes the prefix of an allowlist entry (`/directory/../admin`, encoded dots or slashes) | a path with dot segments, encoded dots / slashes / backslashes, a NUL or doubled slashes never satisfies a path-prefix entry; the URL parser refuses backslashes | `path_prefix_entries_cannot_be_escaped_with_dot_segments_or_encodings`, `ambiguous_paths_never_satisfy_a_prefix_entry` |
| Denial of service | A slow or huge response ties up the caller | connect and total timeouts, response and request size caps, bounded redirect count | `the_total_timeout_cuts_off_a_slow_server`, `the_response_size_cap_applies_to_content_length_and_chunked_bodies` |
| Elevation of privilege | Attack-shaped traffic reaches a third party (CNAME to another host, wrong address) | `TargetGuard` derives the set from the profile, checks the CNAME chain and the resolved addresses (the platform addresses when configured, otherwise public unicast only; empty answers and mistyped platform addresses are errors), applies the metadata baseline, and fails closed when the resolver cannot report CNAMEs; the validator refuses a lab CIDR that is not a private range or that contains the server, and a `domain` that is a public suffix | `a4_a_cname_to_another_host_is_rejected_using_a_real_dns_responder`, `a_resolver_that_cannot_see_cnames_fails_closed_in_live_mode`, `without_platform_addresses_only_public_unicast_answers_are_accepted`, `a_mistyped_platform_address_is_an_error_not_a_weaker_check`, `lab_cidr_must_be_a_private_range_and_must_not_contain_the_platform`, `domain_must_not_be_a_public_suffix` |
| Denial of service (self) | A runaway test cannot be stopped | the latched kill-switch file stops tools within one second: `tripped()` watches the file itself (no background poller is required), the egress client and the probes race their work against it, and a switch path that cannot be examined trips it (fail closed) | `a_blocking_tool_aborts_within_one_second_of_the_file_appearing`, `tripped_watches_the_file_without_a_background_poller`, `the_kill_switch_aborts_without_a_background_poller`, `a_path_that_cannot_be_examined_trips_the_switch`, `the_kill_switch_aborts_a_request_in_flight_within_one_second` |

Residual: the DNS stub resolver does not fall back to TCP for truncated answers (it fails closed); hostnames in the allowlist are trusted to resolve honestly apart from the baseline address check; an operator who adds a wildcard entry trusts every host under it. The coverage-guided fuzz target is UNVERIFIED(`tool_unavailable`): `cargo-fuzz` needs a nightly toolchain; `egress::fuzz_entry` and the proptests exercise the same parsers today.

## T-0025: security UX dangerous actions, lockout prevention and honest warnings

Trust boundary: the operator's browser session and the mutation API it drives, including the copy and
the previews that user acts on. Every counter-requirement below is stated as a numbered requirement in
`docs/UX/SECURITY-UX.md` (`GL-` for the guard, `TC-` for typed confirmation, `TB-` for time boxes) or
as a catalog row in `docs/UX/dangerous-actions.md` (`DA-nn`). The Status column says honestly which
rows are design-only today and which will be tests.

| STRIDE | Threat | Counter-requirement | ATK or test | Status |
| --- | --- | --- | --- | --- |
| Spoofing | A hostile page frames a confirmation and captures the click (clickjacking), or a forged runner header buys the acceptance-runner exception. | `frame-ancestors 'none'` and `X-Frame-Options`; native modal dialog; a typed-confirmation row cannot be prefilled; the runner exception needs the signed runner token (GL-6). | ATK-171; T-0094 headers and browser test; T-0327 A3 token spoofing | design-only until T-0094; the runner part is a T-0327 test |
| Tampering | A CSRF request submits a destructive change the user never previewed, or a replayed confirmation applies a different diff. | CSRF token on every mutation; `Origin` and `Sec-Fetch-Site` checks; the preview is recomputed at submit and bound to a single-use nonce; a stale preview is refused (GL-13). | ATK-296; T-0327; T-0094 | test in T-0327 and T-0094 |
| Repudiation | A time-box extend or an automatic revert leaves no attributable record; an impersonation session denies a write. | Every catalog row writes its B8 event; extend and revert write the time-box events (TB-5); impersonation start, end and blocked write are recorded. | T-0327 A5; T-0235 A1 | test in T-0327 and T-0235 |
| Information disclosure | A stored payload in the preview or the evidence reads the session; a confused deputy in an impersonation session reads another tenant's data; the preview prints an admin CIDR or the acting IP. | Escaped PayloadViewer and a nonce CSP; read-only impersonation with `ERR-AUTH-014`; the preview shows the collision class, not the whole list; tenant scoping (R-18). | ATK-297; ATK-293; ATK-298; T-0094 | test in T-0094; the tenant-scoping tests are T-0327 |
| Denial of service | A broad ban, geo-block or rule refuses the admin surface or the whole staff; a huge preview freezes the tab. | The self-lockout guard blocks or requires step-up (GL-1 to GL-14); platform and never-ban keys cannot be acknowledged; the preview is bounded and computed server-side. | ATK-291; ATK-292; T-0327 | test in T-0327 |
| Elevation of privilege | A hidden control is the only thing stopping a permission the API would allow; a read-only impersonation session writes; a confirmation skips step-up. | UI/API parity (R-27); the permission and the step-up are enforced server-side; non-GET requests fail in impersonation. | ATK-294; ATK-298; T-0327 | test in T-0327 |
| Spoofing / Tampering (UI redress) | A misleading overlay makes the destructive control look like the safe one. | The safe action is the default focus; the destructive button is not the primary style; consequences are plain text; no cross-origin embedding. | ATK-171; T-0094 | design-only until T-0094 |

Residual: the clickjacking and UI redress rows are design requirements until the browser suite of
T-0094 exists. C5 has the generic clickjacking class ATK-171, so the clickjacking and UI redress rows
map to it; C5 has no separate UI-redress class, and `docs/UX/SECURITY-UX.md` says so and cites
ATK-171 as the nearest class instead of inventing an id. The CSRF row keeps ATK-296, the ban row
keeps ATK-291, the tenant-rules row ATK-292, the admin-panel row ATK-295 and the export row ATK-300.
The guard rows are table and unit tests in T-0327 and the time-box rows in T-0235; both are
`UNVERIFIED(task_not_run)` until those tasks run. The honest-limit copy is enforced today only
by the text check of `cargo xtask ux-docs`; the placement on S-044, S-055, S-057 and S-126 is a design
requirement of T-0069.

## Delta T-0215: acceptance runner skeleton

Trust boundary: the acceptance runner's target selection, its reports and its safety envelope, and the operator's approval record. The runner sends nothing in this task (`docs/ACCEPTANCE.md`); the enforcement seams are code and are tested with a recording sender.

| STRIDE | Threat | Mitigation | Test |
| --- | --- | --- | --- |
| Spoofing | A check sends attack-shaped traffic to a target that is not derived from the validated live profile | `Connector::prepare` calls `TargetGuard::from_profile` and the payload-class/lifecycle rules before a `PlannedRequest` (private constructor) can reach any `Sender`; a non-allowlisted target aborts with zero sends; no socket, HTTP client or process execution exists in the crate | `guard` A1 recording-sender tests, source-scan test |
| Tampering | A status line or report is edited to look green, or evidence does not match what was recorded | A PASS is representable only with a hashed evidence artifact; saved logs are hashed over the bytes written and the hash plus a redacted tail is embedded; the renderer refuses a PASS without hashed evidence, duplicate ids and bad ids | report goldens, saved-log re-hash test |
| Repudiation | A run does not record what was not executed, or an abort leaves checks silently missing | mode, stage, load profile, vantage count and notes are recorded; after an abort the remaining checks are `UNVERIFIED(skipped_by_operator)`, not omitted; a caught panic is counted (R-09) | runner plan/abort tests |
| Information disclosure | A secret, token, PII or request body reaches a report or a log | evidence is capped at 512 bytes; the redactor removes registered exact secret values and marker values from both formats and the saved log while keeping SHA-256 digests; a planted-secret test asserts absence | report redaction tests |
| Denial of service | A runaway check exhausts the runner's budget or the target | one shared token bucket with hard ceilings (checks may lower, never raise), a per-check timeout, a latched kill switch aborting within one second and a signal source | A2/A3 tests, runner timeout test |
| Elevation of privilege | A destructive or load check runs in a stage or without the approval the safety envelope requires | the production stage refuses destructive checks without the operator's recorded approval and maintenance window; `load` needs `load_profile_approved` and a per-run approval; the lifecycle is evaluated before the target check | config/guard tests |

Residual: the literal SIGINT/SIGTERM delivery is `UNVERIFIED(environment_unsupported)` on the Windows builder (tested through an injected signal source); live SSH/WireGuard and vantage use are `UNVERIFIED(capability_not_supplied)`; the skeleton implements no live check or sender, so every AC id is `UNVERIFIED(stage_not_reached)` until T-0216/T-0491. The numeric `load` ceilings are authored guard rails because the v5 profile carries no load caps (see `docs/ACCEPTANCE.md`).

## Delta T-0020: error-handling UX model

Trust boundary: the error renderer and the visitor-facing pages S-140 to S-148. The model is a design document (`docs/UX/ERRORS.md`) and its copy is checked by `ux-docs`; enforcement lives in T-0079, T-0085, T-0324 and T-0366.

| STRIDE | Threat | Counter-requirement | Maps to |
| --- | --- | --- | --- |
| Spoofing | A forged error or block page makes a visitor trust an attacker origin. | Visitor pages are served only by the data-plane template (no external requests, inline CSS nonce); the Ray ID shape is validated and is never accepted from a parameter as proof. | ATK-171, T-0366 |
| Tampering | A client changes a code, status or class to steer the recovery path. | The class is derived server-side from the B7 code and status; the client never supplies the class. | ATK-296, T-0085 |
| Repudiation | A failed action leaves no reference for support or audit. | Every API problem carries `request_id`; every visitor page carries a Ray ID; the server log stores the structured record and the event/audit entry links the request. | B8 audit events, T-0085 |
| Information disclosure | An error reveals a rule, a trace, an internal hostname or whether a resource exists. | S-140..S-148 copy and problem documents are scanned for rule words, stack traces and internal hostnames; a cross-tenant read is 404 `ERR-PERM-002`, never 403 (R-20); trace ids and internal hostnames are never shown. | ATK-287, ATK-293, ATK-297 |
| Denial of service | A client retry storm amplifies an outage. | Unsafe POST actions are never retried automatically; background polls back off with a numeric cap and stop at a terminal state; `Retry-After` is honoured with a countdown. | ATK-292, T-0079 |
| Elevation of privilege | A replayed create or a stale update duplicates or escalates a privileged action. | `Idempotency-Key` on every POST create/job trigger; `If-Match` on updates; a mismatch returns ERR-CONC-001. | ATK-294, ATK-296, T-0079 |

Residual: the visitor-page constraints V-1..V-11, the page weight, the CSP and the noscript behaviour are design requirements until T-0065/T-0338/T-0366 implement them; the document marks those measurements `UNVERIFIED(capability_not_supplied)` and the machine check covers the copy inventory, the journey error-path coverage and the B6 method/idempotency classification only.
