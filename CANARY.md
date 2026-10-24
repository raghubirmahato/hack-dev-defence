# CANARY: canary fixtures on the origin (C16.1)

Status of this document: **T-0210 delivery**. The C16.1 fixtures, the `hdd-canary` sidecar, the systemd unit and
`hddctl canary generate|verify` exist and are tested on the build host (Windows, Track L). The through-HDD half of
`hddctl canary verify` and the systemd sandbox are `UNVERIFIED` here for the reasons in [Known limitations](#known-limitations);
this page states exactly which command proves each claim.

Read [section C16.1 of the specification](docs/SPEC.md) (`docs/SPEC.md` line 3879) and task
[T-0210](docs/tasks/P11/T-0210.md) first. The registry row for this work is `REQ-WSK-04`.

## 1. What the canary is

The canary is a set of inert static files on the operator's real origin plus a check that reads them back. It proves two
things about the path HDD sees:

1. **The origin is reachable and the bytes pass through unchanged** (`ok.txt`, `static.css`, `static.js`, `search.html`).
2. **The outbound filter of HDD has a true positive to find**: `leak.txt` contains a harmless sentence that looks like a
   MySQL error, so the filter's database-error detection can be observed on a real response (C16.1 item 2).

The canary is **not** a proxy, not a WAF and not in HDD's request path: it is a fixture on the origin, reached by HDD only
when a test asks for it. That is why the `[DP]` checklist items are answered as "not applicable, with a reason" in
[section 9](#9-dp-checklist-honest-answers) instead of with a hot-path benchmark.

## 2. The contract (C16.1)

All files live under `origin.canary.base_path` (default `/__hdd_canary/`) and are served for `test_hostname` and
`sandbox_hostname` only. `hddctl canary generate` writes these exact bytes:

| File | Exact content | What it proves | Test |
| --- | --- | --- | --- |
| `ok.txt` | `hdd-canary-ok` (13 bytes, no trailing newline) | routing and body pass-through | `t0210_generate_writes_the_five_contract_files_and_real_hashes` |
| `leak.txt` | `You have an error in your SQL syntax; check the manual that corresponds to your MySQL server version` | the outbound filter's DB-error rule has a positive fixture | `t0210_generate_writes_the_five_contract_files_and_real_hashes`, `t0210_sha256_is_real_sha256` |
| `static.css` | two inert CSS rules, one fixed colour | byte-exact CSS pass-through | `t0210_generate_writes_the_five_contract_files_and_real_hashes` |
| `static.js` | an inert script that sets one attribute on an element, no request data | byte-exact JS pass-through | `a1_the_sidecar_serves_exactly_the_c16_1_files` |
| `search.html` | a static page with no form, no query reading and no echo | live payloads sent there are inert | `t0210_generate_writes_the_five_contract_files_and_real_hashes` (asserts no `location.search`, no `innerHTML`) |

`hddctl canary generate` also writes **`manifest.sha256`**: a `SHA256SUMS`-style file with a `# base_path:` header and
one line per file, containing the real SHA-256 of the bytes it wrote (A1). The manifest is a **local evidence artifact**;
it is never served by the sidecar and must not be copied into the web root
(`t0210_generate_writes_the_five_contract_files_and_real_hashes` asserts the manifest is not in the served set,
`a1_the_sidecar_serves_exactly_the_c16_1_files` asserts `GET <base_path>manifest.sha256` is refused).

The published SHA-256 of the two byte-exact assets is in the generated manifest; it depends only on the bytes above and not
on the operator's host. The command prints every hash, so it can be quoted in an incident ticket.

## 3. Generate and verify (both install modes)

Both install modes start the same way:

```bash
# on the machine where hddctl runs (the acceptance runner or the operator's workstation)
cargo build --release -p hddctl
./target/release/hddctl canary generate --dir ./canary-files --base-path /__hdd_canary/
```

`generate` is idempotent: running it again over the same directory writes the same bytes and the same manifest
(`t0210_generate_is_idempotent_and_rejects_a_bad_base_path`). It refuses a base path that a proxy could normalize
differently (`..`, `%`, `//`, `?`, `#`, whitespace; `t0210_base_path_normalisation_table`).

`hddctl canary verify` has five probes plus four fail-closed input rules, and prints one `RULE STATUS` line each; it
exits `1` only when a check FAILs, so `UNVERIFIED` and `WARN` never masquerade as a PASS:

| Rule | What it does | `UNVERIFIED(...)` / notes |
| --- | --- | --- |
| `CANARY-MANIFEST` | re-hashes the five files in `--dir`, compares them with `manifest.sha256` (A1) and compares the manifest's `base_path` with the base path in use (C-7: a mismatch is a FAIL) | no `--dir` was given |
| `CANARY-DIRECT` | fetches the five files from the origin's own URL while `origin.lockdown_state: pending` | no live profile and no `--direct-url`, or lockdown is already applied (the direct request is then intentionally refused) |
| `CANARY-HDD` | fetches the five files through `test_hostname`, i.e. through HDD; a PASS needs **HDD-specific evidence** (K-2): a response header `Server: Hack-Dev-Defence` or `HDD-Ray-ID`, or `HDD-Connecting-IP` in the echo equal to the runner IP. A different host, `X-Forwarded-For` or `X-Real-IP` is never evidence | no live profile and no `--through-url`; `UNVERIFIED(capability_not_supplied)` when no HDD-specific evidence is present; a transport failure is `UNVERIFIED(human_step_pending)` **only** when it is a DNS resolution failure of the profile-named `test_hostname` (the pilot delegation, STOP #1, has no field in the profile: the live profile records no delegation state, and `origin.lockdown_state` is the later STOP #2 origin-firewall/secret-header state); a literal IP, a connect/timeout/TLS failure, or any `--through-url` override with no profile is a `FAIL` (Q-1) |
| `CANARY-QUERY` | fetches every file with and without a query string and compares the served bytes | neither a direct nor a through-HDD target is available; a transport failure on the through target is `UNVERIFIED(human_step_pending)` |
| `CANARY-ECHO` | `GET <base_path>echo-headers`: parses the JSON, requires `nosniff` and no `Set-Cookie`, checks the probe header round-trip and, through HDD with `--runner-ip`, that the runner IP is a **whole address token** of a forwarding header (C-5) | the profile declares a static install (`origin.canary.use_hdd_canary_agent: false`), no profile declares the sidecar and the endpoint is not served, a transport failure on the through target before delegation, or neither target is available |

`X-Content-Type-Options: nosniff` is **required** on the echo JSON by C16 (`docs/SPEC.md` line 3877). On the five contract
files C16.1 does not require it (`docs/SPEC.md` line 3879), so a served file without it is a `WARN` (advisory), not a FAIL;
the sidecar and the documented nginx/apache snippets set it (`t0210_verify_warns_when_the_contract_files_lack_nosniff`,
`t0210_verify_fails_the_echo_without_nosniff`).

The four fail-closed input rules are emitted when their input is wrong, instead of a fabricated PASS: `CANARY-PROFILE`
(the `--file` exists but cannot be read or parsed), `CANARY-BASE-PATH` (the profile/flag base path is not acceptable),
`CANARY-TARGET` (an override target is not one the profile names, or without a profile is not a loopback literal with
`--local-only`: C-3) and `CANARY-ALLOWLIST` (the checked targets cannot form the probe allowlist). A missing profile file is
**not** one of them: it is the normal clean-checkout state, and the dependent probes report
`UNVERIFIED(human_step_pending)` with the operator steps.

The runner IP is asserted only on the **through-HDD** echo, and only as a whole token: the JSON is parsed and each address
of `X-Forwarded-For`/`HDD-Connecting-IP`/`X-Real-IP`/`CF-Connecting-IP`/`Forwarded` is parsed as an IP address and compared
exactly, so `198.51.100.7` never matches `198.51.100.77` and IPv6 works the same way
(`t0210_parsing_verify_reports_a_runner_ip_that_the_echo_does_not_show`,
`t0210_parsing_verify_whole_token_runner_ip_match_accepts_the_exact_address`). A direct-only run reports `CANARY-ECHO` PASS with a
line saying the runner IP was not checked; use `--through-url` (or the live profile) with `--runner-ip`.

The reason of every `UNVERIFIED` line is one of the closed set of section 0.4 of the specification (`capability_not_supplied`, `human_step_pending`, `environment_unsupported`, `oracle_unavailable`, `tool_unavailable`, `stage_not_reached`, `stage_forbids`, `skipped_by_operator`); anything else is a FAIL.

A missing `hdd.live.yaml` is not a failure: it is the normal state of a clean checkout (the file is git-ignored and must
never be committed). The profile-dependent checks then report `UNVERIFIED(human_step_pending)` **with the exact operator
steps printed in the same line**. Generate and the local re-hash still PASS.

Typical runs:

```bash
# local/direct only (no profile): manifest + a sidecar or static install on this machine
hddctl canary verify --dir ./canary-files --local-only --direct-url http://127.0.0.1:8080

# operator machine: the live profile names origin.url and test_hostname
hddctl canary verify --dir /root/canary-files --file hdd.live.yaml --runner-ip 198.51.100.7

# a plain static install: set origin.canary.use_hdd_canary_agent: false in the profile first; CANARY-ECHO is then
# UNVERIFIED(capability_not_supplied) with the origin_access_log alternative (C16 intro, docs/SPEC.md line 3877)
hddctl canary verify --dir /root/canary-files --file hdd.live.yaml
```

### 3.1 Every probe goes through the single egress path

`canary verify` sends only benign `GET`s through `hdd_common::egress::Client` (R-22): connect and total timeouts, a response
size cap, TLS verification, the denial log and the kill-switch file apply to every request. It builds a **purpose-specific
allowlist from the hosts the live profile itself names** — `origin.url` (direct) and `test_hostname` (through HDD) — or from
the explicit `--direct-url`/`--through-url` operator overrides, each entry restricted to the canary base path. It prints
every target before the first request.

It deliberately does **not** use the profile's `egress_allowlist`: that list is the allowlist of attack-shaped acceptance
traffic, and adding the operator's own origin and test hostname to it would be a new operator approval on every canary
check. The overrides are checked before any request leaves the machine (C-3):

* with a live profile, an override host must equal a host the profile itself names (`test_hostname` or the host of
  `origin.url`); anything else is `FAIL` `CANARY-TARGET`;
* without a profile, an override is accepted only with `--local-only` **and** only when it is a loopback literal
  (`127.0.0.0/8` or `::1`); a public name, a private range, the cloud metadata address, `localhost` or a userinfo form such
  as `http://127.0.0.1@evil.example/` is refused before any request (`t0210_verify_local_only_refuses_a_public_name`,
  `..._a_metadata_address`, `..._a_private_address`, `..._the_name_localhost`, `t0210_verify_refuses_a_userinfo_trick`,
  `t0210_verify_without_a_profile_requires_local_only_for_overrides`,
  `t0210_verify_refuses_a_profile_override_host_the_profile_does_not_name`).

No wildcard entry, no other port and no arbitrary command-line target is accepted. Decision reviewed and approved by the
Lead for T-0210; do not widen it silently (test
`t0210_verify_checks_the_through_path_and_query_invariance_when_overridden` asserts the printed targets).

One transport-level failure of a benign `GET` (connect, timeout, connection error) is retried **once**, so one transient
reset does not turn a canary probe into a false FAIL; a policy denial is never retried and a second failure is reported as
a FAIL (`t0210_parsing_verify_retries_one_transient_connection_error`). The retry repeats only a plain `GET` through the same
egress client.

Every other failure class is reported as its own status (K-6): the kill-switch file stops the probe and gives
`UNVERIFIED(skipped_by_operator)` (`t0210_verify_kill_switch_abort_is_skipped_by_operator`; point the tool at a test file
with `--kill-switch <path>`); a response over the canary size cap is a FAIL with its own message and a remediation that says
to investigate the response path, never "fix the origin" (`t0210_verify_response_too_large_is_its_own_failure`); a transport
failure to the through-HDD target is `UNVERIFIED(human_step_pending)` only while delegation is not recorded as done, and a
FAIL once `origin.lockdown_state: applied` records it as done
(`t0210_verify_transport_failure_to_the_through_target_is_a_pending_step`,
`t0210_verify_through_transport_fails_when_delegation_is_recorded_as_done`). Every `UNVERIFIED` line uses only the closed
reason set (`t0210_verify_uses_only_the_closed_reason_set`).

### 3.2 Query strings

C16.1 requires that a query string never changes what is served. Both install modes are checked the same way: each file is
fetched with and without `?hdd_canary_check=1&x=%2e%2e%2f`, the two bodies must be identical and must equal the contract
bytes (`a2_query_strings_do_not_change_what_is_served_and_are_not_echoed`, `t0210_verify_checks_the_through_path_and_query_invariance_when_overridden`).
The sidecar strips the query before routing and never decodes percent-encoding, so `.../ok.txt?x=1` serves exactly the bytes
of `.../ok.txt`, and no query value ever reaches a response.

## 4. Install mode A: the `hdd-canary` sidecar (systemd unit)

Use this mode when the origin cannot serve the files from its web root, or when the `echo-headers` checks are wanted. It
serves **only** the five files and `GET <base_path>echo-headers`; see section 6 for what it refuses.

### 4.1 Build and install the binary

```bash
cargo build --release -p hdd-canary
# Windows equivalent of sha256sum, or sha256sum on Linux:
sha256sum target/release/hdd-canary
# PowerShell:
Get-FileHash -Algorithm SHA256 .\target\release\hdd-canary.exe
```

Copy the binary to the origin at `/usr/local/bin/hdd-canary`, and record the checksum in the install log next to the
release tag. The packaged release (a signed build produced by `cargo xtask release`) is **not available yet**:
`cargo xtask release` is `UNVERIFIED(stage_not_reached)` because it arrives with T-0512 (phase P29). Until then use the
`cargo build --release` command above; do not present a locally built binary as a release artifact.

### 4.2 Generate the files, create the service account, install the unit

```bash
# as root on the origin
install -d -m 0750 -o root -g root /var/lib/hdd-canary
./hddctl canary generate --dir /var/lib/hdd-canary --base-path /__hdd_canary/
useradd --system --home /nonexistent --shell /usr/sbin/nologin hdd-canary 2>/dev/null || true
chown -R root:hdd-canary /var/lib/hdd-canary
chmod 0640 /var/lib/hdd-canary/*

cp deploy/hdd-canary.service /etc/systemd/system/hdd-canary.service
systemctl daemon-reload
systemctl enable --now hdd-canary.service
systemctl status --no-pager hdd-canary.service
journalctl -u hdd-canary.service -n 20 --no-pager
```

`deploy/hdd-canary.service` runs the binary as the unprivileged `hdd-canary` user with `CapabilityBoundingSet=` (empty),
`AmbientCapabilities=` (empty), `NoNewPrivileges=yes`, `ProtectSystem=strict`, a read-only `/var/lib/hdd-canary`, the exact
option `SystemCallFilter=@system-service` with `SystemCallErrorNumber=EPERM` and `SystemCallArchitectures=native` (the
`@system-service` set is defined by systemd; the unit does not restate it), `RestrictAddressFamilies=AF_INET AF_INET6
AF_UNIX`, `MemoryDenyWriteExecute=yes`, `PrivateTmp`/`PrivateDevices`/`ProtectKernel*`/`ProtectClock`/`ProtectProc=invisible`,
`LockPersonality`, `RestrictNamespaces`/`RestrictRealtime`/`RestrictSUIDSGID`, `IPAddressDeny=any` with
`IPAddressAllow=localhost` and `UMask=0077`. That is the A4 record: the service starts with no capabilities and a reduced
system-call set. The file contains the exact options with a comment for each; `systemd-analyze security hdd-canary.service`
is the command that shows the score.

Two values must be edited for the deployment and are marked in the unit:

* `ExecStart=... --bind <ADDR:PORT>`: the default is `127.0.0.1:8080`. Bind the origin's private interface (or a WireGuard
  address), never a public interface while `lockdown_state` is `pending`, and let only HDD reach it (section 7).
* `IPAddressAllow=`: the unit narrows incoming addresses with `IPAddressDeny=any` and allows `localhost`. If the sidecar must
  be reachable from another host, add that host's address (`IPAddressAllow=<HDD IP>`) **and** keep the deny, then restart the
  unit and re-run `systemd-analyze security`.

The binary verifies the manifest before serving when `--manifest` is passed (the unit passes it): a changed or missing file
stops the service instead of serving a fixture that no longer matches the published hash. A listener thread that dies (a
panic) is counted in `Running::metrics()` and makes the process exit non-zero, so `Restart=on-failure` fires instead of a
silent outage (K-4, R-09: `t0210_wait_reports_a_dead_listener_thread`). Files are read **once at startup**,
by their five fixed names, with `std::fs::read`; after that the process never touches the filesystem again. The service
therefore keeps the bytes it verified even if the directory changes, and a restart is the only way to pick up new bytes.

### 4.3 Check it

```bash
# from the origin itself, direct to the sidecar
curl -sS -D - http://127.0.0.1:8080/__hdd_canary/ok.txt
curl -sS -D - "http://127.0.0.1:8080/__hdd_canary/search.html?probe=1"
curl -sS -D - http://127.0.0.1:8080/__hdd_canary/echo-headers

# then the same through HDD, with the live profile
hddctl canary verify --dir <files> --file hdd.live.yaml --runner-ip <runner IP>
```

The `curl` commands show the fixed response headers (`X-Content-Type-Options: nosniff`, `Cache-Control: no-store`,
`Referrer-Policy: no-referrer`, `X-Frame-Options: DENY`, a restrictive `Content-Security-Policy`, no `Set-Cookie`).

## 5. Install mode B: plain static files in the origin web root

Use this mode when the operator prefers not to run another service. Copy the five files (never `manifest.sha256`) into the
web root under the base path, preserving the exact bytes, and **declare the mode in the profile**:
`origin.canary.use_hdd_canary_agent: false`. `canary verify` then reports `CANARY-ECHO`
`UNVERIFIED(capability_not_supplied)` with the `origin_access_log` alternative (the C16 intro, `docs/SPEC.md` line 3877:
the header checks become UNVERIFIED unless `origin_access_log` is provided). If the flag stays `true` (the default, meaning
the sidecar is expected) and the endpoint is missing, `CANARY-ECHO` is a genuine FAIL. `CANARY-QUERY` and the file checks
still run.

```bash
install -d -m 0755 /var/www/html/__hdd_canary
cp canary-files/ok.txt canary-files/leak.txt canary-files/static.css canary-files/static.js canary-files/search.html \
   /var/www/html/__hdd_canary/
```

Any static handler works. Declare the mode with `origin.canary.use_hdd_canary_agent: false` in the profile so the checker
treats the missing `echo-headers` as the documented limitation instead of an error; the per-request header checks then need
`origin_access_log` (C16 intro, `docs/SPEC.md` line 3877). The file checks and `CANARY-QUERY` still run, and `CANARY-HDD`
can still PASS when the response carries HDD's own headers (`Server: Hack-Dev-Defence` or `HDD-Ray-ID`, K-2/K-5) - what
remains `UNVERIFIED(capability_not_supplied)` is the per-request header echo (`X-Forwarded-For`/`HDD-Connecting-IP` as HDD
saw them), because a static install has no echo endpoint.

### 5.1 nginx

```nginx
location /__hdd_canary/ {
    alias /var/www/html/__hdd_canary/;
    autoindex off;                       # no directory listing
    default_type text/plain;
    types { }
    add_header X-Content-Type-Options nosniff always;
    add_header Cache-Control no-store always;
    add_header Referrer-Policy no-referrer always;
    # no access_log of the query string is needed here; HDD's origin_access_log is the header evidence
}
```

nginx's static handler ignores the query string, so `?x=1` serves the same file; this is exactly what
`CANARY-QUERY` asserts. Do not add a `rewrite` or `if ($args ...)` rule in this location: it would make the query string
change the response and `CANARY-QUERY` fails.

### 5.2 Apache httpd

```apache
Alias /__hdd_canary/ /var/www/html/__hdd_canary/
<Directory /var/www/html/__hdd_canary>
    Options -Indexes -ExecCGI +FollowSymLinks
    AllowOverride None
    Require all granted                  # tighten to the HDD addresses once lockdown is applied (section 7)
    Header always set X-Content-Type-Options nosniff
    Header always set Cache-Control no-store
    Header always set Referrer-Policy no-referrer
    <FilesMatch "^(static\.css|static\.js|search\.html)$">
        # the normal static MIME types of the site apply
    </FilesMatch>
</Directory>
```

## 6. What the sidecar refuses (A2, A3)

The sidecar serves exactly the contract paths and `GET <base_path>echo-headers`. Everything else gets **one identical opaque
response** (`404`, `Content-Length: 10`, body `not found`) with the same fixed headers. The tests send very long headers, odd
and unknown methods (`PROPFIND`, `POST`, lowercase `get`), bodies, `..` and encoded-slash path tricks, the base path itself,
`manifest.sha256` and absolute-form targets, and assert byte-identical responses with no reflection of a marker
(`a2_hostile_requests_get_one_opaque_response_and_no_reflection`).

Limits enforced in the parser and asserted by tests:

| Limit | Value | Test |
| --- | --- | --- |
| request line | 1024 bytes | `t0210_parse_request_enforces_the_request_line_limit` |
| header section | 8192 bytes (all header lines with their CRLF) | `t0210_parse_request_enforces_the_header_size_and_count_limits` |
| header count | 100 | `t0210_parse_request_enforces_the_header_size_and_count_limits` |
| served file | 64 KiB, checked from `symlink_metadata` and again with a hard `take()` while reading; only a regular file is served | `t0210_start_refuses_a_file_over_the_size_limit`, `t0210_start_refuses_a_non_regular_file` |
| `echo-headers` body | 16 KiB, with `"truncated":true` when it does not fit | `t0210_echo_headers_json_is_bounded_and_redacts_credentials`, `a3_echo_headers_returns_only_received_headers_with_a_size_cap` |
| a fixed worker pool (4 threads, accept queue of 64, one absolute 5 s deadline per connection measured from accept); a full queue is shed with a fixed opaque 503 + Connection: close + Retry-After: 1, counted in connections_shed | covers the request head, the write of the response and the discard of a rejected request's remainder; the remaining time is recomputed and applied before every read **and every write** (a slow reader cannot reset the deadline), and the connection is closed at the deadline | `a_connection_deadline_closes_a_dripping_client_at_the_deadline`, `a_rejected_client_sees_the_response_close_before_the_deadline`, `t0210_write_with_deadline_abandons_a_slow_reader_at_the_deadline` |

Additional refusal rules: only `GET` and `HEAD` (a body declared with `Content-Length` or `Transfer-Encoding` is refused
before any of it is read: `a2_a_body_is_never_read_and_the_server_keeps_serving`); a rejected `HEAD` gets the headers with
no body (`a2_a_rejected_head_gets_no_response_body`); no percent-decoding, no case folding and no dot-segment normalization
(only the literal bytes can match); no directory listing and no index (`a1_the_sidecar_serves_exactly_the_c16_1_files`).

The root directory itself is checked too: a symlinked (or Windows reparse-point) `--root`/`--dir` is refused (`t0210_start_refuses_a_symlinked_root_directory_when_the_privilege_exists`, or `UNVERIFIED(environment_unsupported)` where the privilege to create a symlink is absent). The sidecar opens a connection's file only at startup, by its five fixed names, with `symlink_metadata` (a symbolic link is
refused, never followed), the regular-file check and a hard `take(MAX_FILE_BYTES + 1)` read. The same decision is used by
`hddctl canary generate` (it refuses to write through a symlink or over a directory) and by `hddctl canary verify --dir`
(it hashes like the sidecar loads), so the verifier cannot pass a directory the sidecar would refuse; the decision is a
pure function (`t0210_ensure_regular_decision_table`), and the unix-only symlink case is
`UNVERIFIED(environment_unsupported)` on the Windows build host. Accepted streams are set back to **blocking** explicitly:
on Windows an accepted stream inherits the listener's non-blocking mode, which made a request arriving just after
`accept()` read as `WouldBlock` and answered with the opaque 404 (the F-B2-0 flake; regression test
`a2_a_request_that_arrives_after_accept_is_served_not_rejected`). A rejected connection is answered and its write side is
shut down (`shutdown(Write)`) before the bounded drain, so the client sees the end of the response immediately
(`a_rejected_client_sees_the_response_close_before_the_deadline`). `Content-Length: 0` declares no body and is accepted; a
positive length or any `Transfer-Encoding` is refused (`t0210_parse_request_accepts_content_length_zero`).

Requests the sidecar rejects are answered first and the rest of that connection is discarded unparsed, bounded by
`MAX_DRAIN_BYTES` (64 KiB) **and the connection deadline**, so the client reads the rejection instead of a TCP reset;
nothing of it is inspected, stored or reflected.

### 6.1 `echo-headers` (A3)

`GET <base_path>echo-headers` returns `{"headers":[{"name":...,"value":...}],"truncated":false}` as
`application/json; charset=utf-8` with `X-Content-Type-Options: nosniff`. It lists only the received header names and values
(the order is preserved, names are lower-cased), and the body is capped at 16 KiB. Two request headers are never echoed by
value: `cookie` and `authorization`/`proxy-authorization` are listed by name with the value `[not-echoed]`, so the endpoint
cannot be used to read a session cookie or a bearer token back
(`t0210_echo_headers_json_is_bounded_and_redacts_credentials`, `a3_echo_headers_returns_only_received_headers_with_a_size_cap`).
It sets no cookie and reads no request body. It exists to verify what HDD sends: `X-Forwarded-For`, `HDD-Connecting-IP`,
the secret origin header and the runner's own IP as HDD sees it (C16). Because it echoes request headers, it is an
information-disclosure surface if exposed: restrict who can reach the sidecar (section 7).

## 7. Security considerations

* **Bind to a private interface.** The default is `127.0.0.1:8080`. Bind the origin's private address (or WireGuard) and
  reach it only from the HDD host, or run it behind the origin's TLS terminator. Do not bind a public interface while
  `origin.lockdown_state` is `pending`.
* **Access only from HDD once lockdown is applied.** After the origin firewall/secret-header lockdown is applied (C16,
  `origin.lockdown_state: applied`), restrict the canary endpoint to the HDD addresses at the origin firewall and/or in the
  reverse proxy, and re-run `hddctl canary verify`; the direct check then reports `UNVERIFIED(capability_not_supplied)`
  because a direct request is intentionally not expected to succeed.
* **Least privilege.** The sidecar uses no capabilities, no setuid, a read-only data directory, no shell, no CGI and no
  execution of anything; it never writes to the filesystem (section 4.2). The unit carries the sandbox options.
* **No secrets in the canary, and the echo is a restricted surface.** The five files are public by design and the manifest
  is local evidence only. `echo-headers` never returns the value of a secret-bearing request header: any header whose name
  contains `secret`, `token`, `auth`, `key` or `signature`, plus `cookie` and `x-api-key`, is listed by name with
  `[not-echoed]`; the secret origin header `HDD-Origin-Auth` (`v1;<kid>;<ts>;<nonce>;<sig>`) is reported only as presence,
  version and key id (`v1;<kid>`) - never the timestamp, nonce or signature. The endpoint still echoes the *other* request
  headers and still reports that the origin auth header exists, so it remains an information-disclosure surface: access to it
  must be restricted to HDD (section 7 first two bullets), and `canary verify` reports the presence without ever printing a
  value (`a_echo_headers_never_leaks_secret_bearing_request_headers`,
  `t0210_parsing_verify_reports_the_origin_auth_presence_without_its_value`).
* **Empty egress side.** The sidecar makes no outbound connection; `canary verify` is the only client and it goes through
  `hdd_common::egress` (section 3.1).
* **Query strings** are never reflected and never change routing (section 3.2).

## 8. Removal and undo (OPS)

The install is idempotent: re-running `generate`, the file copies and `systemctl enable --now` converges to the same state
(`t0210_generate_is_idempotent_and_rejects_a_bad_base_path`; `systemd` enable is idempotent). To undo, in reverse order:

```bash
# sidecar install (mode A)
systemctl disable --now hdd-canary.service
rm -f /etc/systemd/system/hdd-canary.service
systemctl daemon-reload
rm -rf /var/lib/hdd-canary
userdel hdd-canary 2>/dev/null || true

# static install (mode B): remove the location and the copied files
rm -rf /var/www/html/__hdd_canary
# nginx: delete the location block and reload; apache: delete the Alias/Directory block and reload
nginx -t && systemctl reload nginx
```

After removal, `curl -sS -o /dev/null -w '%{http_code}\n' https://<test_hostname>/__hdd_canary/ok.txt` must show `404`
(or the site's branded 404) and `hddctl canary verify` must report the file checks as FAIL/UNVERIFIED, not PASS. The removal
changes no other site behaviour; the canary base path is not linked from the site. There is nothing to restore beyond
regenerating the files and re-copying them, and `hddctl canary verify` is the check that the restored bytes are the
contract bytes (`t0210_verify_detects_served_bytes_that_differ_from_the_contract`,
`t0210_verify_detects_a_tampered_or_missing_manifest`).

**SSH-lockout protection (OPS checklist).** This task's steps change files on the origin and one local systemd unit; they do
**not** edit `sshd_config`, firewall rules or anything that can lock the operator out of SSH. The checklist item is
therefore not applicable to T-0210 rather than omitted: the origin firewall change that makes the canary reachable only
from HDD is a separate operator change owned by the preflight/AC-00 work (T-0217) and the origin-hardening task, and that
change must use its own timed auto-revert guard before it is applied.

## 9. `[DP]` checklist: honest answers

The sidecar is an **origin-side fixture, not the proxy**: no HDD request depends on it, so the data-plane obligations are
answered with the reason, not with a proxy benchmark.

| `[DP]` item | Answer for T-0210 |
| --- | --- |
| On the hot path? | **No.** It is a fixture on the origin (C16), read by `hddctl canary verify`; HDD's proxy path never calls it. |
| Hot path never awaits the database | Not applicable: the sidecar has **no database and no Redis dependency at all** (std-only binary plus SHA-256); it never opens a store. `t0210_metrics_are_bounded_and_saturate` and the crate dependency list are the evidence. |
| Bounded memory and queues | Yes: five files loaded once, each at most 64 KiB; one connection at a time with one absolute 5 s deadline (head read and drain share it and the remaining time is recomputed before every read); 512-byte read chunks; 1 KiB request-line, 8 KiB header and 100-header caps; 16 KiB capped echo JSON body; saturating `u64` counters. No queue is created beyond the OS backlog (`accept_errors` counts what the OS refuses). |
| Criterion benchmark or histogram | Not applicable, with the reason: the sidecar is not in HDD's measured request path, so a criterion benchmark of it would measure a fixture, not the product's latency. The product's proxy benchmarks belong to the proxy tasks; `CANARY.md` does not present a latency number. |
| Fuzz or proptest | Yes: a bounded, deterministic sweep with a fixed seed that generates structured and mutated request heads (valid and invalid method, version, target, header names/values, duplicates, folded lines, huge values), feeds raw noise too, and asserts that **both** the accepted and the rejected parser outcomes occur in meaningful numbers (>= 500 each) and that every accepted head keeps the documented limits (`t0210_parser_never_panics_on_arbitrary_bytes_and_keeps_limits`); plus a hostile-client integration suite over real TCP sockets (`a2_*`, `a3_*`). No new fuzzing tool was added. |
| Behaviour when Redis or Postgres is down | Not applicable: the sidecar has no store; it serves the bytes it loaded at startup even if everything else on the host is down. `hddctl canary verify` reads the profile file only. |
| Metric with drop counter | Implemented as bounded saturating counters exposed by `Running::metrics()`: `served`, `rejected`, `echo_requests`, `bytes_out`, `accept_errors` (the drop counter of the accept queue), `read_timeouts`, `write_timeouts` and `listener_panics` (`t0210_metrics_are_bounded_and_saturate`, `t0210_wait_reports_a_dead_listener_thread`). There is deliberately no metrics endpoint: the sidecar serves only the C16.1 contract, so a scrape path would widen its surface. |

## 10. `[OPS]` checklist

| Item | Evidence |
| --- | --- |
| Idempotent | `hddctl canary generate` twice is byte-identical (`t0210_generate_is_idempotent_and_rejects_a_bad_base_path`); file copies, `systemctl enable --now` and the nginx/apache blocks converge on re-run. |
| Dry-run mode | Generate into a staging directory and run `hddctl canary verify --dir <staging> --direct-url <local sidecar>` before touching the origin; `systemd-analyze security hdd-canary.service` previews the sandbox. No command in this page changes the live site before the operator copies files. |
| Documented undo | Section 8, with the post-removal `404` check. |
| SSH-lockout protection | Not applicable to this task, with the reason in section 8 (no SSH or firewall change here). |
| Restore or rollback exercised | The restore procedure (regenerate, re-copy, re-verify) is exercised by `t0210_verify_detects_served_bytes_that_differ_from_the_contract` and by the mutation demos in `docs/evidence/P11/T-0210-negative-demos.txt`; the manifest check fails on a changed file (`t0210_check_manifest_detects_a_changed_file_and_names_it`). |

## 11. `[DOC]` checklist and known limitations

Every claim above names a test or a command the reader can run. The green commands are:

```bash
cargo nextest run -p hdd-canary -p hddctl --no-fail-fast
cargo fmt -p hdd-canary -p hddctl -- --check
cargo clippy -p hdd-canary -p hddctl --all-targets -- -D warnings
```

The evidence files for this task are `docs/evidence/P11/T-0210-red.txt`, `T-0210-verify.txt` and
`T-0210-negative-demos.txt` (mutation demos: a backup, a mutation that makes the named check FAIL, a byte-identical restore
with the same SHA-256, and the check PASS again).

Known limitations, stated instead of hidden:

* **The through-HDD and query-through-HDD checks are `UNVERIFIED(human_step_pending)` here.** There is no `hdd.live.yaml`
  in this repository (it is git-ignored and must never be committed), no pilot DNS delegation and no reachable HDD edge on
  the build host. The command prints the exact operator steps instead of a fabricated PASS; the direct/local halves are
  exercised in tests with a real sidecar on `127.0.0.1:0`.
* **The systemd sandbox is `UNVERIFIED(environment_unsupported)` here.** The build host is Windows; systemd does not exist
  there, so `systemd-analyze security hdd-canary.service` has not been run. The unit file, its options and this page are the
  record; run `systemd-analyze security` on the Linux host at install time.
* **`cargo xtask release` does not exist yet** (`UNVERIFIED(stage_not_reached)`): it arrives with T-0512 (P29). Packaging is
  the `cargo build --release` command plus a recorded checksum (section 4.1); this page does not describe a signed release
  artifact that is not built yet.
* **The sidecar speaks HTTP/1.1 only; TLS termination is the origin's job.** The origin already serves its site over TLS, so
  either put the sidecar behind that terminator or use the plain static-file install (mode B) and let the direct check use
  the origin's `https://` URL. The unit binds loopback/private addresses and is not intended to be exposed as an HTTPS
  endpoint by itself.
* **`leak.txt` through HDD depends on the site mode.** In `monitor`/`log` mode HDD forwards the harmless sentence and the
  canary sees it; in `block` mode HDD's outbound filter is expected to intercept it, so a `CANARY-HDD` FAIL on `leak.txt`
  is the filter working, not an origin defect. The line names the file, so the operator can tell the two apart.
* **A plain static install cannot serve `echo-headers`.** Set `origin.canary.use_hdd_canary_agent: false`: the C16 intro
  (`docs/SPEC.md` line 3877) says the header checks become `UNVERIFIED(capability_not_supplied)` unless `origin_access_log`
  is provided, and `canary verify` then reports exactly that and exits 0. A missing endpoint while the flag is `true` is a
  FAIL, because the profile then expects the sidecar.
