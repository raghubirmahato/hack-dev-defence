# Running HDD on your own computer (the `local` profile)

> **Skeleton (T-0561).** The comparison table and the rules below are final. The sections marked *to come* are written by the task
> that builds the feature (named in each), so nothing here describes behavior that does not exist yet.

HDD can run on a personal computer and be live only while it is running. It is the same product as the hosted one (rule R-31: one
code path, two runtime profiles), with a different set of things the profile may change. Local is for learning, development,
demonstrations and attended use. It is not a way to get 24/7 protection: when the computer sleeps or HDD stops, nothing protects
your sites, and a tunnel in front of a local instance has no listener.

## What the local profile can and cannot do

`hddctl preflight --plan` prints this for your machine, with the build track (Track H or Track L) and which acceptance checks can
run here.

| Capability | Local profile |
| --- | --- |
| Authoritative DNS on port 53 | not available (`ERR-LOCAL-001`) |
| Kernel enforcement (nftables, XDP) | not available (`ERR-LOCAL-001`); the application-layer jail enforces |
| ACME certificates for public names | not available (`ERR-LOCAL-001`); a name-constrained local certificate authority is used |
| `saas` deployment mode, open signup, full nameserver delegation | not available (`ERR-LOCAL-001`) |
| LAN exposure of protected sites | allowed with the exact acknowledgement `I-UNDERSTAND-LOCAL-IS-NOT-24x7` (`ERR-LOCAL-002` until given) |
| Embedded database, in-process key-value store | available |

## Settings

The file `hdd.live.yaml` needs only `runtime`, `operator_email` and `signup` for `runtime.profile: local`. The environment overrides the
file: `HDD_RUNTIME_PROFILE`, `HDD_DATA_DIR`, `HDD_LOCAL_DATABASE`, `HDD_KV_BACKEND`, `HDD_LOCAL_PORTS`, `HDD_LOCAL_SUFFIX`,
`HDD_LOCAL_TLS`, `HDD_LOCAL_LAN_EXPOSURE`, `HDD_LOCAL_LAN_ACK`, `HDD_LOCAL_DOGFOOD`, `HDD_LOCAL_LOOPBACK_IDENTITY`. Their types and
accepted values are in `docs/runtime-env.schema.json`; the file schema is `docs/profile.schema.json`.

## Profile comparison (C18.2)

| Aspect | `local` | `hosted` |
| --- | --- | --- |
| Intended use | Development, demos, learning, attended protection of a site through an operator-run tunnel | Unattended production, 24/7 |
| Supported OS | Windows 10/11 x64, macOS 13+ (arm64, x64), Linux (x64, arm64) | Linux x64 or arm64 (Debian 12+, Ubuntu 22.04+, RHEL 9 class); kernel 5.15+ for XDP (optional) |
| Process model | `hdd-local` supervisor runs web, api, worker, proxy and (optionally) dns as supervised tasks in one process, or the normal service binaries when `kv: redis` | Separate services under systemd or containers |
| Product surfaces | Served directly by `hdd-web` and `hdd-api` with the control-plane hardening of C18.7; routing them through the proxy (`dogfood`) is optional and off by default | Always behind the proxy as `platform_internal` |
| PostgreSQL | Embedded and managed by `hdd-local`, or external, or Docker Compose | External or host-local server, hardened |
| Redis | Not needed (`MemoryKv`); optional | Required when more than one service process exists |
| Ports | Unprivileged: web 8443, proxy 8080 and 8444, dns 5300 | 80, 443, 53 (and UDP 443) |
| TLS | Name-constrained local CA, `*.hdd.localhost` | ACME (staging first, production by approval) |
| DNS | Optional authoritative server on 5300 for tooling and tests | Authoritative on 53 with `ns1`/`ns2`, delegation, DNSSEC state |
| Integration modes | `local_only`, and `subdomain_only`, `cname_partial`, `a_record_partial` through a tunnel or port forward | All modes |
| Client identity | Peer IP for LAN and tunnel clients; keyed identity for loopback clients | Peer IP or trusted-proxy header |
| Kernel enforcement | None (the `Enforcer` is `Noop`); the L7 jail enforces | nftables sets, XDP, host agent |
| Shield and DDoS | L7 behavior only | Full |
| Uptime | Only while running and awake; optional start at login | Watchdog, auto-restart, boot start, backups, signed upgrades |
| Mail | SMTP if configured; otherwise the admin-only outbox viewer | SMTP required for multi-user installs |
| Acceptance | Unit, integration and browser tests, `profile-parity`, and the `local` tier (AC-55); hosted-only checks are UNVERIFIED(`environment_unsupported`) | Everything |

## Install, first run, the supervisor, backups, exposure and troubleshooting

### The embedded database (available now, T-0563)

```text
hdd-local db up --download --allow https://github.com/theseus-rs/postgresql-binaries/releases/download/17.11.1/ --allow https://release-assets.githubusercontent.com/
hdd-local db status
hdd-local backup          # an encrypted logical backup under <data dir>/backups
hdd-local restore FILE
hdd-local db down
```

`db up` needs 2 GiB of free disk space, installs PostgreSQL 17 into the data directory (after checking the pinned SHA-256; offline: `--bundle ARCHIVE`), listens on `127.0.0.1` only and prints where the connection URL file is. Nothing is downloaded unless you pass `--download` and the allowlist entries yourself. Details and limits: OPERATIONS.md, ADR-0029.

*To come:* the supervisor and the first-run setup (T-0564), the local certificate authority and the hosts helper (T-0566), export (T-0569), tunnel exposure (T-0568), and `hdd-local doctor` (T-0564).
