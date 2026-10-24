# Hosting HDD on a server 24/7 (the `hosted` profile)

> **Skeleton (T-0561).** The comparison table is final. The checks and runbooks are written by T-0571 to T-0574; nothing here claims
> a behavior that does not exist yet.

HDD does not promise an uptime figure. Availability comes from the host, the supervisor, the network and operating discipline;
HDD measures it (heartbeat and external probe) and reports what it measured. One server is a single point of failure.

## Hosting profiles (C18.10)

| Profile | Shape | Use when | Limits |
| --- | --- | --- | --- |
| H1 Single server | One Linux server runs everything (2 vCPU, 4 GiB RAM, 40 GiB disk minimum) | One operator, a handful to hundreds of domains | A single point of failure |
| H2 Edge and control split | Edge nodes (proxy, DNS, firewall agent, shield) and one control node | The data plane must survive control-plane maintenance | More to operate |
| H3 Container platform | Docker host or Kubernetes with host networking and UDP exposure | You already run containers | Needs 53 UDP and TCP, 80 and 443 without NAT surprises |
| H4 Platform-as-a-service or serverless | Heroku-style, Cloud Run, edge functions | Not supported for the data plane (no raw UDP 53, no control of TLS termination) | May host only static public pages |
| H5 Home server or single-board computer | Behind NAT with port forwarding, dynamic DNS or a tunnel | Learning, attended protection of small personal sites | No authoritative DNS; treat as local with autostart, not production |

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

## Checks, runbooks, backups and upgrades

*To come:* `hddctl hosting check` (HC-01 to HC-23, T-0571), the runbooks in `docs/RUNBOOKS/` (T-0573), backups and restore drills
(T-0574), signed upgrades (T-0518, T-0524). Until they exist the corresponding acceptance items (AC-56) are UNVERIFIED
(`stage_not_reached`).
