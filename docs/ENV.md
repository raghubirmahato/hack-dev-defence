# ENV: builder environment discovery (T-0003)

Run 2026-10-18 15:44Z on the builder by read-only commands only (no `sudo`, no configuration change, no binding of ports). Full logs: `acceptance-env/*.log` (git-ignored) with `acceptance-env/SHA256SUMS`.
Re-run with the same checklist at the start of P11 (VPS) and P28 (lab). Output is stable except timestamps.

Status words: a missing optional tool is `UNVERIFIED(tool_unavailable)`; a capability the platform cannot offer is `UNVERIFIED(environment_unsupported)`; `FAIL` is reserved for a check that ran and failed.

| Item | Command | Status | Output tail (last 5 lines) | Log sha256 | What degrades |
| --- | --- | --- | --- | --- | --- |
| rustc | `rustc -V` | PASS | rustc 1.98.1 (48a229cea 2026-09-01) | 2e6cb7c4cc4b | - |
| cargo | `cargo -V` | PASS | cargo 1.98.1 (797e8a9bc 2026-08-05) | 1c0496100283 | - |
| rustup toolchains (nightly present?) | `rustup toolchain list` | UNVERIFIED(tool_unavailable) | stable-x86_64-pc-windows-msvc (default) / 1.98.1-x86_64-pc-windows-msvc (active) | 4c630fc0a041 | No nightly toolchain: hdd-xdp-ebpf cannot build here; AC-26 becomes UNVERIFIED(environment_unsupported) on this builder (kernel filter is Linux-only anyway). |
| bpf-linker | `bpf-linker --version` | UNVERIFIED(tool_unavailable) | not installed / not on PATH | 0f1f6f7552ae | XDP object cannot be linked on this builder; Linux/lab builder needed (P25). |
| docker | `docker -v` | UNVERIFIED(environment_unsupported) | not installed / not on PATH | 3e24ff7a6594 | Track L: no testcontainers; use the embedded PostgreSQL and in-process stores of hdd-local (T-0561 to T-0563). Compose-based checks are UNVERIFIED. |
| dig | `dig -v` | PASS | DiG 9.17.12 | a0e34b56ddae | - |
| delv | `delv -v` | PASS | delv 9.17.12 | 49d228f97657 | - |
| openssl | `openssl version` | PASS | OpenSSL 3.5.8 25 Aug 2026 (Library: OpenSSL 3.5.8 25 Aug 2026) | 06e2b26602a0 | - |
| ssh | `ssh -V` | PASS | OpenSSH_10.5p1, OpenSSL 3.5.8 25 Aug 2026 | 0e490df03649 | - |
| nft | `nft --version` | UNVERIFIED(environment_unsupported) | not installed / not on PATH | a679a1bdd82f | nftables backend cannot be exercised here (Windows). Linux builder/lab required (AC-26, AC-29). |
| iptables | `iptables -V` | UNVERIFIED(environment_unsupported) | not installed / not on PATH | 3f77957bcb41 | ipset/iptables fallback backend cannot be exercised here. |
| node (must NOT be required) | `node -v` | PASS | v24.18.0 | 65929b50bc7d | Present but never required by the build (R-05). |
| git | `git --version` | PASS | git version 2.56.0.windows.1 | e0027d3aa159 | - |
| python (bootstrap tool only, DEV-V5-000) | `python --version` | PASS | Python 3.14.6 | 7df28311574c | - |
| cargo-deny | `cargo-deny --version` | PASS | cargo-deny 0.20.2 | 5c285590c8ef | - |
| cargo-nextest | `cargo-nextest --version` | PASS | cargo-nextest 0.9.148 (cd1d6d546 2026-10-07) / release: 0.9.148 / commit-hash: cd1d6d5467322dbc0d39a80cb671d000ac302798 / commit-date: 2026-10-07 / host: x86_64-pc-windows-msvc | 3f11c7b3a1a5 | - |
| cargo-audit | `cargo-audit --version` | PASS | cargo-audit 0.22.2 | 82b1c08c4303 | - |
| cargo-vet | `cargo-vet --version` | UNVERIFIED(tool_unavailable) | not installed / not on PATH | 66c8c4059a2e | `cargo xtask verify` step for cargo-vet will be UNVERIFIED(tool_unavailable) until installed (T-0005). |
| cargo-machete | `cargo-machete --version` | PASS | 0.9.2 | 714ba9716f29 | - |
| cargo-llvm-cov | `cargo-llvm-cov --version` | UNVERIFIED(tool_unavailable) | not installed / not on PATH | cf148d24ad2b | `cargo xtask verify` step for cargo-llvm-cov will be UNVERIFIED(tool_unavailable) until installed (T-0005). |
| cargo-mutants | `cargo-mutants --version` | UNVERIFIED(tool_unavailable) | not installed / not on PATH | 5d11386b7a0c | `cargo xtask verify` step for cargo-mutants will be UNVERIFIED(tool_unavailable) until installed (T-0005). |
| cargo-fuzz | `cargo-fuzz --version` | UNVERIFIED(tool_unavailable) | not installed / not on PATH | 6dde8b1350df | `cargo xtask verify` step for cargo-fuzz will be UNVERIFIED(tool_unavailable) until installed (T-0005). |
| tokei | `tokei --version` | UNVERIFIED(tool_unavailable) | not installed / not on PATH | 9e0473c0d92b | `cargo xtask verify` step for tokei will be UNVERIFIED(tool_unavailable) until installed (T-0005). |
| cargo-geiger | `cargo-geiger --version` | UNVERIFIED(tool_unavailable) | not installed / not on PATH | 384621880995 | `cargo xtask verify` step for cargo-geiger will be UNVERIFIED(tool_unavailable) until installed (T-0005). |
| cosign | `cosign --version` | UNVERIFIED(tool_unavailable) | not installed / not on PATH | 6f781d3f0d69 | `cargo xtask verify` step for cosign will be UNVERIFIED(tool_unavailable) until installed (T-0005). |
| OS and architecture | `Get-CimInstance Win32_OperatingSystem` | PASS | Microsoft Windows NT 10.0.26300.0 / 64-bit / Microsoft Windows 11 Pro | 54bdc7f831f6 | - |
| CPU, RAM, virtualization | `Get-CimInstance Win32_Processor / Win32_ComputerSystem` | PASS | AMD Ryzen 7 7735HS with Radeon Graphics         cores=8 logical=16 / RAM_GB=15.2 hypervisor_present=False | 758f4fa1604e | - |
| Disk | `Get-PSDrive -PSProvider FileSystem` | PASS | C: free_GB=80.5 used_GB=290.8 / D: free_GB=343.2 used_GB=133.2 / E: free_GB=24.2 used_GB=75.6 | 473f9e3ee821 | - |
| NIC and link speed (Windows equivalent of ethtool) | `Get-CimInstance Win32_NetworkAdapter` | PASS | MediaTek Wi-Fi 6 MT7921 Wireless LAN Card speed_Mbps=827 / VMware Virtual Ethernet Adapter for VMnet1 speed_Mbps=95 / VMware Virtual Ethernet Adapter for VMnet8 speed_Mbps=95 | 3e051557ba98 | XDP native/generic support and BTF (/sys/kernel/btf/vmlinux) cannot be probed on Windows: UNVERIFIED(environment_unsupported); AC-26 needs a Linux lab host. |
| Listeners on 53/80/443 (read-only; nothing is bound by this check) | `Get-NetTCPConnection -State Listen (ports 53,80,443)` | PASS | (none listening) | 22b9bd80e588 | Local profile uses unprivileged defaults (web 8443, proxy 8080/8444, dns 5300) anyway (section 8). |
| NTP / clock sync | `w32tm /query /status` | PASS | Root Dispersion: 4.0990050s / ReferenceId: 0x28515E41 (source IP:  40.81.94.65) / Last Successful Sync Time: 10/18/2026 8:39:10 PM / Source: time.windows.com,0x9 / Poll Interval: 10 (1024s) | 8fdc67833924 | - |
| Chromium-family browser for CDP e2e (chrome/edge path probe only, no launch) | `Test-Path of known install paths` | PASS | C:\Program Files\Google\Chrome\Application\chrome.exe exists=True / C:\Program Files (x86)\Google\Chrome\Application\chrome.exe exists=False / C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe exists=True / C:\Program Files\Microsoft\Edge\Applicatio | 4166e4d46d12 | A Chromium-family browser exists; headless launch under chromiumoxide is proven by T-0075, not here. |
| Installed font files | `count of C:\Windows\Fonts` | PASS | 531 | 06a490ce67ff | - |
| BTF (/sys/kernel/btf/vmlinux) | `Test-Path /sys/kernel/btf/vmlinux` | UNVERIFIED(environment_unsupported) | False | b637eb48fb65 | Linux-only: kernel version, BTF and XDP support are UNVERIFIED(environment_unsupported) on this Windows builder. |
| Outbound connectivity | `(none run)` | UNVERIFIED(human_step_pending) | No egress_allowlist exists yet (hdd.live.yaml not supplied); no outbound request was made. |  | Operator must supply hdd.live.yaml with egress_allowlist (Q-040); connectivity is then probed against those hosts only. |

## Build track decision

**Track L** (no Docker; Windows 11 builder). The embedded PostgreSQL and in-process stores of `hdd-local` (started by `cargo xtask db up`, T-0563) replace testcontainers. Until T-0563 lands, database-dependent checks are UNVERIFIED(`environment_unsupported`) unless a local PostgreSQL is installed; tasks that do not need a database continue.

Hosted-only checks (authoritative DNS on port 53, kernel firewall/XDP, ACME on a public name, STOP #1 and STOP #2) need a Linux host and are UNVERIFIED(`environment_unsupported`) here. Which acceptance checks can run in the `local` tier is printed by `hdd-local doctor` once it exists (T-0564).

## Not covered by this discovery

- The VPS (`deploy_mode: ssh`) was not probed: no SSH account was supplied.
- No runner, lab or origin machine exists in this session.
- Headless browser launch and font rendering are proven by the UI tasks, not here.
