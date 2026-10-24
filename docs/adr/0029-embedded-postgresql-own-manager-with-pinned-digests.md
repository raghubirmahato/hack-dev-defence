# ADR-0029: Embedded PostgreSQL (own manager with pinned digests)

- Status: **accepted**
- Deciding task: [T-0563](../tasks/P33/T-0563.md) · Embedded PostgreSQL manager and `cargo xtask db up`
- Date opened / decided: opened and decided 2026-10-19
- Deciders: agent (section 0.5), within R-08, R-22, R-31 and the safety rules about downloads

## Context

A machine without Docker or a database server (Track L) still has to build, test and run the local profile against a real
PostgreSQL. T-0563 step 1 asks for a spike: the `postgresql_embedded` crate or an equivalent, with SHA-256 and signature
verification, a pinned download host that must be in `egress_allowlist`, an offline bundle path, and per-OS binaries (Windows x64,
macOS arm64 and x64, Linux x64 and arm64).

Facts gathered on 2026-10-19 (registry and GitHub API, read only):

| Candidate | State |
| --- | --- |
| `postgresql_embedded` 0.21.0 (with `postgresql_archive` 0.21.0 and `postgresql_commands`) | Maintained (released 2026-07-19); licence `(Apache-2.0 OR MIT) AND PostgreSQL`. `postgresql_archive` has 26 direct dependencies, among them `reqwest` with middleware, `sha1`, `md-5`, `zip` and `liblzma`; `postgresql_embedded` depends on `sqlx`. It resolves "latest matching" versions at run time and downloads with its own HTTP client |
| `theseus-rs/postgresql-binaries` (the distribution behind it) | Pushed 2026-10-18; PostgreSQL 16, 17 and 18 lines; for every release and target a `.tar.gz`, a `.sha256`, an SBOM, an SPDX document and SLSA provenance. Windows x64 is 48 MB, Linux x64 40 MB, macOS arm64 90 MB. Targets include all five that T-0563 names |
| Zonky embedded-postgres-binaries (Maven Central) | Same five targets; artifacts are PGP-signed, but verifying a PGP signature needs a PGP implementation and a pinned signer key, neither of which exists in the workspace |
| EDB zip files | Official, but x86-64 only for Windows and Linux and no macOS arm64 build |

## Options considered

| Option | Pros | Cons | Spike or evidence link |
| --- | --- | --- | --- |
| Own manager (`hdd-local::pg`) over the `postgresql-binaries` archives, with the version, file name, size and SHA-256 pinned in `crates/hdd-local/postgres-manifest.toml` and the download made through `hdd-common::egress` | One outbound path (R-22); the digest is chosen by us and compiled in, so neither the host nor the release page can change what runs; no run-time version resolution; small additions (`flate2`, `tar`, `chacha20poly1305`) | We maintain the lifecycle code (initdb, hba, start/stop, roles, backup) | `crates/hdd-local/src/pg/`, tests `a2_a_binary_with_a_wrong_checksum_is_refused_and_nothing_is_installed_or_started`, `extraction_refuses_traversal_absolute_paths_escaping_links_and_special_files` |
| `postgresql_embedded` crate | Less code to write | Its HTTP client bypasses the egress module (R-22 forbids `reqwest` outside it, and the rule is enforced by `xtask rules`); it fetches by version requirement, so the digest it checks comes from the same release page it downloads from; about 25 more crates for archive handling alone | `cargo info`, the dependency list above |
| Zonky binaries with PGP verification | A real signature chain | Adds a PGP stack and a key-distribution problem; Maven Central is another host to approve | n/a |
| Require an external PostgreSQL or Docker | Nothing to build | That is exactly what Track L lacks | n/a |

## Decision

Build the manager ourselves and pin the archives. Reason: R-22 requires every outbound connection to go through the egress module
and R-08 asks for the smallest vetted dependency set; a pinned digest in the repository is a stronger check than a checksum file
published next to the archive, because the digest is reviewed in a commit rather than fetched at run time.

- **Verification.** Size and SHA-256 are compared before anything is extracted (A2). The pinned digests are the ones the distributor
  publishes in its `.sha256` files, fetched on 2026-10-19 by a script and not typed; the archive of the builder's own target was
  also hashed after download (evidence under `docs/evidence/P33/`). Verification of the SLSA provenance and SBOM attestations that
  accompany each archive is **not implemented**: it is UNVERIFIED and a candidate for a later task.
- **Download.** Only through `hdd-common::egress` and only to the allowlist entries the operator supplies
  (`https://github.com/theseus-rs/postgresql-binaries/releases/download/<tag>/` and the host GitHub redirects release assets to,
  `https://release-assets.githubusercontent.com/`). Giving `--allow` on the command line is the approval of that destination.
  Offline: `--bundle <archive>` (verified identically).
- **Extraction.** Absolute paths, `..`, backslashes, drive prefixes, device nodes and links that leave the destination are refused;
  at most 100,000 entries and 3 GiB.
- **Version.** PostgreSQL 17 (supported until 2029; HC-15 asks for 16 or newer). A data directory written by another major version
  is refused with instructions to migrate by dump and restore, never in place.
- **Substitute.** If the embedded route proves unreliable on an operating system, the substitute is an external server
  (`runtime.local.database: external`) or Compose; `hdd-local doctor` (T-0564) reports which one is in use.

## Consequences

`hdd-local` becomes a library plus the binary and gains `flate2` (rust backend), `tar` (no default features), `chacha20poly1305`
and `clap` (already vetted). The xtask depends on `hdd-local` for `cargo xtask db`. The Job Object that makes Windows kill the
server when the supervisor dies needs `unsafe` and belongs to the supervisor (T-0564); until then a crash of the front end leaves
the server running, and `db up` reuses it (a stale `postmaster.pid` is handled by `pg_ctl`).

## Security impact

The server listens on `127.0.0.1` only, authenticates with `scram-sha-256` only, has data checksums on, and `pg_hba.conf` has two
loopback lines and nothing else. Passwords are generated (256 bits), live in owner-only files and reach the bundled programs
through `PGPASSFILE` or standard input, never through a command line or an environment variable. Services read the connection URL
from a file. Backups are encrypted (ChaCha20-Poly1305, chunked, authenticated with index and end-of-file flag) with a key that
survives `db reset`.

## Rollback plan

Remove `hdd-local::pg` and the `db` commands: nothing else depends on them yet (T-0564 and T-0105 are the first consumers). A
data directory created by the manager is an ordinary PostgreSQL cluster and can be started with any PostgreSQL 17 binary.

## Links

- Task: [T-0563](../tasks/P33/T-0563.md)
- Related: [ADR-0027](0027-one-code-path-two-runtime-profiles.md), [ADR-0028](0028-redis-client-redis-rs-instead-of-fred.md)
