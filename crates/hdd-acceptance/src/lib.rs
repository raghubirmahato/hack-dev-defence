//! `hdd-acceptance`: the acceptance runner skeleton (T-0215, `REQ-WSK-09`).
//!
//! The runner carries every acceptance check of Appendix E3. This crate is the part that must exist before any check can send
//! traffic: the safety envelope is encoded here first and tested before a send function exists (task acceptance A1).
//!
//! * [`status`]: the closed status taxonomy of E3.1 (`PASS`, `FAIL(reason)`, `UNVERIFIED(reason_code)`) and the status line.
//! * [`limits`]: the five rate/load profiles of section 2.3, their hard ceilings and the one token-bucket limiter every check
//!   shares. The limiter takes an injectable [`hdd_common::kv::clock::Clock`], so rate and duration behaviour is measured in
//!   tests without sleeping (A2).
//! * [`guard`]: payload classes A/B/C, the [`hdd_common::egress::TargetGuard`] wrapper derived from the live profile, the
//!   egress allowlist for infrastructure destinations, and the connector seam. [`guard::Sender`] is a trait: this crate ships
//!   **no** real sender yet, so nothing can leave a machine from this code (A1 is tested with a recording sender).
//! * [`inspect`]: the inspect-first gate ([`inspect::InspectGate`]) calling `POST /api/v1/waf/inspect` through a typed client.
//!   It refuses to hand out a send ticket when `would_block` is false or the `config_revision` changed (A5).
//! * [`runner`]: the [`runner::Check`] trait, dependency ordering, the `finally` cleanup stack, per-check timeouts, kill-switch
//!   and signal handling (A3).
//! * [`control`]: out-of-band control-plane plumbing without network access: the runner-IP bannability check, SSH argv
//!   construction that never runs a command, and the vantage-point plan.
//! * [`report`]: JSON and Markdown reports, one status line per registered id, evidence blocks, redaction, saved logs with
//!   SHA-256 and the tail embedded.
//! * [`registry`]: AC-00 to AC-62 as typed rows, each `UNVERIFIED(stage_not_reached)` by default, cross-checked against the
//!   specification by parsing `docs/SPEC.md` and `docs/spec/E3.md` whole-token (A4).
//! * [`config`]: profile loading and validation through `hdd_common::profile`, lifecycle-stage rules, load-profile approval
//!   and the assembled [`config::RunnerConfig`].
//!
//! Nothing in this crate opens a socket, spawns a process or writes to a network interface. `docs/ACCEPTANCE.md` describes the
//! status taxonomy, the evidence layout and what is still unimplemented.
//!
//! The safety invariants are **crate-private conventions**, not a security boundary (review items R-3 and S-1/S-2/S-6, and the
//! round-3 scope note). The threat model is a check written by us that makes a mistake, not hostile code compiled into this
//! crate: a check body cannot *name* the connector constructor, the rate budget, the abort latch, the check context, the
//! inspect gate or an evidence reference, so accidental misuse cannot turn off the destructive flag, start a fresh limiter,
//! widen the allowlist with a profile of its own, mint an inspect ticket or fabricate a PASS. Rust privacy is a compile-time
//! convention; code inside this crate (or `unsafe`/build-script tricks outside it) is outside that guarantee. What is
//! *actually* enforced at runtime is the run's shared state and the evidence write records, not the visibility alone.
//!
//! The doc-tests below fail to compile, which is the property under test. `compile_fail` has no error-code form in rustdoc
//! (annotating it with `,EXXXX` is silently ignored and would still pass on a different error), so the exact code of each
//! snippet is asserted by the `tests/compile_fail_codes.rs` integration test (review item N-9).
//!
//! ```compile_fail
//! // `Connector::new` is crate-private: only `CheckContext::connector` (built by the executor) can create one.
//! let _ = hdd_acceptance::guard::Connector::new;
//! ```
//!
//! ```compile_fail
//! // The connector takes no profile argument: the profile comes from the executor (review item S-1), so this old signature
//! // must not compile even if a caller has a `Profile` to pass.
//! fn probe(ctx: &hdd_acceptance::runner::CheckContext) {
//!     let _ = ctx.connector("rev-1", "a profile cannot be passed here");
//! }
//! ```
//!
//! ```compile_fail
//! // `InspectGate::new` is crate-private: a check cannot build a gate and mint a ticket (review item S-2).
//! struct FakeClient;
//! impl hdd_acceptance::inspect::InspectClient for FakeClient {
//!     fn inspect(
//!         &mut self,
//!         _request: &hdd_acceptance::inspect::InspectRequest,
//!     ) -> Result<
//!         hdd_acceptance::inspect::InspectResponse,
//!         hdd_acceptance::inspect::InspectClientError,
//!     > {
//!         unimplemented!()
//!     }
//! }
//! let _ = hdd_acceptance::inspect::InspectGate::new(FakeClient, "rev-1");
//! ```
//!
//! ```compile_fail
//! // `CheckContext::new` is crate-private: a check body cannot forge the destructive flag or a fresh latch.
//! let _ = hdd_acceptance::runner::CheckContext::new;
//! ```
//!
//! ```compile_fail
//! // `EvidenceRef::new` is crate-private: only `EvidenceStore` hashes the bytes it wrote, and the executor re-verifies them.
//! let _ = hdd_acceptance::status::EvidenceRef::new;
//! ```
//!
//! ```compile_fail
//! // `AbortLatch::new` and `RunInvalidLatch::new` are crate-private: only the executor creates the run's latches.
//! let _ = hdd_acceptance::runner::AbortLatch::new;
//! ```
//!
//! ```compile_fail
//! // `EvidenceRef` has private fields: a struct literal cannot bypass the store (review item S-6).
//! let _ = hdd_acceptance::status::EvidenceRef {
//!     path: "x".into(),
//!     sha256: String::new(),
//!     bytes: 0,
//! };
//! ```
//!
//! ```compile_fail
//! // `AbortLatch` has no `Default` impl: only the executor builds the run's latches (review item S-6).
//! let _: hdd_acceptance::runner::AbortLatch = Default::default();
//! ```
#![forbid(unsafe_code)]

pub mod config;
pub mod control;
pub mod guard;
pub mod inspect;
pub mod limits;
pub mod registry;
pub mod report;
pub mod runner;
pub mod status;

#[cfg(test)]
pub(crate) mod test_support;
