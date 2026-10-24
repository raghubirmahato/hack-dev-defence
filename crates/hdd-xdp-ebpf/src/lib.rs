//! `hdd-xdp-ebpf`: kernel program (only crate allowed unsafe).
//!
//! Scaffold (T-0004). Built only by `cargo xtask xdp build` (T-0466) with the pinned nightly
//! toolchain. `unsafe` is permitted in this crate alone, under ADR-0025, with verifier and
//! packet-level tests (T-0466). The decision logic lives in `hdd-xdp-logic`.
#![no_std]
