//! `hdd-common`: config, models, kv traits (KvStore, Bus, Limiter) with Redis and in-process backends, pub/sub messages, errors, Ray ID, client-IP resolution, egress client, profile.
//!
//! Implemented so far: the Live Target Profile (`profile`, T-0006), small network value types (`net`) and the egress
//! allowlist (`egress`, T-0009). The other responsibilities listed above belong to later tasks (see `ARCHITECTURE.md`).
#![forbid(unsafe_code)]

pub mod buildplan;
pub mod egress;
pub mod kv;
pub mod net;
pub mod parity;
pub mod profile;
