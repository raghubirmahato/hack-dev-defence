//! Runtime state behind three traits (T-0562, R-31, C18.3): [`KvStore`], [`Bus`] and the [`limiter::Limiter`] built on
//! `KvStore::rate_window_check`.
//!
//! Wherever a task says "Redis" for runtime state it means these traits. [`memory::MemoryKv`] is the in-process backend of the
//! `local` profile (and of tests); `redis::RedisKv` (feature `redis`) is the hosted backend. Both are checked by one
//! conformance suite ([`conformance`]). Only this module talks to Redis (`xtask kv-lint`).
//!
//! # Usage contract for the tasks that consume the traits
//!
//! * **Keys** follow B5.12 and are built with [`keys`]; every key has the `hdd:` prefix and a documented TTL; nothing secret is
//!   stored in plaintext. A key is at most [`MAX_KEY_BYTES`] bytes and a value at most [`MAX_VALUE_BYTES`].
//! * **TTL on creation.** `incr`, `hset`, `zadd` and `sadd` apply their TTL when the key is created and leave it alone afterwards
//!   (Redis `EXPIRE ... NX`). `set` replaces the value and the TTL. `None` means no expiry.
//! * **Ban store** (T-0316): `hdd:ban:{org}:{site}:{ip_key}` hashes plus the `hdd:banned_ips` zset (score = expiry in unix ms).
//!   Both live in pinned namespaces of `MemoryKv`: never evicted, capped with [`KvError::PinnedFull`], rebuilt from Postgres by
//!   [`rehydrate`] before listeners open.
//! * **Rate limiter** (T-0333): [`limiter::Limiter::check`] with [`Algorithm::Counter`] for ordinary limits (sliding window
//!   counter with two sub-windows; the estimate differs from the exact sliding count by at most the previous sub-window's
//!   count, so at most one `limit` per window boundary; measured by the conformance suite) and [`Algorithm::Exact`] or
//!   [`Algorithm::Gcra`] for authentication endpoints and ban-triggering limits (never approximate). At most
//!   [`limiter::MAX_SCOPES`] scopes per call; each scope counts the attempt independently.
//! * **Challenge nonces** (T-0108, T-0337): `set` the nonce with a TTL, redeem it once with `challenge_nonce_consume`.
//! * **Session cache** (T-0113): `hdd:sess:{hash}` hashes in a pinned namespace.
//! * **Config bus** (T-0211) and **live event feed** (T-0446): [`Bus`]; a [`BusEvent::Resync`] means "reload from Postgres now".
//! * **Credential-stuffing counters** (T-0343): `incr` with a TTL. **Campaign detection** (T-0325): `sadd` with a TTL and
//!   `scard`-style reads through `smembers`. **Gate and flow engines** (T-0575, T-0577): `hdd:gate:sess:` (pinned) and
//!   `flow_signal_update`.
//! * **Non-durable state resets on restart** (rate counters, nonces, campaign sets, flow counters). That only forgives, it never
//!   blocks; durable state (bans, offences, sessions) is rehydrated.

use std::collections::{BTreeMap, BTreeSet};
use std::future::Future;
use std::time::Duration;

pub mod bus;
pub mod clock;
#[cfg(any(test, feature = "conformance"))]
pub mod conformance;
pub mod keys;
pub mod limiter;
pub mod memory;
pub mod metrics;
pub mod rate;
#[cfg(feature = "redis")]
pub mod redis;
pub mod rehydrate;
mod startup;

pub use bus::{Bus, BusEvent, MemoryBus, ResyncReason, Subscription};
pub use limiter::Limiter;
pub use memory::{MemoryKv, MemoryLimits};
pub use rate::{Algorithm, RateDecision, RateRequest};
pub use startup::{ServiceRegistry, startup_check};

/// Longest accepted key.
pub const MAX_KEY_BYTES: usize = 512;
/// Largest accepted value (bytes, per value or hash field).
pub const MAX_VALUE_BYTES: usize = 1024 * 1024;
/// Most members of one hash, set, sorted set or flow-signal map (an attacker-chosen member name cannot grow one key without bound).
pub const MAX_MEMBERS: usize = 100_000;
/// Most distinct signals of one business flow. `flow_signal_update` returns the whole map on every call, so the cap is small: a
/// flow has a handful of named signals, and an attacker-chosen name must not make every update copy a large map.
pub const MAX_FLOW_SIGNALS: usize = 64;

/// Why a store operation failed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum KvError {
    /// The key is empty, longer than [`MAX_KEY_BYTES`] or contains a control character.
    BadKey(String),
    /// A value is larger than [`MAX_VALUE_BYTES`].
    ValueTooLarge {
        /// Size offered.
        got: usize,
    },
    /// The key holds another kind of value.
    WrongType {
        /// Key (truncated).
        key: String,
    },
    /// The pinned namespace (bans, sessions) is full; nothing was evicted and nothing was written.
    PinnedFull {
        /// Namespace prefix.
        namespace: &'static str,
        /// Its cap in keys.
        cap: usize,
    },
    /// The store is full and nothing could be evicted.
    Full,
    /// One collection already holds [`MAX_MEMBERS`] members ([`MAX_FLOW_SIGNALS`] for a flow) and the new member is not among them.
    CollectionFull {
        /// The cap.
        cap: usize,
    },
    /// An argument is out of range (limit 0, cost above the limit, window too short, ...).
    InvalidArgument(&'static str),
    /// More scopes than [`limiter::MAX_SCOPES`].
    TooManyScopes {
        /// How many were offered.
        got: usize,
    },
    /// The backend cannot be reached or answered with an error (Redis).
    Backend(String),
    /// `HDD_KV_BACKEND=memory` is refused for this deployment.
    MemoryBackendRefused(String),
}

impl std::fmt::Display for KvError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            KvError::BadKey(why) => write!(f, "bad key: {why}"),
            KvError::ValueTooLarge { got } => {
                write!(f, "value of {got} bytes exceeds {MAX_VALUE_BYTES}")
            }
            KvError::WrongType { key } => write!(f, "key `{key}` holds another kind of value"),
            KvError::PinnedFull { namespace, cap } => write!(
                f,
                "pinned namespace `{namespace}` is full ({cap} keys); pinned data is never evicted"
            ),
            KvError::Full => f.write_str("the store is full and nothing can be evicted"),
            KvError::CollectionFull { cap } => {
                write!(f, "the collection already holds {cap} members")
            }
            KvError::InvalidArgument(what) => write!(f, "invalid argument: {what}"),
            KvError::TooManyScopes { got } => {
                write!(f, "{got} scopes exceed the cap of {}", limiter::MAX_SCOPES)
            }
            KvError::Backend(m) => write!(f, "backend error: {m}"),
            KvError::MemoryBackendRefused(m) => f.write_str(m),
        }
    }
}

impl std::error::Error for KvError {}

/// Result of a store operation.
pub type KvResult<T> = Result<T, KvError>;

/// Validate a key the same way for every backend.
pub fn check_key(key: &str) -> KvResult<()> {
    if key.is_empty() {
        return Err(KvError::BadKey("empty".into()));
    }
    if key.len() > MAX_KEY_BYTES {
        return Err(KvError::BadKey(format!(
            "{} bytes exceeds {MAX_KEY_BYTES}",
            key.len()
        )));
    }
    if key.chars().any(char::is_control) {
        return Err(KvError::BadKey("contains a control character".into()));
    }
    Ok(())
}

/// Validate a value size the same way for every backend.
pub fn check_value(value: &[u8]) -> KvResult<()> {
    if value.len() > MAX_VALUE_BYTES {
        Err(KvError::ValueTooLarge { got: value.len() })
    } else {
        Ok(())
    }
}

/// Key-value operations with identical semantics in every backend.
///
/// Methods return `impl Future + Send` so that the trait works with any executor without boxing.
pub trait KvStore: Send + Sync {
    /// `memory` or `redis` (metric label).
    fn backend(&self) -> &'static str;

    /// Value of a string key.
    fn get(&self, key: &str) -> impl Future<Output = KvResult<Option<Vec<u8>>>> + Send;
    /// Store a string value, replacing the value and the TTL.
    fn set(
        &self,
        key: &str,
        value: &[u8],
        ttl: Option<Duration>,
    ) -> impl Future<Output = KvResult<()>> + Send;
    /// Delete a key of any type; true when it existed.
    fn del(&self, key: &str) -> impl Future<Output = KvResult<bool>> + Send;
    /// True when the key exists.
    fn exists(&self, key: &str) -> impl Future<Output = KvResult<bool>> + Send;
    /// Set the TTL of an existing key; false when the key does not exist.
    fn expire(&self, key: &str, ttl: Duration) -> impl Future<Output = KvResult<bool>> + Send;
    /// Remaining TTL; `None` when the key is missing or has no expiry.
    fn ttl(&self, key: &str) -> impl Future<Output = KvResult<Option<Duration>>> + Send;

    /// Add `by` to an integer key (created as 0, with `ttl` on creation) and return the new value.
    fn incr(
        &self,
        key: &str,
        by: i64,
        ttl: Option<Duration>,
    ) -> impl Future<Output = KvResult<i64>> + Send;

    /// Set a hash field (the hash is created with `ttl` when it does not exist).
    fn hset(
        &self,
        key: &str,
        field: &str,
        value: &[u8],
        ttl: Option<Duration>,
    ) -> impl Future<Output = KvResult<()>> + Send;
    /// Read a hash field.
    fn hget(
        &self,
        key: &str,
        field: &str,
    ) -> impl Future<Output = KvResult<Option<Vec<u8>>>> + Send;
    /// Read the whole hash (empty when missing).
    fn hgetall(
        &self,
        key: &str,
    ) -> impl Future<Output = KvResult<BTreeMap<String, Vec<u8>>>> + Send;

    /// Add or update a sorted-set member; true when the member is new.
    fn zadd(
        &self,
        key: &str,
        score: f64,
        member: &str,
        ttl: Option<Duration>,
    ) -> impl Future<Output = KvResult<bool>> + Send;
    /// Members with `min <= score <= max`, by ascending score then member, at most `limit`.
    fn zrange_by_score(
        &self,
        key: &str,
        min: f64,
        max: f64,
        limit: usize,
    ) -> impl Future<Output = KvResult<Vec<(String, f64)>>> + Send;
    /// Remove a sorted-set member; true when it existed.
    fn zrem(&self, key: &str, member: &str) -> impl Future<Output = KvResult<bool>> + Send;
    /// Number of members.
    fn zcard(&self, key: &str) -> impl Future<Output = KvResult<usize>> + Send;

    /// Add a set member (the set is created with `ttl`); true when the member is new.
    fn sadd(
        &self,
        key: &str,
        member: &str,
        ttl: Option<Duration>,
    ) -> impl Future<Output = KvResult<bool>> + Send;
    /// All members, sorted.
    fn smembers(&self, key: &str) -> impl Future<Output = KvResult<BTreeSet<String>>> + Send;

    /// Replace the value when the current value equals `expected` (`None` means "must not exist"); true when replaced.
    fn compare_and_set(
        &self,
        key: &str,
        expected: Option<&[u8]>,
        new: &[u8],
        ttl: Option<Duration>,
    ) -> impl Future<Output = KvResult<bool>> + Send;

    /// Named atomic operation: one rate-limit decision (see [`rate`] for the exact semantics of each algorithm).
    fn rate_window_check(
        &self,
        key: &str,
        req: &RateRequest,
    ) -> impl Future<Output = KvResult<RateDecision>> + Send;
    /// Named atomic operation: get and delete in one step (challenge replay protection); the value, once.
    fn challenge_nonce_consume(
        &self,
        key: &str,
    ) -> impl Future<Output = KvResult<Option<Vec<u8>>>> + Send;
    /// Named atomic operation: progressive ban ladder. The stored count first loses one for every whole `decay` since the last
    /// offence (never below zero), then gains one; the key lives `ttl` from now. Returns the new count.
    fn offence_incr_with_decay(
        &self,
        key: &str,
        decay: Duration,
        ttl: Duration,
    ) -> impl Future<Output = KvResult<u32>> + Send;
    /// Named atomic operation: record one signal of a business flow and return the counts of every signal seen so far for the
    /// key (the key is created with `ttl`).
    fn flow_signal_update(
        &self,
        key: &str,
        signal: &str,
        ttl: Duration,
    ) -> impl Future<Output = KvResult<BTreeMap<String, u64>>> + Send;
}

#[cfg(test)]
mod tests;
#[cfg(test)]
mod tests_review;
