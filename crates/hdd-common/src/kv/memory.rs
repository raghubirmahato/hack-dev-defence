//! `MemoryKv`: the in-process backend (local profile, tests). Same semantics as Redis, checked by the same conformance suite.
//!
//! * **Sharded maps.** Keys hash to one of N shards, each behind its own mutex. Every operation, including the named atomic
//!   ones, runs under one shard lock, so each is atomic; no operation touches two shards.
//! * **TTL.** Per-key expiry in microseconds on an injectable [`Clock`]. Expiry is lazy on access plus a sweeper
//!   ([`MemoryKv::sweep`], [`MemoryKv::spawn_sweeper`]) that pops an expiry heap, so an expired key is never visible and idle
//!   expired keys do not hold memory for long.
//! * **Bounded memory.** Each shard holds at most `max_keys / shards` keys and `max_bytes / shards` bytes. An insert that would
//!   exceed a cap first drops expired keys, then the least recently used evictable key; the evictions are counted.
//! * **Pinned namespaces** (`hdd:banned_ips`, `hdd:ban:`, `hdd:sess:`, `hdd:gate:sess:`): never evicted. They are capped as a
//!   group by `pinned_max_keys`; a new pinned key beyond the cap fails with [`KvError::PinnedFull`] and writes nothing (existing
//!   pinned keys can still be updated).

use std::cmp::Reverse;
use std::collections::{BTreeMap, BTreeSet, BinaryHeap, HashMap};
use std::hash::{BuildHasher, RandomState};
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::Duration;

use super::clock::{Clock, SystemClock};
use super::rate::{RateDecision, RateEntry, RateRequest};
use super::{KvError, KvResult, KvStore, MAX_FLOW_SIGNALS, MAX_MEMBERS, check_key, check_value};

/// Prefixes of the pinned namespaces (bans and sessions).
pub const PINNED_NAMESPACES: &[&str] =
    &["hdd:banned_ips", "hdd:ban:", "hdd:sess:", "hdd:gate:sess:"];

fn pinned_namespace(key: &str) -> Option<&'static str> {
    PINNED_NAMESPACES
        .iter()
        .copied()
        .find(|p| key.starts_with(p))
}

/// Capacity of a [`MemoryKv`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MemoryLimits {
    /// Number of shards (at least 1).
    pub shards: usize,
    /// Maximum number of keys (all shards together, divided evenly).
    pub max_keys: usize,
    /// Maximum approximate size in bytes (divided evenly).
    pub max_bytes: usize,
    /// Maximum number of keys in the pinned namespaces together.
    pub pinned_max_keys: usize,
}

impl Default for MemoryLimits {
    fn default() -> Self {
        MemoryLimits {
            shards: 16,
            max_keys: 1_000_000,
            max_bytes: 512 * 1024 * 1024,
            pinned_max_keys: 500_000,
        }
    }
}

/// Counters of the store's housekeeping (also exported as metrics by the caller).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct MemoryStats {
    /// Keys dropped because their TTL ran out.
    pub expired: u64,
    /// Keys evicted to make room (least recently used first).
    pub evicted: u64,
    /// New pinned keys refused because the pinned cap was reached.
    pub pinned_rejected: u64,
    /// Writes refused because nothing could be evicted.
    pub full_rejected: u64,
}

#[derive(Debug, Clone)]
enum Value {
    Str(Vec<u8>),
    Int(i64),
    Hash(BTreeMap<String, Vec<u8>>),
    ZSet(BTreeMap<String, f64>),
    Set(BTreeSet<String>),
    Rate(RateEntry),
    Offence { count: u32, last_us: u64 },
    Flow(BTreeMap<String, u64>),
}

impl Value {
    /// Size of a value at creation, beyond the entry overhead (collections grow through `resize`).
    fn initial_bytes(&self) -> usize {
        match self {
            Value::Rate(r) => r.approx_bytes(),
            _ => 0,
        }
    }
}

struct Entry {
    value: Value,
    expires_us: Option<u64>,
    stamp: u64,
    bytes: usize,
    pinned: bool,
}

/// Estimated cost of one entry beyond its key and value: the map slot, the LRU node, the expiry-heap entry and the shared key.
const ENTRY_OVERHEAD: usize = 256;
/// Expired heap entries examined on every write, so that housekeeping needs no sweeper to stay bounded.
const PURGE_PER_WRITE: usize = 4;

#[derive(Default)]
struct Shard {
    map: HashMap<Arc<str>, Entry>,
    /// Evictable keys by last access, oldest first. Pinned keys are not in it.
    lru: BTreeMap<u64, Arc<str>>,
    expiry: BinaryHeap<Reverse<(u64, Arc<str>)>>,
    bytes: usize,
    stamp: u64,
}

/// What an operation wants done with the key afterwards.
enum Ttl {
    /// No expiry.
    Clear,
    /// Expire at this time.
    At(u64),
}

struct Counters {
    expired: AtomicU64,
    evicted: AtomicU64,
    pinned_rejected: AtomicU64,
    full_rejected: AtomicU64,
}

/// The in-process store.
pub struct MemoryKv {
    shards: Vec<Mutex<Shard>>,
    /// Answers `shard_of` if the index were ever out of range (it cannot be: the index is taken modulo the shard count). It
    /// exists so that the function is total without indexing.
    fallback: Mutex<Shard>,
    hasher: RandomState,
    clock: Arc<dyn Clock>,
    shard_max_keys: usize,
    shard_max_bytes: usize,
    pinned_max_keys: usize,
    pinned_count: AtomicUsize,
    counters: Counters,
}

fn lock(m: &Mutex<Shard>) -> MutexGuard<'_, Shard> {
    m.lock().unwrap_or_else(PoisonError::into_inner)
}

/// The integers Redis accepts for `INCRBY`: an optional minus sign, no plus sign, no leading zeros, fitting an `i64`.
pub(crate) fn parse_redis_int(b: &[u8]) -> Option<i64> {
    let s = std::str::from_utf8(b).ok()?;
    let digits = s.strip_prefix('-').unwrap_or(s);
    let ok = digits == "0" && s == "0"
        || (digits
            .as_bytes()
            .first()
            .is_some_and(|c| (b'1'..=b'9').contains(c))
            && digits.bytes().all(|c| c.is_ascii_digit()));
    if ok { s.parse::<i64>().ok() } else { None }
}

fn ttl_us(ttl: Option<Duration>) -> Option<u64> {
    ttl.map(|d| u64::try_from(d.as_micros()).unwrap_or(u64::MAX).max(1))
}

fn remaining(expires: u64, now: u64) -> Duration {
    Duration::from_micros(expires.saturating_sub(now))
}

impl MemoryKv {
    /// A store with the default capacity and the real clock.
    pub fn new() -> MemoryKv {
        MemoryKv::with(MemoryLimits::default(), Arc::new(SystemClock::new()))
    }

    /// A store with explicit capacity and clock.
    pub fn with(limits: MemoryLimits, clock: Arc<dyn Clock>) -> MemoryKv {
        let shards = limits.shards.max(1);
        MemoryKv {
            shards: (0..shards).map(|_| Mutex::new(Shard::default())).collect(),
            fallback: Mutex::new(Shard::default()),
            hasher: RandomState::new(),
            clock,
            shard_max_keys: limits.max_keys.div_ceil(shards).max(1),
            shard_max_bytes: limits.max_bytes.div_ceil(shards).max(1),
            pinned_max_keys: limits.pinned_max_keys,
            pinned_count: AtomicUsize::new(0),
            counters: Counters {
                expired: AtomicU64::new(0),
                evicted: AtomicU64::new(0),
                pinned_rejected: AtomicU64::new(0),
                full_rejected: AtomicU64::new(0),
            },
        }
    }

    /// Entries in the expiry heaps (test and monitoring hook; bounded by a small multiple of the live keys).
    pub fn expiry_heap_len(&self) -> usize {
        self.shards.iter().map(|s| lock(s).expiry.len()).sum()
    }

    /// Housekeeping counters.
    pub fn stats(&self) -> MemoryStats {
        MemoryStats {
            expired: self.counters.expired.load(Ordering::Relaxed),
            evicted: self.counters.evicted.load(Ordering::Relaxed),
            pinned_rejected: self.counters.pinned_rejected.load(Ordering::Relaxed),
            full_rejected: self.counters.full_rejected.load(Ordering::Relaxed),
        }
    }

    /// Number of live keys (expired keys that were not swept yet are not counted).
    pub fn len(&self) -> usize {
        let now = self.clock.now_us();
        self.shards
            .iter()
            .map(|s| {
                lock(s)
                    .map
                    .values()
                    .filter(|e| e.expires_us.is_none_or(|x| x > now))
                    .count()
            })
            .sum()
    }

    /// True when no live key exists.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Number of live keys in the pinned namespaces.
    pub fn pinned_len(&self) -> usize {
        self.pinned_count.load(Ordering::Relaxed)
    }

    /// Approximate bytes held.
    pub fn approx_bytes(&self) -> usize {
        self.shards.iter().map(|s| lock(s).bytes).sum()
    }

    /// Drop every expired key now; returns how many.
    pub fn sweep(&self) -> usize {
        let now = self.clock.now_us();
        let mut total = 0;
        for s in &self.shards {
            let mut sh = lock(s);
            total += self.purge_expired(&mut sh, now);
        }
        total
    }

    /// Sweep every `interval` on the runtime until the returned handle is aborted or the store is dropped.
    pub fn spawn_sweeper(self: &Arc<Self>, interval: Duration) -> tokio::task::JoinHandle<()> {
        let weak = Arc::downgrade(self);
        tokio::spawn(async move {
            let mut tick = tokio::time::interval(interval);
            loop {
                tick.tick().await;
                let Some(kv) = weak.upgrade() else { return };
                kv.sweep();
            }
        })
    }

    fn shard_of(&self, key: &str) -> &Mutex<Shard> {
        let h = self.hasher.hash_one(key);
        let n = self.shards.len();
        let i = usize::try_from(h % n as u64).unwrap_or(0);
        self.shards.get(i).unwrap_or(&self.fallback)
    }

    fn remove(&self, sh: &mut Shard, key: &str, expired: bool) -> bool {
        let Some((k, e)) = sh.map.remove_entry(key) else {
            return false;
        };
        sh.bytes = sh.bytes.saturating_sub(e.bytes);
        if e.pinned {
            self.pinned_count.fetch_sub(1, Ordering::Relaxed);
        } else {
            sh.lru.remove(&e.stamp);
        }
        drop(k);
        if expired {
            self.counters.expired.fetch_add(1, Ordering::Relaxed);
        }
        true
    }

    fn purge_expired(&self, sh: &mut Shard, now: u64) -> usize {
        self.purge_some(sh, now, usize::MAX)
    }

    /// Drop up to `max` expiry-heap entries that are due (stale entries count against `max` too).
    fn purge_some(&self, sh: &mut Shard, now: u64, max: usize) -> usize {
        let mut n = 0;
        let mut looked = 0;
        while let Some(Reverse((at, _))) = sh.expiry.peek() {
            if looked >= max {
                break;
            }
            looked += 1;
            if *at > now {
                break;
            }
            let Some(Reverse((at, key))) = sh.expiry.pop() else {
                break;
            };
            // The heap may hold stale entries for keys that were re-set or deleted.
            if sh.map.get(&key).is_some_and(|e| e.expires_us == Some(at))
                && self.remove(sh, &key, true)
            {
                n += 1;
            }
        }
        n
    }

    /// Drop the key if it has expired.
    fn expire_if_due(&self, sh: &mut Shard, key: &str, now: u64) {
        if sh
            .map
            .get(key)
            .is_some_and(|e| e.expires_us.is_some_and(|x| x <= now))
        {
            self.remove(sh, key, true);
        }
    }

    fn touch(sh: &mut Shard, key: &str) {
        sh.stamp += 1;
        let stamp = sh.stamp;
        let Some(e) = sh.map.get_mut(key) else { return };
        if !e.pinned
            && let Some(k) = sh.lru.remove(&e.stamp)
        {
            sh.lru.insert(stamp, k);
        }
        e.stamp = stamp;
    }

    /// Reserve one slot of the pinned cap (atomically: concurrent inserts in other shards cannot overshoot it). Expired pinned
    /// keys of this shard are dropped first, since they would otherwise count until a sweep.
    fn reserve_pinned(&self, sh: &mut Shard, ns: &'static str, now: u64) -> KvResult<()> {
        let take = || {
            self.pinned_count
                .fetch_update(Ordering::AcqRel, Ordering::Acquire, |c| {
                    (c < self.pinned_max_keys).then_some(c + 1)
                })
                .is_ok()
        };
        if take() {
            return Ok(());
        }
        self.purge_expired(sh, now);
        if take() {
            return Ok(());
        }
        self.counters
            .pinned_rejected
            .fetch_add(1, Ordering::Relaxed);
        Err(KvError::PinnedFull {
            namespace: ns,
            cap: self.pinned_max_keys,
        })
    }

    /// Make room for one new key of about `bytes` bytes. For a pinned key a slot of the pinned cap is reserved (and released
    /// again when this fails, so a failed insert leaves nothing behind).
    fn make_room(&self, sh: &mut Shard, key: &str, bytes: usize, now: u64) -> KvResult<()> {
        let pinned = pinned_namespace(key);
        if let Some(ns) = pinned {
            self.reserve_pinned(sh, ns, now)?;
        }
        let released = |this: &MemoryKv| {
            if pinned.is_some() {
                this.pinned_count.fetch_sub(1, Ordering::Relaxed);
            }
        };
        let over = |sh: &Shard| {
            sh.map.len() >= self.shard_max_keys || sh.bytes + bytes > self.shard_max_bytes
        };
        if over(sh) {
            self.purge_expired(sh, now);
        }
        while over(sh) {
            let Some((&stamp, _)) = sh.lru.iter().next() else {
                self.counters.full_rejected.fetch_add(1, Ordering::Relaxed);
                released(self);
                return Err(KvError::Full);
            };
            if let Some(victim) = sh.lru.remove(&stamp)
                && let Some((_, e)) = sh.map.remove_entry(&*victim)
            {
                sh.bytes = sh.bytes.saturating_sub(e.bytes);
                self.counters.evicted.fetch_add(1, Ordering::Relaxed);
            }
        }
        Ok(())
    }

    /// The live entry for `key`, or a fresh one made by `make` (after making room). `ttl` applies to a created entry only.
    fn entry_or_insert<'a>(
        &self,
        sh: &'a mut Shard,
        key: &str,
        now: u64,
        ttl: Option<u64>,
        make: impl FnOnce() -> Value,
    ) -> KvResult<&'a mut Entry> {
        self.expire_if_due(sh, key, now);
        self.purge_some(sh, now, PURGE_PER_WRITE);
        if !sh.map.contains_key(key) {
            let value = make();
            let bytes = key.len()
                + ENTRY_OVERHEAD
                + match &value {
                    Value::Str(v) => v.len(),
                    other => other.initial_bytes(),
                };
            self.make_room(sh, key, bytes, now)?;
            let k: Arc<str> = Arc::from(key);
            let pinned = pinned_namespace(key).is_some();
            sh.stamp += 1;
            let stamp = sh.stamp;
            let expires_us = ttl.map(|t| now.saturating_add(t));
            if let Some(at) = expires_us {
                sh.expiry.push(Reverse((at, Arc::clone(&k))));
            }
            // a pinned key already holds its slot of the cap (reserved by `make_room`)
            if !pinned {
                sh.lru.insert(stamp, Arc::clone(&k));
            }
            sh.bytes += bytes;
            sh.map.insert(
                k,
                Entry {
                    value,
                    expires_us,
                    stamp,
                    bytes,
                    pinned,
                },
            );
        } else {
            Self::touch(sh, key);
        }
        sh.map.get_mut(key).ok_or(KvError::Full)
    }

    /// Account a change of an entry's size.
    fn resize(sh: &mut Shard, key: &str, delta: isize) {
        if let Some(e) = sh.map.get_mut(key) {
            let new = e.bytes.saturating_add_signed(delta);
            sh.bytes = sh.bytes.saturating_sub(e.bytes) + new;
            e.bytes = new;
        }
    }

    fn set_ttl(sh: &mut Shard, key: &str, ttl: Ttl) {
        let Some(e) = sh.map.get_mut(key) else { return };
        match ttl {
            Ttl::Clear => e.expires_us = None,
            Ttl::At(at) => {
                e.expires_us = Some(at);
                if let Some((k, _)) = sh.map.get_key_value(key) {
                    sh.expiry.push(Reverse((at, Arc::clone(k))));
                }
                // every re-set leaves a stale heap entry behind; rebuild the heap when they outnumber the live keys
                if sh.expiry.len() > 4 * sh.map.len() + 1024 {
                    sh.expiry = sh
                        .map
                        .iter()
                        .filter_map(|(k, e)| e.expires_us.map(|at| Reverse((at, Arc::clone(k)))))
                        .collect();
                }
            }
        }
    }

    /// Replace the value of a key in place (whatever it held), or create it. Nothing is removed before the replacement is known
    /// to fit, so a refused write leaves the old value (a ban, a session) untouched.
    fn replace_value(
        &self,
        sh: &mut Shard,
        key: &str,
        now: u64,
        value: Value,
        expires: Option<u64>,
    ) -> KvResult<()> {
        self.expire_if_due(sh, key, now);
        if sh.map.contains_key(key) {
            Self::touch(sh, key);
            let new_bytes = key.len()
                + ENTRY_OVERHEAD
                + match &value {
                    Value::Str(v) => v.len(),
                    other => other.initial_bytes(),
                };
            if let Some(e) = sh.map.get_mut(key) {
                sh.bytes = sh.bytes.saturating_sub(e.bytes) + new_bytes;
                e.bytes = new_bytes;
                e.value = value;
            }
            Self::set_ttl(sh, key, expires.map_or(Ttl::Clear, Ttl::At));
            // a larger value may push the shard over its byte cap: evict other evictable keys, never this one
            while sh.bytes > self.shard_max_bytes {
                let victim = sh
                    .lru
                    .iter()
                    .find(|(_, k)| &***k != key)
                    .map(|(s, k)| (*s, Arc::clone(k)));
                let Some((stamp, victim)) = victim else { break };
                sh.lru.remove(&stamp);
                if let Some((_, e)) = sh.map.remove_entry(&*victim) {
                    sh.bytes = sh.bytes.saturating_sub(e.bytes);
                    self.counters.evicted.fetch_add(1, Ordering::Relaxed);
                }
            }
            return Ok(());
        }
        self.entry_or_insert(sh, key, now, None, || value)?;
        Self::set_ttl(sh, key, expires.map_or(Ttl::Clear, Ttl::At));
        Ok(())
    }

    fn wrong_type(key: &str) -> KvError {
        KvError::WrongType {
            key: key.chars().take(64).collect(),
        }
    }
}

impl Default for MemoryKv {
    fn default() -> Self {
        MemoryKv::new()
    }
}

macro_rules! typed {
    ($self:ident, $sh:ident, $key:expr, $now:expr, $ttl:expr, $make:expr, $pat:pat => $body:expr) => {{
        let e = $self.entry_or_insert(&mut $sh, $key, $now, $ttl, $make)?;
        match &mut e.value {
            $pat => $body,
            _ => return Err(MemoryKv::wrong_type($key)),
        }
    }};
}

impl KvStore for MemoryKv {
    fn backend(&self) -> &'static str {
        "memory"
    }

    async fn get(&self, key: &str) -> KvResult<Option<Vec<u8>>> {
        check_key(key)?;
        let now = self.clock.now_us();
        let mut sh = lock(self.shard_of(key));
        self.expire_if_due(&mut sh, key, now);
        let out = match sh.map.get(key).map(|e| &e.value) {
            None => None,
            Some(Value::Str(v)) => Some(v.clone()),
            Some(Value::Int(i)) => Some(i.to_string().into_bytes()),
            Some(_) => return Err(MemoryKv::wrong_type(key)),
        };
        if out.is_some() {
            Self::touch(&mut sh, key);
        }
        Ok(out)
    }

    async fn set(&self, key: &str, value: &[u8], ttl: Option<Duration>) -> KvResult<()> {
        check_key(key)?;
        check_value(value)?;
        let now = self.clock.now_us();
        let mut sh = lock(self.shard_of(key));
        // `set` replaces whatever the key held, whatever its type; the old value stays if the new one is refused.
        let at = ttl_us(ttl).map(|t| now.saturating_add(t));
        self.replace_value(&mut sh, key, now, Value::Str(value.to_vec()), at)
    }

    async fn del(&self, key: &str) -> KvResult<bool> {
        check_key(key)?;
        let now = self.clock.now_us();
        let mut sh = lock(self.shard_of(key));
        self.expire_if_due(&mut sh, key, now);
        Ok(self.remove(&mut sh, key, false))
    }

    async fn exists(&self, key: &str) -> KvResult<bool> {
        check_key(key)?;
        let now = self.clock.now_us();
        let mut sh = lock(self.shard_of(key));
        self.expire_if_due(&mut sh, key, now);
        Ok(sh.map.contains_key(key))
    }

    async fn expire(&self, key: &str, ttl: Duration) -> KvResult<bool> {
        check_key(key)?;
        let now = self.clock.now_us();
        let mut sh = lock(self.shard_of(key));
        self.expire_if_due(&mut sh, key, now);
        if !sh.map.contains_key(key) {
            return Ok(false);
        }
        let at = now.saturating_add(ttl_us(Some(ttl)).unwrap_or(1));
        Self::set_ttl(&mut sh, key, Ttl::At(at));
        Ok(true)
    }

    async fn ttl(&self, key: &str) -> KvResult<Option<Duration>> {
        check_key(key)?;
        let now = self.clock.now_us();
        let mut sh = lock(self.shard_of(key));
        self.expire_if_due(&mut sh, key, now);
        Ok(sh
            .map
            .get(key)
            .and_then(|e| e.expires_us)
            .map(|at| remaining(at, now)))
    }

    async fn incr(&self, key: &str, by: i64, ttl: Option<Duration>) -> KvResult<i64> {
        check_key(key)?;
        let now = self.clock.now_us();
        let mut sh = lock(self.shard_of(key));
        let at = ttl_us(ttl);
        // Redis semantics: a string that holds a decimal integer can be incremented; anything else is a type error.
        let out = typed!(self, sh, key, now, at, || Value::Int(0), v @ (Value::Int(_) | Value::Str(_)) => {
            let current = match v {
                Value::Int(n) => Some(*n),
                Value::Str(s) => parse_redis_int(s),
                _ => None,
            };
            match current.map(|n| n.checked_add(by)) {
                None => return Err(MemoryKv::wrong_type(key)),
                Some(None) => return Err(KvError::InvalidArgument("integer overflow")),
                Some(Some(n)) => {
                    *v = Value::Int(n);
                    n
                }
            }
        });
        Ok(out)
    }

    async fn hset(
        &self,
        key: &str,
        field: &str,
        value: &[u8],
        ttl: Option<Duration>,
    ) -> KvResult<()> {
        check_key(key)?;
        check_value(value)?;
        check_key(field)?;
        let now = self.clock.now_us();
        let mut sh = lock(self.shard_of(key));
        let at = ttl_us(ttl);
        let old = typed!(self, sh, key, now, at, || Value::Hash(BTreeMap::new()), Value::Hash(h) => {
            if h.len() >= MAX_MEMBERS && !h.contains_key(field) {
                return Err(KvError::CollectionFull { cap: MAX_MEMBERS });
            }
            h.insert(field.to_owned(), value.to_vec()).map(|v| v.len())
        });
        let delta = match old {
            Some(o) => value.len() as isize - o as isize,
            None => (field.len() + value.len() + 48) as isize,
        };
        Self::resize(&mut sh, key, delta);
        Ok(())
    }

    async fn hget(&self, key: &str, field: &str) -> KvResult<Option<Vec<u8>>> {
        check_key(key)?;
        let now = self.clock.now_us();
        let mut sh = lock(self.shard_of(key));
        self.expire_if_due(&mut sh, key, now);
        let out = match sh.map.get(key).map(|e| &e.value) {
            None => None,
            Some(Value::Hash(h)) => h.get(field).cloned(),
            Some(_) => return Err(MemoryKv::wrong_type(key)),
        };
        if sh.map.contains_key(key) {
            Self::touch(&mut sh, key);
        }
        Ok(out)
    }

    async fn hgetall(&self, key: &str) -> KvResult<BTreeMap<String, Vec<u8>>> {
        check_key(key)?;
        let now = self.clock.now_us();
        let mut sh = lock(self.shard_of(key));
        self.expire_if_due(&mut sh, key, now);
        let out = match sh.map.get(key).map(|e| &e.value) {
            None => BTreeMap::new(),
            Some(Value::Hash(h)) => h.clone(),
            Some(_) => return Err(MemoryKv::wrong_type(key)),
        };
        if sh.map.contains_key(key) {
            Self::touch(&mut sh, key);
        }
        Ok(out)
    }

    async fn zadd(
        &self,
        key: &str,
        score: f64,
        member: &str,
        ttl: Option<Duration>,
    ) -> KvResult<bool> {
        check_key(key)?;
        check_key(member)?;
        if score.is_nan() {
            return Err(KvError::InvalidArgument("score is not a number"));
        }
        let now = self.clock.now_us();
        let mut sh = lock(self.shard_of(key));
        let at = ttl_us(ttl);
        let new = typed!(self, sh, key, now, at, || Value::ZSet(BTreeMap::new()), Value::ZSet(z) => {
            if z.len() >= MAX_MEMBERS && !z.contains_key(member) {
                return Err(KvError::CollectionFull { cap: MAX_MEMBERS });
            }
            z.insert(member.to_owned(), score).is_none()
        });
        if new {
            Self::resize(&mut sh, key, (member.len() + 40) as isize);
        }
        Ok(new)
    }

    async fn zrange_by_score(
        &self,
        key: &str,
        min: f64,
        max: f64,
        limit: usize,
    ) -> KvResult<Vec<(String, f64)>> {
        check_key(key)?;
        if min.is_nan() || max.is_nan() {
            return Err(KvError::InvalidArgument("a score bound is not a number"));
        }
        let now = self.clock.now_us();
        let mut sh = lock(self.shard_of(key));
        self.expire_if_due(&mut sh, key, now);
        let mut out: Vec<(String, f64)> = match sh.map.get(key).map(|e| &e.value) {
            None => Vec::new(),
            Some(Value::ZSet(z)) => z
                .iter()
                .filter(|(_, s)| **s >= min && **s <= max)
                .map(|(m, s)| (m.clone(), *s))
                .collect(),
            Some(_) => return Err(MemoryKv::wrong_type(key)),
        };
        out.sort_by(|a, b| a.1.total_cmp(&b.1).then_with(|| a.0.cmp(&b.0)));
        out.truncate(limit);
        if sh.map.contains_key(key) {
            Self::touch(&mut sh, key);
        }
        Ok(out)
    }

    async fn zrem(&self, key: &str, member: &str) -> KvResult<bool> {
        check_key(key)?;
        let now = self.clock.now_us();
        let mut sh = lock(self.shard_of(key));
        self.expire_if_due(&mut sh, key, now);
        let (removed, empty) = match sh.map.get_mut(key).map(|e| &mut e.value) {
            None => return Ok(false),
            Some(Value::ZSet(z)) => (z.remove(member).is_some(), z.is_empty()),
            Some(_) => return Err(MemoryKv::wrong_type(key)),
        };
        if removed {
            Self::resize(&mut sh, key, -((member.len() + 40) as isize));
        }
        if empty {
            self.remove(&mut sh, key, false);
        }
        Ok(removed)
    }

    async fn zcard(&self, key: &str) -> KvResult<usize> {
        check_key(key)?;
        let now = self.clock.now_us();
        let mut sh = lock(self.shard_of(key));
        self.expire_if_due(&mut sh, key, now);
        match sh.map.get(key).map(|e| &e.value) {
            None => Ok(0),
            Some(Value::ZSet(z)) => Ok(z.len()),
            Some(_) => Err(MemoryKv::wrong_type(key)),
        }
    }

    async fn sadd(&self, key: &str, member: &str, ttl: Option<Duration>) -> KvResult<bool> {
        check_key(key)?;
        check_key(member)?;
        let now = self.clock.now_us();
        let mut sh = lock(self.shard_of(key));
        let at = ttl_us(ttl);
        let new = typed!(self, sh, key, now, at, || Value::Set(BTreeSet::new()), Value::Set(s) => {
            if s.len() >= MAX_MEMBERS && !s.contains(member) {
                return Err(KvError::CollectionFull { cap: MAX_MEMBERS });
            }
            s.insert(member.to_owned())
        });
        if new {
            Self::resize(&mut sh, key, (member.len() + 32) as isize);
        }
        Ok(new)
    }

    async fn smembers(&self, key: &str) -> KvResult<BTreeSet<String>> {
        check_key(key)?;
        let now = self.clock.now_us();
        let mut sh = lock(self.shard_of(key));
        self.expire_if_due(&mut sh, key, now);
        match sh.map.get(key).map(|e| &e.value) {
            None => Ok(BTreeSet::new()),
            Some(Value::Set(s)) => Ok(s.clone()),
            Some(_) => Err(MemoryKv::wrong_type(key)),
        }
    }

    async fn compare_and_set(
        &self,
        key: &str,
        expected: Option<&[u8]>,
        new: &[u8],
        ttl: Option<Duration>,
    ) -> KvResult<bool> {
        check_key(key)?;
        check_value(new)?;
        let now = self.clock.now_us();
        let mut sh = lock(self.shard_of(key));
        self.expire_if_due(&mut sh, key, now);
        let current: Option<Vec<u8>> = match sh.map.get(key).map(|e| &e.value) {
            None => None,
            Some(Value::Str(v)) => Some(v.clone()),
            Some(Value::Int(i)) => Some(i.to_string().into_bytes()),
            Some(_) => return Err(MemoryKv::wrong_type(key)),
        };
        if current.as_deref() != expected {
            return Ok(false);
        }
        let at = ttl_us(ttl).map(|t| now.saturating_add(t));
        self.replace_value(&mut sh, key, now, Value::Str(new.to_vec()), at)?;
        Ok(true)
    }

    async fn rate_window_check(&self, key: &str, req: &RateRequest) -> KvResult<RateDecision> {
        check_key(key)?;
        req.validate()?;
        let now = self.clock.now_us();
        let mut sh = lock(self.shard_of(key));
        let algo = req.algorithm;
        let (decision, keep, before, after) = {
            let e = self.entry_or_insert(&mut sh, key, now, None, || {
                Value::Rate(RateEntry::new(algo))
            })?;
            let Value::Rate(r) = &mut e.value else {
                return Err(MemoryKv::wrong_type(key));
            };
            let before = r.approx_bytes();
            let d = r.check(now, req);
            (
                d,
                r.keep_for_us(now, req.window_us()),
                before,
                r.approx_bytes(),
            )
        };
        Self::resize(&mut sh, key, after as isize - before as isize);
        Self::set_ttl(&mut sh, key, Ttl::At(now.saturating_add(keep)));
        Ok(decision)
    }

    async fn challenge_nonce_consume(&self, key: &str) -> KvResult<Option<Vec<u8>>> {
        check_key(key)?;
        let now = self.clock.now_us();
        let mut sh = lock(self.shard_of(key));
        self.expire_if_due(&mut sh, key, now);
        let out = match sh.map.get(key).map(|e| &e.value) {
            None => return Ok(None),
            Some(Value::Str(v)) => v.clone(),
            Some(Value::Int(i)) => i.to_string().into_bytes(),
            Some(_) => return Err(MemoryKv::wrong_type(key)),
        };
        self.remove(&mut sh, key, false);
        Ok(Some(out))
    }

    async fn offence_incr_with_decay(
        &self,
        key: &str,
        decay: Duration,
        ttl: Duration,
    ) -> KvResult<u32> {
        check_key(key)?;
        let decay_us = ttl_us(Some(decay)).unwrap_or(1);
        let ttl_us_v = ttl_us(Some(ttl)).unwrap_or(1);
        let now = self.clock.now_us();
        let mut sh = lock(self.shard_of(key));
        let count = typed!(self, sh, key, now, Some(ttl_us_v), || Value::Offence { count: 0, last_us: now }, Value::Offence { count, last_us } => {
            let steps = now.saturating_sub(*last_us) / decay_us;
            let decayed = u64::from(*count).saturating_sub(steps);
            *count = u32::try_from(decayed).unwrap_or(u32::MAX).saturating_add(1);
            *last_us = now;
            *count
        });
        Self::set_ttl(&mut sh, key, Ttl::At(now.saturating_add(ttl_us_v)));
        Ok(count)
    }

    async fn flow_signal_update(
        &self,
        key: &str,
        signal: &str,
        ttl: Duration,
    ) -> KvResult<BTreeMap<String, u64>> {
        check_key(key)?;
        check_key(signal)?;
        let ttl_us_v = ttl_us(Some(ttl)).unwrap_or(1);
        let now = self.clock.now_us();
        let mut sh = lock(self.shard_of(key));
        let (out, new_signal) = typed!(self, sh, key, now, Some(ttl_us_v), || Value::Flow(BTreeMap::new()), Value::Flow(f) => {
            let new = !f.contains_key(signal);
            if new && f.len() >= MAX_FLOW_SIGNALS {
                return Err(KvError::CollectionFull {
                    cap: MAX_FLOW_SIGNALS,
                });
            }
            let c = f.entry(signal.to_owned()).or_insert(0);
            *c += 1;
            (f.clone(), new)
        });
        if new_signal {
            Self::resize(&mut sh, key, (signal.len() + 40) as isize);
        }
        Ok(out)
    }
}

impl std::fmt::Debug for MemoryKv {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MemoryKv")
            .field("shards", &self.shards.len())
            .field("pinned", &self.pinned_len())
            .finish_non_exhaustive()
    }
}
