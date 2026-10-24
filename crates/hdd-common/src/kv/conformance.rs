//! The conformance suite `kv_conformance` (T-0562 step 5): the same checks run against every backend.
//!
//! A backend is plugged in through [`Factory`]. The checks cover TTL accuracy (within 50 ms), atomicity under 64 concurrent
//! tasks, the semantics of the named atomic operations, key and value limits, wrong-type errors, bus ordering with gap and lag
//! detection, and the three rate-limit algorithms against independent reference models over random request sequences (exact
//! agreement for the exact and gcra algorithms and for the counter formula, plus the documented error bound of the counter
//! against the true sliding count).
//!
//! This is test-support code compiled for unit tests and under the `conformance` feature (the Redis run in `tests/`), so it
//! may assert and unwrap.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    reason = "test-support code: a failed check must stop the run with a message"
)]

use std::collections::BTreeSet;
use std::sync::Arc;
use std::time::Duration;

use super::bus::{Bus, BusEvent, ResyncReason};
use super::clock::ManualClock;
use super::rate::{Algorithm, RateRequest};
use super::{KvError, KvStore, MAX_KEY_BYTES, MAX_VALUE_BYTES};

/// A backend under test.
pub trait Factory: Send + Sync {
    /// The store type.
    type Kv: KvStore + 'static;
    /// A store on the real clock (TTL checks).
    fn real(&self) -> impl std::future::Future<Output = Self::Kv> + Send;
    /// A fresh store whose rate-limit time is driven by the returned clock (model checks). Keys of different calls must not
    /// collide when the backend is shared.
    fn manual(&self) -> impl std::future::Future<Output = (Self::Kv, Arc<ManualClock>)> + Send;
}

/// Small deterministic generator (the suite must not depend on a `rand` crate).
pub struct Rng(u64);

impl Rng {
    /// Seeded generator.
    pub fn new(seed: u64) -> Rng {
        Rng(seed.max(1))
    }

    /// Next 64 random bits (xorshift64*).
    pub fn next_u64(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        self.0 = x;
        x.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }

    /// Uniform in `lo..=hi`.
    pub fn range(&mut self, lo: u64, hi: u64) -> u64 {
        lo + self.next_u64() % (hi - lo + 1)
    }
}

/// Run every check on a backend. `sequences` is the number of random rate-limit sequences (10,000 for the acceptance run).
pub async fn run_all<F: Factory>(f: &F, sequences: usize) {
    basic_operations(&f.real().await).await;
    limits_and_wrong_types(&f.real().await).await;
    ttl_accuracy(&f.real().await).await;
    named_operations(f).await;
    atomicity_under_64_tasks(f).await;
    rate_models(f, sequences, 0xC0FF_EE00).await;
    rate_retry_after(f, sequences.min(2000), 0xBADD_CAFE).await;
    counter_error_bound(f, sequences.min(2000), 0x5EED_0001).await;
}

/// Plain operations: strings, integers, hashes, sorted sets, sets, compare-and-set.
pub async fn basic_operations<K: KvStore>(kv: &K) {
    let k = unique("basic");
    assert_eq!(kv.get(&k).await.unwrap(), None);
    kv.set(&k, b"v1", None).await.unwrap();
    assert_eq!(kv.get(&k).await.unwrap().as_deref(), Some(&b"v1"[..]));
    assert!(kv.exists(&k).await.unwrap());
    assert!(kv.del(&k).await.unwrap());
    assert!(!kv.del(&k).await.unwrap());
    assert!(!kv.exists(&k).await.unwrap());

    let n = unique("incr");
    assert_eq!(kv.incr(&n, 5, None).await.unwrap(), 5);
    assert_eq!(kv.incr(&n, -2, None).await.unwrap(), 3);
    assert_eq!(kv.get(&n).await.unwrap().as_deref(), Some(&b"3"[..]));

    // a string that holds an integer can be incremented (Redis semantics); other strings and overflow are errors
    let s = unique("incr-string");
    kv.set(&s, b"41", None).await.unwrap();
    assert_eq!(kv.incr(&s, 1, None).await.unwrap(), 42);
    kv.set(&s, b"forty-two", None).await.unwrap();
    assert!(matches!(
        kv.incr(&s, 1, None).await,
        Err(KvError::WrongType { .. })
    ));
    kv.set(&s, i64::MAX.to_string().as_bytes(), None)
        .await
        .unwrap();
    assert!(matches!(
        kv.incr(&s, 1, None).await,
        Err(KvError::InvalidArgument(_))
    ));

    let h = unique("hash");
    kv.hset(&h, "a", b"1", None).await.unwrap();
    kv.hset(&h, "b", b"2", None).await.unwrap();
    kv.hset(&h, "a", b"3", None).await.unwrap();
    assert_eq!(kv.hget(&h, "a").await.unwrap().as_deref(), Some(&b"3"[..]));
    assert_eq!(kv.hget(&h, "zz").await.unwrap(), None);
    let all = kv.hgetall(&h).await.unwrap();
    assert_eq!(all.len(), 2);
    assert_eq!(all.get("b").map(Vec::as_slice), Some(&b"2"[..]));
    assert!(kv.hgetall(&unique("nohash")).await.unwrap().is_empty());

    let z = unique("zset");
    assert!(kv.zadd(&z, 10.0, "c", None).await.unwrap());
    assert!(kv.zadd(&z, 5.0, "a", None).await.unwrap());
    assert!(kv.zadd(&z, 7.5, "b", None).await.unwrap());
    assert!(
        !kv.zadd(&z, 1.0, "c", None).await.unwrap(),
        "re-adding updates the score"
    );
    let r = kv.zrange_by_score(&z, 0.0, 8.0, 10).await.unwrap();
    assert_eq!(
        r,
        vec![
            ("c".to_owned(), 1.0),
            ("a".to_owned(), 5.0),
            ("b".to_owned(), 7.5)
        ]
    );
    assert_eq!(
        kv.zrange_by_score(&z, 6.0, f64::MAX, 1)
            .await
            .unwrap()
            .len(),
        1
    );
    assert_eq!(kv.zcard(&z).await.unwrap(), 3);
    assert!(kv.zrem(&z, "a").await.unwrap());
    assert!(!kv.zrem(&z, "a").await.unwrap());
    assert_eq!(kv.zcard(&z).await.unwrap(), 2);

    let s = unique("set");
    assert!(kv.sadd(&s, "x", None).await.unwrap());
    assert!(!kv.sadd(&s, "x", None).await.unwrap());
    assert!(kv.sadd(&s, "a", None).await.unwrap());
    assert_eq!(
        kv.smembers(&s).await.unwrap(),
        ["a", "x"]
            .iter()
            .map(|m| (*m).to_owned())
            .collect::<BTreeSet<_>>()
    );

    let c = unique("cas");
    assert!(kv.compare_and_set(&c, None, b"one", None).await.unwrap());
    assert!(!kv.compare_and_set(&c, None, b"two", None).await.unwrap());
    assert!(
        !kv.compare_and_set(&c, Some(b"zzz"), b"two", None)
            .await
            .unwrap()
    );
    assert!(
        kv.compare_and_set(&c, Some(b"one"), b"two", None)
            .await
            .unwrap()
    );
    assert_eq!(kv.get(&c).await.unwrap().as_deref(), Some(&b"two"[..]));
}

/// Key length, value size and wrong-type behavior.
pub async fn limits_and_wrong_types<K: KvStore>(kv: &K) {
    let long = format!("hdd:t:{}", "k".repeat(MAX_KEY_BYTES));
    assert!(matches!(kv.get(&long).await, Err(KvError::BadKey(_))));
    assert!(matches!(kv.get("").await, Err(KvError::BadKey(_))));
    assert!(matches!(kv.get("bad\nkey").await, Err(KvError::BadKey(_))));
    let at_limit = format!("hdd:t:{}", "k".repeat(MAX_KEY_BYTES - 6));
    assert_eq!(at_limit.len(), MAX_KEY_BYTES);
    kv.set(&at_limit, b"x", Some(Duration::from_secs(5)))
        .await
        .unwrap();
    assert!(kv.del(&at_limit).await.unwrap());

    let big = vec![7u8; MAX_VALUE_BYTES + 1];
    assert!(matches!(
        kv.set(&unique("big"), &big, None).await,
        Err(KvError::ValueTooLarge { .. })
    ));
    let max = vec![7u8; MAX_VALUE_BYTES];
    let k = unique("max");
    kv.set(&k, &max, Some(Duration::from_secs(5)))
        .await
        .unwrap();
    assert_eq!(
        kv.get(&k).await.unwrap().map(|v| v.len()),
        Some(MAX_VALUE_BYTES)
    );
    kv.del(&k).await.unwrap();

    let h = unique("wrong");
    kv.hset(&h, "f", b"v", Some(Duration::from_secs(5)))
        .await
        .unwrap();
    assert!(matches!(kv.get(&h).await, Err(KvError::WrongType { .. })));
    assert!(matches!(
        kv.incr(&h, 1, None).await,
        Err(KvError::WrongType { .. })
    ));
    assert!(matches!(
        kv.sadd(&h, "m", None).await,
        Err(KvError::WrongType { .. })
    ));
    kv.del(&h).await.unwrap();
}

/// TTL accuracy: a key set for 300 ms is visible before and gone after, and `ttl` is within 50 ms of the truth.
pub async fn ttl_accuracy<K: KvStore>(kv: &K) {
    let k = unique("ttl");
    kv.set(&k, b"v", Some(Duration::from_millis(400)))
        .await
        .unwrap();
    let left = kv.ttl(&k).await.unwrap().expect("ttl");
    assert!(
        left <= Duration::from_millis(400) && left >= Duration::from_millis(350),
        "ttl right after set: {left:?}"
    );
    tokio::time::sleep(Duration::from_millis(200)).await;
    let left = kv.ttl(&k).await.unwrap().expect("ttl");
    assert!(
        left >= Duration::from_millis(150) && left <= Duration::from_millis(250),
        "ttl after 200 ms: {left:?}"
    );
    assert!(kv.exists(&k).await.unwrap());
    tokio::time::sleep(Duration::from_millis(250)).await;
    assert!(
        !kv.exists(&k).await.unwrap(),
        "key must be gone 450 ms after a 400 ms ttl"
    );
    assert_eq!(kv.get(&k).await.unwrap(), None);

    // creation-only TTL for incr, hset, sadd, zadd
    let n = unique("ttl-incr");
    kv.incr(&n, 1, Some(Duration::from_millis(300)))
        .await
        .unwrap();
    tokio::time::sleep(Duration::from_millis(150)).await;
    kv.incr(&n, 1, Some(Duration::from_secs(60))).await.unwrap();
    let left = kv.ttl(&n).await.unwrap().expect("ttl");
    assert!(
        left <= Duration::from_millis(200),
        "second incr must not extend: {left:?}"
    );
    tokio::time::sleep(Duration::from_millis(200)).await;
    assert!(!kv.exists(&n).await.unwrap());

    // expire and persist
    let e = unique("ttl-expire");
    kv.set(&e, b"v", None).await.unwrap();
    assert_eq!(kv.ttl(&e).await.unwrap(), None);
    assert!(kv.expire(&e, Duration::from_millis(200)).await.unwrap());
    assert!(
        !kv.expire(&unique("ttl-missing"), Duration::from_secs(1))
            .await
            .unwrap()
    );
    tokio::time::sleep(Duration::from_millis(280)).await;
    assert!(!kv.exists(&e).await.unwrap());
}

/// Semantics of challenge nonces, offence decay and flow signals.
pub async fn named_operations<F: Factory>(f: &F) {
    let kv = f.real().await;
    // nonce: once
    let n = unique("nonce");
    kv.set(&n, b"payload", Some(Duration::from_secs(5)))
        .await
        .unwrap();
    assert_eq!(
        kv.challenge_nonce_consume(&n).await.unwrap().as_deref(),
        Some(&b"payload"[..])
    );
    assert_eq!(kv.challenge_nonce_consume(&n).await.unwrap(), None);
    assert_eq!(
        kv.challenge_nonce_consume(&unique("never")).await.unwrap(),
        None
    );

    // flow signals
    let fl = unique("flow");
    let m = kv
        .flow_signal_update(&fl, "view", Duration::from_secs(5))
        .await
        .unwrap();
    assert_eq!(m.get("view"), Some(&1));
    kv.flow_signal_update(&fl, "view", Duration::from_secs(5))
        .await
        .unwrap();
    let m = kv
        .flow_signal_update(&fl, "submit", Duration::from_secs(5))
        .await
        .unwrap();
    assert_eq!((m.get("view"), m.get("submit")), (Some(&2), Some(&1)));

    // offence ladder with decay, on the manual clock (no sleeping)
    let (kv, clock) = f.manual().await;
    let o = unique("offence");
    let decay = Duration::from_secs(60);
    let ttl = Duration::from_secs(3600);
    assert_eq!(kv.offence_incr_with_decay(&o, decay, ttl).await.unwrap(), 1);
    assert_eq!(kv.offence_incr_with_decay(&o, decay, ttl).await.unwrap(), 2);
    assert_eq!(kv.offence_incr_with_decay(&o, decay, ttl).await.unwrap(), 3);
    // two whole decay steps forgive two offences before the new one is added: 3 - 2 + 1
    advance(&clock, Duration::from_secs(130)).await;
    assert_eq!(kv.offence_incr_with_decay(&o, decay, ttl).await.unwrap(), 2);
    // a long quiet time forgives everything, never below zero
    advance(&clock, Duration::from_secs(60 * 60)).await;
    assert_eq!(kv.offence_incr_with_decay(&o, decay, ttl).await.unwrap(), 1);
}

/// 64 concurrent tasks: counters add up, nonces and compare-and-set have one winner, the exact limiter admits exactly `limit`.
pub async fn atomicity_under_64_tasks<F: Factory>(f: &F) {
    let kv = Arc::new(f.real().await);

    let counter = unique("atomic-incr");
    let mut handles = Vec::new();
    for _ in 0..64 {
        let kv = Arc::clone(&kv);
        let key = counter.clone();
        handles.push(tokio::spawn(async move {
            for _ in 0..50 {
                kv.incr(&key, 1, Some(Duration::from_secs(30)))
                    .await
                    .unwrap();
            }
        }));
    }
    for h in handles {
        h.await.unwrap();
    }
    assert_eq!(
        kv.get(&counter).await.unwrap().as_deref(),
        Some(&b"3200"[..])
    );

    let nonce = unique("atomic-nonce");
    kv.set(&nonce, b"n", Some(Duration::from_secs(30)))
        .await
        .unwrap();
    let mut handles = Vec::new();
    for _ in 0..64 {
        let kv = Arc::clone(&kv);
        let key = nonce.clone();
        handles.push(tokio::spawn(async move {
            kv.challenge_nonce_consume(&key).await.unwrap()
        }));
    }
    let mut winners = 0;
    for h in handles {
        if h.await.unwrap().is_some() {
            winners += 1;
        }
    }
    assert_eq!(winners, 1, "exactly one task may redeem a nonce");

    let cas = unique("atomic-cas");
    let mut handles = Vec::new();
    for i in 0..64u8 {
        let kv = Arc::clone(&kv);
        let key = cas.clone();
        handles.push(tokio::spawn(async move {
            kv.compare_and_set(&key, None, &[i], Some(Duration::from_secs(30)))
                .await
                .unwrap()
        }));
    }
    let mut winners = 0;
    for h in handles {
        if h.await.unwrap() {
            winners += 1;
        }
    }
    assert_eq!(
        winners, 1,
        "exactly one compare-and-set on a missing key may win"
    );

    for algo in [Algorithm::Exact, Algorithm::Gcra] {
        let key = unique("atomic-rate");
        let mut handles = Vec::new();
        for _ in 0..64 {
            let kv = Arc::clone(&kv);
            let key = key.clone();
            handles.push(tokio::spawn(async move {
                let req = RateRequest::new(10, Duration::from_secs(30), algo);
                kv.rate_window_check(&key, &req).await.unwrap().allowed
            }));
        }
        let mut allowed = 0;
        for h in handles {
            if h.await.unwrap() {
                allowed += 1;
            }
        }
        // gcra refills one unit every 3 s; the burst of 64 tasks finishes far inside that
        assert_eq!(allowed, 10, "{algo:?}: limit 10 with 64 concurrent callers");
    }

    let off = unique("atomic-offence");
    let mut handles = Vec::new();
    for _ in 0..64 {
        let kv = Arc::clone(&kv);
        let key = off.clone();
        handles.push(tokio::spawn(async move {
            kv.offence_incr_with_decay(&key, Duration::from_secs(3600), Duration::from_secs(3600))
                .await
                .unwrap()
        }));
    }
    let mut seen = BTreeSet::new();
    for h in handles {
        seen.insert(h.await.unwrap());
    }
    assert_eq!(
        seen,
        (1..=64u32).collect::<BTreeSet<_>>(),
        "every increment must see a distinct count"
    );
}

async fn advance(clock: &ManualClock, by: Duration) {
    clock.advance_us(u64::try_from(by.as_micros()).unwrap());
}

/// Bus ordering, forced gap and lag detection. `force_gap` publishes a message with a skipped revision on the channel.
pub async fn bus_checks<B, G, Fut>(bus: &B, force_gap: G, lag_capacity: Option<usize>)
where
    B: Bus,
    G: Fn(String) -> Fut,
    Fut: std::future::Future<Output = ()>,
{
    let ch = unique("bus");
    let mut sub = bus.subscribe(&ch).await.unwrap();
    let mut revs: Vec<u64> = Vec::new();
    // stay below the buffer of a bounded in-process bus so that ordering is tested without a lag
    let count = lag_capacity.map_or(20, |c| c.saturating_sub(1).clamp(1, 20));
    for i in 0..count {
        revs.push(bus.publish(&ch, &[i as u8]).await.unwrap());
    }
    assert!(
        revs.windows(2).all(|w| w[1] == w[0] + 1),
        "revisions grow by one: {revs:?}"
    );
    for (i, rev) in revs.iter().enumerate() {
        match tokio::time::timeout(Duration::from_secs(5), sub.recv())
            .await
            .expect("message")
        {
            BusEvent::Message { revision, payload } => {
                assert_eq!(revision, *rev);
                assert_eq!(payload, vec![u8::try_from(i).unwrap()]);
            }
            other => panic!("expected message {i}, got {other:?}"),
        }
    }
    assert_eq!(sub.resyncs(), 0);

    // a skipped revision yields a resync, and the message is still delivered afterwards
    force_gap(ch.clone()).await;
    match tokio::time::timeout(Duration::from_secs(5), sub.recv())
        .await
        .expect("event")
    {
        BusEvent::Resync(ResyncReason::Gap { expected, got }) => assert!(got > expected),
        other => panic!("expected a gap resync, got {other:?}"),
    }
    match tokio::time::timeout(Duration::from_secs(5), sub.recv())
        .await
        .expect("event")
    {
        BusEvent::Message { .. } => {}
        other => panic!("expected the message after the resync, got {other:?}"),
    }
    assert_eq!(sub.resyncs(), 1);

    // a subscriber that falls behind its buffer is told to resync (backends with a bounded in-process buffer)
    if let Some(cap) = lag_capacity {
        let ch = unique("bus-lag");
        let mut slow = bus.subscribe(&ch).await.unwrap();
        for i in 0..(cap * 4) {
            bus.publish(&ch, &[u8::try_from(i % 250).unwrap()])
                .await
                .unwrap();
        }
        match slow.recv().await {
            BusEvent::Resync(ResyncReason::Lagged { missed }) => assert!(missed > 0),
            other => panic!("expected a lag resync, got {other:?}"),
        }
        // after the resync the subscriber continues without a false gap
        match slow.recv().await {
            BusEvent::Message { .. } => {}
            other => panic!("expected a message after the lag resync, got {other:?}"),
        }
    }

    // channels are independent
    let a = unique("bus-a");
    let b = unique("bus-b");
    bus.publish(&a, b"1").await.unwrap();
    assert_eq!(
        bus.publish(&b, b"1").await.unwrap(),
        1,
        "each channel counts its own revisions"
    );
}

// ---------------------------------------------------------------------------------------------------------------------
// Reference models. Written independently of `rate.rs`: they keep the full history of allowed requests and recompute from it.

#[derive(Default)]
struct RefModel {
    allowed: Vec<(u64, u64)>,
    tat: u64,
    viol: u32,
    viol_until: u64,
}

struct RefAnswer {
    allowed: bool,
    remaining: u64,
    violations: u32,
}

impl RefModel {
    fn decide(&mut self, now: u64, limit: u64, w: u64, cost: u64, algo: Algorithm) -> RefAnswer {
        let (allowed, remaining) = match algo {
            Algorithm::Exact => {
                let used: u64 = self
                    .allowed
                    .iter()
                    .filter(|(t, _)| t + w > now)
                    .map(|(_, c)| c)
                    .sum();
                if used + cost <= limit {
                    self.allowed.push((now, cost));
                    (true, limit - used - cost)
                } else {
                    (false, limit - used)
                }
            }
            Algorithm::Counter => {
                let idx = now / w;
                let cur: u64 = self
                    .allowed
                    .iter()
                    .filter(|(t, _)| t / w == idx)
                    .map(|(_, c)| c)
                    .sum();
                let prev: u64 = if idx == 0 {
                    0
                } else {
                    self.allowed
                        .iter()
                        .filter(|(t, _)| t / w == idx - 1)
                        .map(|(_, c)| c)
                        .sum()
                };
                let est =
                    u128::from(prev) * u128::from(w - now % w) + u128::from(cur) * u128::from(w);
                let cap = u128::from(limit) * u128::from(w);
                if est + u128::from(cost) * u128::from(w) <= cap {
                    self.allowed.push((now, cost));
                    (
                        true,
                        ((cap - est - u128::from(cost) * u128::from(w)) / u128::from(w)) as u64,
                    )
                } else {
                    (false, ((cap - est.min(cap)) / u128::from(w)) as u64)
                }
            }
            Algorithm::Gcra => {
                let t = (w / limit).max(1);
                let cap = limit * t;
                let backlog = self.tat.max(now) - now + cost * t;
                if backlog <= cap {
                    self.tat = now + backlog;
                    (true, (cap - backlog) / t)
                } else {
                    (false, (cap - (self.tat.max(now) - now).min(cap)) / t)
                }
            }
        };
        if !allowed {
            if now >= self.viol_until {
                self.viol = 0;
            }
            self.viol += 1;
            self.viol_until = now + w;
        }
        RefAnswer {
            allowed,
            remaining,
            violations: if now < self.viol_until { self.viol } else { 0 },
        }
    }
}

/// One random request sequence: `(delay before the request in µs, cost)`.
fn random_sequence(rng: &mut Rng, limit: u64, w: u64) -> Vec<(u64, u32)> {
    let len = rng.range(5, 60) as usize;
    let step_cap = (w / 2).max(2);
    (0..len)
        .map(|_| {
            let delay = match rng.range(0, 9) {
                0..=4 => rng.range(0, step_cap / 20 + 1),
                5..=7 => rng.range(0, step_cap),
                8 => rng.range(w / 2, w * 2),
                _ => 0,
            };
            let cost = if rng.range(0, 7) == 0 {
                rng.range(1, limit.min(3)) as u32
            } else {
                1
            };
            (delay, cost)
        })
        .collect()
}

fn random_params(rng: &mut Rng) -> (Algorithm, u32, u64) {
    let algo = match rng.range(0, 2) {
        0 => Algorithm::Counter,
        1 => Algorithm::Exact,
        _ => Algorithm::Gcra,
    };
    let limit = rng.range(1, 20) as u32;
    // the window in microseconds, at least one microsecond per unit (gcra), a whole number of milliseconds
    let w_ms = rng.range(1, 3000).max(1);
    (algo, limit, w_ms * 1000)
}

/// The decisions of `kv` equal the reference model on random sequences.
pub async fn rate_models<F: Factory>(f: &F, sequences: usize, seed: u64) {
    let mut rng = Rng::new(seed);
    for seq in 0..sequences {
        let (algo, limit, w) = random_params(&mut rng);
        let ops = random_sequence(&mut rng, u64::from(limit), w);
        let (kv, clock) = f.manual().await;
        advance(&clock, Duration::from_secs(100)).await;
        let key = unique("model");
        let mut model = RefModel::default();
        let mut now = 100_000_000u64;
        for (n, (delay, cost)) in ops.iter().enumerate() {
            clock.advance_us(*delay);
            now += delay;
            let req = RateRequest {
                limit,
                window: Duration::from_micros(w),
                algorithm: algo,
                cost: *cost,
            };
            let got = kv.rate_window_check(&key, &req).await.unwrap();
            let want = model.decide(now, u64::from(limit), w, u64::from(*cost), algo);
            assert_eq!(
                (got.allowed, u64::from(got.remaining), got.violations),
                (want.allowed, want.remaining, want.violations),
                "sequence {seq} step {n}: {algo:?} limit {limit} window {w}us cost {cost} delay {delay}us"
            );
        }
    }
}

/// A denied decision's `reset_ms` is a tight `Retry-After`: waiting that long succeeds, waiting a millisecond less fails.
pub async fn rate_retry_after<F: Factory>(f: &F, sequences: usize, seed: u64) {
    let mut rng = Rng::new(seed);
    let mut probed = 0;
    for seq in 0..sequences {
        let (algo, limit, w) = random_params(&mut rng);
        let ops = random_sequence(&mut rng, u64::from(limit), w);
        // find the first denial by replaying on a scratch store
        let (scratch, sclock) = f.manual().await;
        let skey = unique("retry-scan");
        let mut denied_at = None;
        for (n, (delay, cost)) in ops.iter().enumerate() {
            sclock.advance_us(*delay);
            let req = RateRequest {
                limit,
                window: Duration::from_micros(w),
                algorithm: algo,
                cost: *cost,
            };
            let d = scratch.rate_window_check(&skey, &req).await.unwrap();
            if !d.allowed {
                denied_at = Some((n, d.reset_ms));
                break;
            }
        }
        let Some((n, reset_ms)) = denied_at else {
            continue;
        };
        let denied_cost = ops[n].1;
        for (extra_ms, expect_allowed) in [(reset_ms, true), (reset_ms.saturating_sub(1), false)] {
            if reset_ms == 0 && !expect_allowed {
                continue;
            }
            let (kv, clock) = f.manual().await;
            let key = unique("retry");
            for (delay, cost) in &ops[..n] {
                clock.advance_us(*delay);
                let req = RateRequest {
                    limit,
                    window: Duration::from_micros(w),
                    algorithm: algo,
                    cost: *cost,
                };
                assert!(kv.rate_window_check(&key, &req).await.unwrap().allowed);
            }
            clock.advance_us(ops[n].0);
            let req = RateRequest {
                limit,
                window: Duration::from_micros(w),
                algorithm: algo,
                cost: denied_cost,
            };
            let first = kv.rate_window_check(&key, &req).await.unwrap();
            assert!(!first.allowed);
            assert_eq!(first.reset_ms, reset_ms, "replay must be deterministic");
            clock.advance_ms(extra_ms);
            let later = kv.rate_window_check(&key, &req).await.unwrap();
            assert_eq!(
                later.allowed, expect_allowed,
                "sequence {seq}: {algo:?} limit {limit} window {w}us, retry-after {reset_ms} ms, waited {extra_ms} ms"
            );
        }
        probed += 1;
    }
    assert!(
        probed > 0,
        "no sequence produced a denial: the generator is broken"
    );
}

/// The counter's estimate differs from the true sliding count by at most the previous window's count.
pub async fn counter_error_bound<F: Factory>(f: &F, sequences: usize, seed: u64) {
    let mut rng = Rng::new(seed);
    let mut worst = 0u128;
    for seq in 0..sequences {
        let (_, limit, w) = random_params(&mut rng);
        let ops = random_sequence(&mut rng, u64::from(limit), w);
        let (kv, clock) = f.manual().await;
        advance(&clock, Duration::from_secs(100)).await;
        let key = unique("bound");
        let mut allowed_log: Vec<(u64, u64)> = Vec::new();
        let mut now = 100_000_000u64;
        for (delay, cost) in &ops {
            clock.advance_us(*delay);
            now += delay;
            // the true sliding count and the estimate just before the decision
            let truth: u64 = allowed_log
                .iter()
                .filter(|(t, _)| t + w > now)
                .map(|(_, c)| c)
                .sum();
            let idx = now / w;
            let cur: u64 = allowed_log
                .iter()
                .filter(|(t, _)| t / w == idx)
                .map(|(_, c)| c)
                .sum();
            let prev: u64 = allowed_log
                .iter()
                .filter(|(t, _)| t / w + 1 == idx)
                .map(|(_, c)| c)
                .sum();
            let est = u128::from(prev) * u128::from(w - now % w) + u128::from(cur) * u128::from(w);
            let diff = est.abs_diff(u128::from(truth) * u128::from(w));
            assert!(
                diff <= u128::from(prev) * u128::from(w),
                "sequence {seq}: estimate off by {diff} (> prev {prev} * window {w})"
            );
            worst = worst.max(diff / u128::from(w));
            let req = RateRequest {
                limit,
                window: Duration::from_micros(w),
                algorithm: Algorithm::Counter,
                cost: *cost,
            };
            if kv.rate_window_check(&key, &req).await.unwrap().allowed {
                allowed_log.push((now, u64::from(*cost)));
            }
        }
    }
    let _ = worst;
}

/// A key that cannot collide with another run on a shared backend.
pub fn unique(label: &str) -> String {
    use std::sync::atomic::{AtomicU64, Ordering};
    static N: AtomicU64 = AtomicU64::new(0);
    let n = N.fetch_add(1, Ordering::Relaxed);
    let mut salt = [0u8; 6];
    let _ = getrandom::fill(&mut salt);
    let hex: String = salt.iter().map(|b| format!("{b:02x}")).collect();
    format!("hdd:conf:{label}:{hex}:{n}")
}
