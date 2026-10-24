//! `MET-hdd_kv_ops_total` and `MET-hdd_kv_latency_seconds` (T-0562 step 7): operation counters by backend, operation and result,
//! and a latency histogram by backend and operation. [`Instrumented`] wraps any [`KvStore`]; the central metrics registry (a later
//! task) renders [`KvMetrics::render_prometheus`] into `/metrics`.

use std::collections::BTreeMap;
use std::collections::BTreeSet;
use std::future::Future;
use std::sync::{Arc, Mutex, PoisonError};
use std::time::{Duration, Instant};

use super::rate::{RateDecision, RateRequest};
use super::{KvResult, KvStore};

/// Upper bounds of the latency buckets, in seconds.
pub const BUCKETS: [f64; 12] = [
    0.000_005, 0.000_01, 0.000_05, 0.000_1, 0.000_25, 0.000_5, 0.001, 0.0025, 0.005, 0.01, 0.05,
    0.25,
];

#[derive(Default, Clone)]
struct Histogram {
    counts: [u64; BUCKETS.len()],
    total: u64,
    sum: f64,
}

#[derive(Default)]
struct Inner {
    ops: BTreeMap<(&'static str, &'static str, &'static str), u64>,
    latency: BTreeMap<(&'static str, &'static str), Histogram>,
}

/// Counters and histograms of store operations.
#[derive(Default)]
pub struct KvMetrics {
    inner: Mutex<Inner>,
}

impl KvMetrics {
    /// An empty set.
    pub fn new() -> KvMetrics {
        KvMetrics::default()
    }

    /// Record one operation.
    pub fn record(&self, backend: &'static str, op: &'static str, ok: bool, elapsed: Duration) {
        let mut g = self.inner.lock().unwrap_or_else(PoisonError::into_inner);
        *g.ops
            .entry((backend, op, if ok { "ok" } else { "error" }))
            .or_insert(0) += 1;
        let h = g.latency.entry((backend, op)).or_default();
        let secs = elapsed.as_secs_f64();
        h.total += 1;
        h.sum += secs;
        for (i, upper) in BUCKETS.iter().enumerate() {
            if secs <= *upper
                && let Some(c) = h.counts.get_mut(i)
            {
                *c += 1;
            }
        }
    }

    /// Count of an `(backend, op, result)` triple.
    pub fn ops(&self, backend: &str, op: &str, result: &str) -> u64 {
        let g = self.inner.lock().unwrap_or_else(PoisonError::into_inner);
        g.ops
            .iter()
            .filter(|((b, o, r), _)| *b == backend && *o == op && *r == result)
            .map(|(_, n)| *n)
            .sum()
    }

    /// Prometheus text exposition of both metrics.
    pub fn render_prometheus(&self) -> String {
        let g = self.inner.lock().unwrap_or_else(PoisonError::into_inner);
        let mut s = String::from(
            "# HELP hdd_kv_ops_total KvStore, Bus and Limiter operations\n# TYPE hdd_kv_ops_total counter\n",
        );
        for ((b, o, r), n) in &g.ops {
            s.push_str(&format!(
                "hdd_kv_ops_total{{backend=\"{b}\",op=\"{o}\",result=\"{r}\"}} {n}\n"
            ));
        }
        s.push_str("# HELP hdd_kv_latency_seconds Backend latency\n# TYPE hdd_kv_latency_seconds histogram\n");
        for ((b, o), h) in &g.latency {
            for (upper, c) in BUCKETS.iter().zip(h.counts.iter()) {
                s.push_str(&format!(
                    "hdd_kv_latency_seconds_bucket{{backend=\"{b}\",op=\"{o}\",le=\"{upper}\"}} {c}\n"
                ));
            }
            s.push_str(&format!(
                "hdd_kv_latency_seconds_bucket{{backend=\"{b}\",op=\"{o}\",le=\"+Inf\"}} {}\n",
                h.total
            ));
            s.push_str(&format!(
                "hdd_kv_latency_seconds_sum{{backend=\"{b}\",op=\"{o}\"}} {}\n",
                h.sum
            ));
            s.push_str(&format!(
                "hdd_kv_latency_seconds_count{{backend=\"{b}\",op=\"{o}\"}} {}\n",
                h.total
            ));
        }
        s
    }
}

/// A store that records every operation in a [`KvMetrics`].
pub struct Instrumented<K: KvStore> {
    inner: K,
    metrics: Arc<KvMetrics>,
}

impl<K: KvStore> Instrumented<K> {
    /// Wrap `inner`.
    pub fn new(inner: K, metrics: Arc<KvMetrics>) -> Instrumented<K> {
        Instrumented { inner, metrics }
    }

    /// The wrapped store.
    pub fn inner(&self) -> &K {
        &self.inner
    }

    async fn timed<T>(
        &self,
        op: &'static str,
        f: impl Future<Output = KvResult<T>>,
    ) -> KvResult<T> {
        let start = Instant::now();
        let r = f.await;
        self.metrics
            .record(self.inner.backend(), op, r.is_ok(), start.elapsed());
        r
    }
}

impl<K: KvStore> KvStore for Instrumented<K> {
    fn backend(&self) -> &'static str {
        self.inner.backend()
    }

    async fn get(&self, key: &str) -> KvResult<Option<Vec<u8>>> {
        self.timed("get", self.inner.get(key)).await
    }

    async fn set(&self, key: &str, value: &[u8], ttl: Option<Duration>) -> KvResult<()> {
        self.timed("set", self.inner.set(key, value, ttl)).await
    }

    async fn del(&self, key: &str) -> KvResult<bool> {
        self.timed("del", self.inner.del(key)).await
    }

    async fn exists(&self, key: &str) -> KvResult<bool> {
        self.timed("exists", self.inner.exists(key)).await
    }

    async fn expire(&self, key: &str, ttl: Duration) -> KvResult<bool> {
        self.timed("expire", self.inner.expire(key, ttl)).await
    }

    async fn ttl(&self, key: &str) -> KvResult<Option<Duration>> {
        self.timed("ttl", self.inner.ttl(key)).await
    }

    async fn incr(&self, key: &str, by: i64, ttl: Option<Duration>) -> KvResult<i64> {
        self.timed("incr", self.inner.incr(key, by, ttl)).await
    }

    async fn hset(
        &self,
        key: &str,
        field: &str,
        value: &[u8],
        ttl: Option<Duration>,
    ) -> KvResult<()> {
        self.timed("hset", self.inner.hset(key, field, value, ttl))
            .await
    }

    async fn hget(&self, key: &str, field: &str) -> KvResult<Option<Vec<u8>>> {
        self.timed("hget", self.inner.hget(key, field)).await
    }

    async fn hgetall(&self, key: &str) -> KvResult<BTreeMap<String, Vec<u8>>> {
        self.timed("hgetall", self.inner.hgetall(key)).await
    }

    async fn zadd(
        &self,
        key: &str,
        score: f64,
        member: &str,
        ttl: Option<Duration>,
    ) -> KvResult<bool> {
        self.timed("zadd", self.inner.zadd(key, score, member, ttl))
            .await
    }

    async fn zrange_by_score(
        &self,
        key: &str,
        min: f64,
        max: f64,
        limit: usize,
    ) -> KvResult<Vec<(String, f64)>> {
        self.timed(
            "zrange_by_score",
            self.inner.zrange_by_score(key, min, max, limit),
        )
        .await
    }

    async fn zrem(&self, key: &str, member: &str) -> KvResult<bool> {
        self.timed("zrem", self.inner.zrem(key, member)).await
    }

    async fn zcard(&self, key: &str) -> KvResult<usize> {
        self.timed("zcard", self.inner.zcard(key)).await
    }

    async fn sadd(&self, key: &str, member: &str, ttl: Option<Duration>) -> KvResult<bool> {
        self.timed("sadd", self.inner.sadd(key, member, ttl)).await
    }

    async fn smembers(&self, key: &str) -> KvResult<BTreeSet<String>> {
        self.timed("smembers", self.inner.smembers(key)).await
    }

    async fn compare_and_set(
        &self,
        key: &str,
        expected: Option<&[u8]>,
        new: &[u8],
        ttl: Option<Duration>,
    ) -> KvResult<bool> {
        self.timed(
            "compare_and_set",
            self.inner.compare_and_set(key, expected, new, ttl),
        )
        .await
    }

    async fn rate_window_check(&self, key: &str, req: &RateRequest) -> KvResult<RateDecision> {
        self.timed("rate_window_check", self.inner.rate_window_check(key, req))
            .await
    }

    async fn challenge_nonce_consume(&self, key: &str) -> KvResult<Option<Vec<u8>>> {
        self.timed(
            "challenge_nonce_consume",
            self.inner.challenge_nonce_consume(key),
        )
        .await
    }

    async fn offence_incr_with_decay(
        &self,
        key: &str,
        decay: Duration,
        ttl: Duration,
    ) -> KvResult<u32> {
        self.timed(
            "offence_incr_with_decay",
            self.inner.offence_incr_with_decay(key, decay, ttl),
        )
        .await
    }

    async fn flow_signal_update(
        &self,
        key: &str,
        signal: &str,
        ttl: Duration,
    ) -> KvResult<BTreeMap<String, u64>> {
        self.timed(
            "flow_signal_update",
            self.inner.flow_signal_update(key, signal, ttl),
        )
        .await
    }
}
