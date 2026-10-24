//! Limiter overhead budgets (T-0562 step 8, R-29: a budget is a test): `MemoryKv` check at most 5 microseconds at p99 and
//! `RedisKv` at most 1 millisecond at p99 in the same data center.
//!
//! Run with `cargo bench -p hdd-common --bench kv_limiter`. The program exits non-zero when a budget is exceeded. The Redis
//! half needs `HDD_TEST_REDIS_URL` (a Redis 7 or newer server close to the machine) and is otherwise reported as
//! `UNVERIFIED(environment_unsupported)`. The harness is plain `std::time::Instant` on purpose: criterion's dependency tree is
//! not justified for two budgets (recorded in docs/DEVIATIONS.md).
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::print_stdout,
    clippy::indexing_slicing,
    reason = "benchmark"
)]

use std::process::ExitCode;
use std::time::{Duration, Instant};

use hdd_common::kv::rate::{Algorithm, RateRequest};
use hdd_common::kv::redis::{RedisConfig, RedisKv};
use hdd_common::kv::{KvStore, MemoryKv};

const MEMORY_BUDGET: Duration = Duration::from_micros(5);
const REDIS_BUDGET: Duration = Duration::from_millis(1);

async fn measure<K: KvStore>(kv: &K, algo: Algorithm, n: usize) -> Vec<Duration> {
    let req = RateRequest::new(1_000_000, Duration::from_secs(60), algo);
    // warm up (script load, allocation)
    for i in 0..1000 {
        kv.rate_window_check(&format!("hdd:rl:bench:warm:{}", i % 64), &req)
            .await
            .unwrap();
    }
    let keys: Vec<String> = (0..1024)
        .map(|i| format!("hdd:rl:bench:{}:{i}", algo.name()))
        .collect();
    let mut samples = Vec::with_capacity(n);
    for i in 0..n {
        let key = &keys[i % keys.len()];
        let t = Instant::now();
        kv.rate_window_check(key, &req).await.unwrap();
        samples.push(t.elapsed());
    }
    samples.sort_unstable();
    samples
}

fn pct(sorted: &[Duration], p: f64) -> Duration {
    let i = ((sorted.len() as f64) * p).ceil() as usize;
    sorted[i.saturating_sub(1).min(sorted.len() - 1)]
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> ExitCode {
    let mut failed = false;
    let mem = MemoryKv::new();
    for algo in [Algorithm::Counter, Algorithm::Exact, Algorithm::Gcra] {
        let s = measure(&mem, algo, 200_000).await;
        let (p50, p99, max) = (pct(&s, 0.5), pct(&s, 0.99), s[s.len() - 1]);
        let verdict = if p99 <= MEMORY_BUDGET { "PASS" } else { "FAIL" };
        failed |= p99 > MEMORY_BUDGET;
        println!(
            "MemoryKv {:7} p50 {p50:?} p99 {p99:?} max {max:?} budget {MEMORY_BUDGET:?}: {verdict}",
            algo.name()
        );
    }
    match std::env::var("HDD_TEST_REDIS_URL")
        .ok()
        .filter(|u| !u.is_empty())
    {
        None => {
            println!("RedisKv: UNVERIFIED(environment_unsupported): HDD_TEST_REDIS_URL is not set")
        }
        Some(url) => {
            let cfg = RedisConfig::new(&url)
                .or_else(|_| RedisConfig::insecure_loopback_for_tests(&url))
                .expect("url");
            let kv = RedisKv::connect(&cfg).await.expect("connect");
            for algo in [Algorithm::Counter, Algorithm::Exact, Algorithm::Gcra] {
                let s = measure(&kv, algo, 20_000).await;
                let (p50, p99, max) = (pct(&s, 0.5), pct(&s, 0.99), s[s.len() - 1]);
                let verdict = if p99 <= REDIS_BUDGET { "PASS" } else { "FAIL" };
                failed |= p99 > REDIS_BUDGET;
                println!(
                    "RedisKv {:7} p50 {p50:?} p99 {p99:?} max {max:?} budget {REDIS_BUDGET:?}: {verdict}",
                    algo.name()
                );
            }
        }
    }
    if failed {
        ExitCode::FAILURE
    } else {
        ExitCode::SUCCESS
    }
}
