//! The shared conformance suite against a real Redis (T-0562 A1, second half).
//!
//! Needs `HDD_TEST_REDIS_URL` (a Redis 7 or newer server; use a throw-away instance: the suite writes keys under `hdd:conf:`).
//! A `redis://` URL is accepted for a loopback host only. Without the variable this test prints
//! `UNVERIFIED(environment_unsupported)` and returns: the Redis half of the acceptance criterion is then unverified, which
//! `cargo xtask verify` (step `kv-redis`) reports as such instead of counting it as a pass.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::print_stdout,
    reason = "test"
)]

use std::sync::Arc;

use hdd_common::kv::bus::Bus;
use hdd_common::kv::clock::ManualClock;
use hdd_common::kv::conformance::{self, Factory};
use hdd_common::kv::redis::{RedisBus, RedisConfig, RedisKv};

struct RedisFactory {
    cfg: RedisConfig,
}

impl Factory for RedisFactory {
    type Kv = RedisKv;

    async fn real(&self) -> RedisKv {
        RedisKv::connect(&self.cfg).await.expect("connect")
    }

    async fn manual(&self) -> (RedisKv, Arc<ManualClock>) {
        let clock = Arc::new(ManualClock::new(0));
        let kv = RedisKv::connect(&self.cfg)
            .await
            .expect("connect")
            .with_clock(clock.clone());
        (kv, clock)
    }
}

fn config() -> Option<RedisConfig> {
    let url = std::env::var("HDD_TEST_REDIS_URL")
        .ok()
        .filter(|u| !u.is_empty())?;
    Some(
        RedisConfig::new(&url)
            .or_else(|_| RedisConfig::insecure_loopback_for_tests(&url))
            .expect(
                "HDD_TEST_REDIS_URL must be rediss:// with a password, or redis:// on loopback",
            ),
    )
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn redis_passes_the_conformance_suite() {
    let Some(cfg) = config() else {
        println!(
            "UNVERIFIED(environment_unsupported): HDD_TEST_REDIS_URL is not set; the Redis backend was not exercised"
        );
        return;
    };
    let f = RedisFactory { cfg: cfg.clone() };
    conformance::run_all(&f, 300).await;

    let kv = Arc::new(f.real().await);
    let bus = Arc::new(RedisBus::connect(&cfg, kv, 256).await.expect("bus"));
    let forcing = Arc::clone(&bus);
    conformance::bus_checks(
        &*bus,
        move |channel| {
            let b = Arc::clone(&forcing);
            async move {
                b.publish_raw(&channel, 10_000, b"after the gap")
                    .await
                    .unwrap();
            }
        },
        None,
    )
    .await;
    let _ = bus.publish("hdd:conf:done", b"x").await;
}
