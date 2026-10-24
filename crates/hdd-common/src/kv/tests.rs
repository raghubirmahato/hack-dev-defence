//! T-0562: the conformance suite against `MemoryKv` and `MemoryBus`, and the behavior only the in-process backend has (bounded
//! memory, eviction, pinned namespaces, rehydration, start-up refusal, metrics).
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    reason = "tests"
)]

use std::sync::Arc;
use std::time::Duration;

use proptest::prelude::*;

use super::bus::{Bus, BusEvent, MemoryBus, ResyncReason};
use super::clock::ManualClock;
use super::conformance::{self, Factory};
use super::keys;
use super::limiter::{Limiter, MAX_SCOPES};
use super::memory::{MemoryKv, MemoryLimits};
use super::metrics::{Instrumented, KvMetrics};
use super::rate::{Algorithm, RateRequest};
use super::rehydrate::{DurableRow, DurableSource, rehydrate};
use super::startup::{ServiceRegistry, startup_check};
use super::{KvError, KvStore};
use crate::profile::env::KvBackend;
use crate::profile::types::RuntimeProfile;

struct MemFactory;

impl Factory for MemFactory {
    type Kv = MemoryKv;

    async fn real(&self) -> MemoryKv {
        MemoryKv::new()
    }

    async fn manual(&self) -> (MemoryKv, Arc<ManualClock>) {
        let clock = Arc::new(ManualClock::new(0));
        (
            MemoryKv::with(MemoryLimits::default(), clock.clone()),
            clock,
        )
    }
}

pub(super) fn store(limits: MemoryLimits) -> (MemoryKv, Arc<ManualClock>) {
    let clock = Arc::new(ManualClock::new(1_000));
    (MemoryKv::with(limits, clock.clone()), clock)
}

// ---------------------------------------------------------------------------------------------------------------------
// The shared suite

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_conformance_suite_passes_on_memory_kv_with_ten_thousand_sequences() {
    conformance::run_all(&MemFactory, 10_000).await;
}

#[tokio::test]
async fn bus_ordering_gap_and_lag_detection_on_the_memory_bus() {
    let bus = Arc::new(MemoryBus::new(8));
    let forcing = Arc::clone(&bus);
    conformance::bus_checks(
        &*bus,
        move |channel| {
            let b = Arc::clone(&forcing);
            async move {
                // revision 20 was the last one published; skip 21 to 99
                b.publish_with_revision(&channel, 100, b"after the gap")
                    .unwrap();
            }
        },
        Some(8),
    )
    .await;
}

// ---------------------------------------------------------------------------------------------------------------------
// TTL on the manual clock

#[tokio::test]
async fn ttl_is_exact_on_the_manual_clock_and_expired_keys_are_never_visible() {
    let (kv, clock) = store(MemoryLimits::default());
    kv.set("hdd:t:a", b"v", Some(Duration::from_secs(1)))
        .await
        .unwrap();
    clock.advance_us(999_999);
    assert!(kv.exists("hdd:t:a").await.unwrap());
    assert_eq!(
        kv.ttl("hdd:t:a").await.unwrap(),
        Some(Duration::from_micros(1))
    );
    clock.advance_us(1);
    assert!(!kv.exists("hdd:t:a").await.unwrap());
    assert_eq!(kv.get("hdd:t:a").await.unwrap(), None);
    assert_eq!(kv.stats().expired, 1);
    // an expired key can be recreated
    kv.set("hdd:t:a", b"w", None).await.unwrap();
    assert_eq!(kv.get("hdd:t:a").await.unwrap().as_deref(), Some(&b"w"[..]));
}

#[tokio::test]
async fn re_setting_a_key_replaces_its_ttl_and_a_stale_expiry_does_not_delete_it() {
    let (kv, clock) = store(MemoryLimits::default());
    kv.set("hdd:t:b", b"1", Some(Duration::from_secs(1)))
        .await
        .unwrap();
    kv.set("hdd:t:b", b"2", Some(Duration::from_secs(10)))
        .await
        .unwrap();
    clock.advance_us(2_000_000);
    assert_eq!(kv.sweep(), 0, "the first expiry entry is stale");
    assert_eq!(kv.get("hdd:t:b").await.unwrap().as_deref(), Some(&b"2"[..]));
    kv.set("hdd:t:b", b"3", None).await.unwrap();
    clock.advance_us(60_000_000);
    assert_eq!(kv.get("hdd:t:b").await.unwrap().as_deref(), Some(&b"3"[..]));
}

#[tokio::test]
async fn the_sweeper_removes_idle_expired_keys() {
    let (kv, clock) = store(MemoryLimits::default());
    for i in 0..100 {
        kv.set(
            &format!("hdd:t:sweep:{i}"),
            b"v",
            Some(Duration::from_secs(1)),
        )
        .await
        .unwrap();
    }
    kv.set("hdd:t:sweep:keep", b"v", None).await.unwrap();
    assert_eq!(kv.len(), 101);
    clock.advance_us(1_500_000);
    assert_eq!(kv.len(), 1, "expired keys are not live");
    assert_eq!(kv.sweep(), 100);
    assert_eq!(kv.stats().expired, 100);
    assert!(kv.approx_bytes() > 0);
}

#[tokio::test(start_paused = true)]
async fn the_background_sweeper_runs_on_the_runtime_and_stops_with_the_store() {
    let (kv, clock) = store(MemoryLimits::default());
    let kv = Arc::new(kv);
    kv.set("hdd:t:bg", b"v", Some(Duration::from_secs(1)))
        .await
        .unwrap();
    clock.advance_us(2_000_000);
    let handle = kv.spawn_sweeper(Duration::from_millis(100));
    tokio::time::sleep(Duration::from_millis(250)).await;
    assert_eq!(kv.stats().expired, 1);
    drop(kv);
    tokio::time::sleep(Duration::from_millis(250)).await;
    assert!(
        handle.is_finished(),
        "the sweeper must end when the store is dropped"
    );
}

// ---------------------------------------------------------------------------------------------------------------------
// A5: bounded memory, eviction, pinned namespaces

fn one_shard(max_keys: usize, pinned: usize) -> MemoryLimits {
    MemoryLimits {
        shards: 1,
        max_keys,
        max_bytes: 64 * 1024 * 1024,
        pinned_max_keys: pinned,
    }
}

#[tokio::test]
async fn a_key_flood_is_bounded_and_the_evictions_are_counted() {
    let (kv, _) = store(MemoryLimits {
        shards: 4,
        max_keys: 400,
        max_bytes: 64 * 1024 * 1024,
        pinned_max_keys: 100,
    });
    for i in 0..20_000 {
        kv.set(&format!("hdd:t:flood:{i}"), b"payload", None)
            .await
            .unwrap();
    }
    assert!(kv.len() <= 400, "{} keys held", kv.len());
    let s = kv.stats();
    assert_eq!(s.evicted, 20_000 - kv.len() as u64);
    assert_eq!(s.pinned_rejected, 0);
}

#[tokio::test]
async fn bytes_are_bounded_too() {
    let (kv, _) = store(MemoryLimits {
        shards: 1,
        max_keys: 1_000_000,
        max_bytes: 100_000,
        pinned_max_keys: 10,
    });
    let value = vec![1u8; 1000];
    for i in 0..1000 {
        kv.set(&format!("hdd:t:big:{i}"), &value, None)
            .await
            .unwrap();
    }
    assert!(kv.approx_bytes() <= 100_000, "{} bytes", kv.approx_bytes());
    assert!(kv.stats().evicted > 800);
}

#[tokio::test]
async fn the_least_recently_used_key_goes_first() {
    let (kv, _) = store(one_shard(3, 10));
    kv.set("hdd:t:a", b"1", None).await.unwrap();
    kv.set("hdd:t:b", b"2", None).await.unwrap();
    kv.set("hdd:t:c", b"3", None).await.unwrap();
    assert!(kv.get("hdd:t:a").await.unwrap().is_some(), "touch a");
    kv.set("hdd:t:d", b"4", None).await.unwrap();
    assert!(
        !kv.exists("hdd:t:b").await.unwrap(),
        "b was the least recently used"
    );
    for k in ["hdd:t:a", "hdd:t:c", "hdd:t:d"] {
        assert!(kv.exists(k).await.unwrap(), "{k}");
    }
}

#[tokio::test]
async fn expired_keys_are_dropped_before_live_keys_are_evicted() {
    let (kv, clock) = store(one_shard(3, 10));
    kv.set("hdd:t:old", b"1", Some(Duration::from_secs(1)))
        .await
        .unwrap();
    kv.set("hdd:t:b", b"2", None).await.unwrap();
    kv.set("hdd:t:c", b"3", None).await.unwrap();
    clock.advance_us(2_000_000);
    kv.set("hdd:t:d", b"4", None).await.unwrap();
    let s = kv.stats();
    assert_eq!(
        (s.expired, s.evicted),
        (1, 0),
        "the expired key made the room"
    );
    for k in ["hdd:t:b", "hdd:t:c", "hdd:t:d"] {
        assert!(kv.exists(k).await.unwrap(), "{k}");
    }
}

#[tokio::test]
async fn pinned_namespaces_are_never_evicted() {
    let (kv, _) = store(MemoryLimits {
        shards: 2,
        max_keys: 50,
        max_bytes: 64 * 1024 * 1024,
        pinned_max_keys: 20,
    });
    let ban = keys::ban("org", "site", "ip1").unwrap();
    kv.hset(&ban, "reason", b"sqli", Some(Duration::from_secs(3600)))
        .await
        .unwrap();
    kv.zadd(keys::BANNED_IPS, 99.0, "ip1", None).await.unwrap();
    kv.hset(
        &keys::session("abc").unwrap(),
        "user",
        b"u1",
        Some(Duration::from_secs(3600)),
    )
    .await
    .unwrap();
    kv.hset(
        &keys::gate_session("site", "tok").unwrap(),
        "u",
        b"1",
        Some(Duration::from_secs(3600)),
    )
    .await
    .unwrap();
    for i in 0..5_000 {
        kv.set(&format!("hdd:t:flood:{i}"), b"x", None)
            .await
            .unwrap();
    }
    assert!(kv.stats().evicted > 4_000);
    assert_eq!(kv.pinned_len(), 4);
    assert_eq!(
        kv.hget(&ban, "reason").await.unwrap().as_deref(),
        Some(&b"sqli"[..])
    );
    assert_eq!(kv.zcard(keys::BANNED_IPS).await.unwrap(), 1);
    assert!(kv.exists(&keys::session("abc").unwrap()).await.unwrap());
    assert!(
        kv.exists(&keys::gate_session("site", "tok").unwrap())
            .await
            .unwrap()
    );
}

#[tokio::test]
async fn the_pinned_cap_is_a_clear_error_that_writes_nothing() {
    let (kv, _) = store(MemoryLimits {
        shards: 1,
        max_keys: 1000,
        max_bytes: 64 * 1024 * 1024,
        pinned_max_keys: 3,
    });
    for i in 0..3 {
        kv.hset(
            &keys::ban("o", "s", &format!("ip{i}")).unwrap(),
            "r",
            b"x",
            None,
        )
        .await
        .unwrap();
    }
    let extra = keys::ban("o", "s", "ip-extra").unwrap();
    let err = kv.hset(&extra, "r", b"x", None).await.unwrap_err();
    assert!(matches!(err, KvError::PinnedFull { cap: 3, .. }), "{err:?}");
    assert!(err.to_string().contains("pinned"));
    assert!(!kv.exists(&extra).await.unwrap(), "nothing was written");
    assert_eq!(kv.stats().pinned_rejected, 1);
    // existing pinned keys can still change
    kv.hset(&keys::ban("o", "s", "ip0").unwrap(), "r", b"updated", None)
        .await
        .unwrap();
    // a session is refused too, since the cap is shared by the namespaces
    assert!(matches!(
        kv.hset(&keys::session("s1").unwrap(), "u", b"1", None)
            .await,
        Err(KvError::PinnedFull { .. })
    ));
    // deleting makes room
    assert!(kv.del(&keys::ban("o", "s", "ip1").unwrap()).await.unwrap());
    kv.hset(&extra, "r", b"x", None).await.unwrap();
    // ordinary keys are not affected by the pinned cap
    kv.set("hdd:t:ordinary", b"v", None).await.unwrap();
}

#[tokio::test]
async fn expired_pinned_keys_free_their_slot() {
    let (kv, clock) = store(one_shard(100, 2));
    kv.hset("hdd:sess:a", "u", b"1", Some(Duration::from_secs(1)))
        .await
        .unwrap();
    kv.hset("hdd:sess:b", "u", b"1", Some(Duration::from_secs(1)))
        .await
        .unwrap();
    clock.advance_us(1_500_000);
    kv.sweep();
    assert_eq!(kv.pinned_len(), 0);
    kv.hset("hdd:sess:c", "u", b"1", Some(Duration::from_secs(1)))
        .await
        .unwrap();
    assert_eq!(kv.pinned_len(), 1);
}

#[tokio::test]
async fn a_shard_full_of_pinned_keys_refuses_ordinary_writes_with_a_clear_error() {
    let (kv, _) = store(one_shard(2, 10));
    kv.hset("hdd:sess:a", "u", b"1", None).await.unwrap();
    kv.hset("hdd:sess:b", "u", b"1", None).await.unwrap();
    assert_eq!(
        kv.set("hdd:t:x", b"v", None).await.unwrap_err(),
        KvError::Full
    );
    assert_eq!(kv.stats().full_rejected, 1);
    assert!(kv.exists("hdd:sess:a").await.unwrap());
}

proptest! {
    #![proptest_config(ProptestConfig { cases: 64, .. ProptestConfig::default() })]

    /// Whatever the sequence of writes, the key count stays within the cap, pinned keys survive and the accounting is exact.
    #[test]
    fn eviction_invariants_hold_for_any_operation_sequence(
        ops in proptest::collection::vec((0u8..6, 0u16..400, 0u32..3_000_000), 1..300)
    ) {
        let rt = tokio::runtime::Builder::new_current_thread().enable_time().build().unwrap();
        rt.block_on(async {
            let (kv, clock) = store(MemoryLimits { shards: 2, max_keys: 40, max_bytes: 64 * 1024 * 1024, pinned_max_keys: 6 });
            let mut pinned_live = std::collections::BTreeSet::new();
            for (kind, n, advance) in ops {
                clock.advance_us(u64::from(advance % 2000));
                match kind {
                    0 | 1 => { let _ = kv.set(&format!("hdd:t:p:{n}"), b"v", None).await; }
                    2 => { let _ = kv.set(&format!("hdd:t:e:{n}"), b"v", Some(Duration::from_micros(u64::from(advance) + 1))).await; }
                    3 => {
                        let k = format!("hdd:sess:{}", n % 10);
                        if kv.hset(&k, "u", b"1", None).await.is_ok() { pinned_live.insert(k); }
                    }
                    4 => {
                        let k = format!("hdd:sess:{}", n % 10);
                        if kv.del(&k).await.unwrap() { pinned_live.remove(&k); }
                    }
                    _ => { let _ = kv.get(&format!("hdd:t:p:{n}")).await; }
                }
                prop_assert!(kv.len() <= 40 + 1);
                prop_assert!(kv.pinned_len() <= 6);
            }
            for k in pinned_live {
                prop_assert!(kv.exists(&k).await.unwrap(), "pinned key {k} vanished");
            }
            Ok(())
        })?;
    }
}

// ---------------------------------------------------------------------------------------------------------------------
// Limiter

#[tokio::test]
async fn the_limiter_checks_up_to_four_scopes_and_answers_with_the_most_restrictive() {
    let (kv, _) = store(MemoryLimits::default());
    let l = Limiter::new(Arc::new(kv));
    let w = Duration::from_secs(10);
    // the second scope is nearly used up
    for _ in 0..4 {
        l.check(&["hdd:rl:s:ip:b"], 5, w, Algorithm::Exact)
            .await
            .unwrap();
    }
    let d = l
        .check(&["hdd:rl:s:ip:a", "hdd:rl:s:ip:b"], 5, w, Algorithm::Exact)
        .await
        .unwrap();
    assert!(d.allowed);
    assert_eq!(d.remaining, 0, "min over scopes");
    let d = l
        .check(&["hdd:rl:s:ip:a", "hdd:rl:s:ip:b"], 5, w, Algorithm::Exact)
        .await
        .unwrap();
    assert!(!d.allowed, "one denied scope denies the call");
    assert_eq!(d.violations, 1);
    assert!(d.reset_ms > 0 && d.reset_ms <= 10_000);
    let keys: Vec<String> = (0..5).map(|i| format!("hdd:rl:s:ip:{i}")).collect();
    let refs: Vec<&str> = keys.iter().map(String::as_str).collect();
    assert_eq!(MAX_SCOPES, 4);
    assert!(matches!(
        l.check(&refs, 5, w, Algorithm::Exact).await,
        Err(KvError::TooManyScopes { got: 5 })
    ));
    assert!(matches!(
        l.check(&[], 5, w, Algorithm::Exact).await,
        Err(KvError::InvalidArgument(_))
    ));
}

#[tokio::test]
async fn invalid_rate_requests_are_refused_the_same_way_everywhere() {
    let (kv, _) = store(MemoryLimits::default());
    let w = Duration::from_secs(1);
    for req in [
        RateRequest::new(0, w, Algorithm::Counter),
        RateRequest::new(10_000_001, w, Algorithm::Counter),
        RateRequest::new(5, Duration::from_micros(10), Algorithm::Counter),
        RateRequest::new(5, Duration::from_secs(90_000), Algorithm::Counter),
        RateRequest {
            cost: 0,
            ..RateRequest::new(5, w, Algorithm::Exact)
        },
        RateRequest {
            cost: 6,
            ..RateRequest::new(5, w, Algorithm::Exact)
        },
        RateRequest::new(5_000, Duration::from_millis(1), Algorithm::Gcra),
        // limit * window above 2^50 unit-microseconds: the scripts of the hosted backend would lose precision
        RateRequest::new(10_000_000, Duration::from_secs(86_400), Algorithm::Exact),
        RateRequest::new(2_000_000, Duration::from_secs(600), Algorithm::Counter),
    ] {
        assert!(
            matches!(
                kv.rate_window_check("hdd:rl:s:x:y", &req).await,
                Err(KvError::InvalidArgument(_))
            ),
            "{req:?}"
        );
    }
}

#[tokio::test]
async fn the_largest_accepted_limit_and_window_products_still_work() {
    let (kv, _) = store(MemoryLimits::default());
    // 1,000,000 units for 18 minutes is 1.08e15 < 2^50
    let r = RateRequest::new(1_000_000, Duration::from_secs(1_080), Algorithm::Counter);
    assert!(
        kv.rate_window_check("hdd:rl:s:big:k", &r)
            .await
            .unwrap()
            .allowed
    );
}

#[tokio::test]
async fn changing_a_limits_algorithm_starts_the_key_afresh() {
    let (kv, _) = store(MemoryLimits::default());
    let w = Duration::from_secs(10);
    for _ in 0..3 {
        kv.rate_window_check("hdd:rl:s:a:b", &RateRequest::new(3, w, Algorithm::Exact))
            .await
            .unwrap();
    }
    assert!(
        !kv.rate_window_check("hdd:rl:s:a:b", &RateRequest::new(3, w, Algorithm::Exact))
            .await
            .unwrap()
            .allowed
    );
    assert!(
        kv.rate_window_check("hdd:rl:s:a:b", &RateRequest::new(3, w, Algorithm::Gcra))
            .await
            .unwrap()
            .allowed
    );
}

#[tokio::test]
async fn rate_state_is_forgotten_after_its_window() {
    let (kv, clock) = store(MemoryLimits::default());
    let w = Duration::from_secs(1);
    for algo in [Algorithm::Counter, Algorithm::Exact, Algorithm::Gcra] {
        let key = format!("hdd:rl:s:{}:k", algo.name());
        kv.rate_window_check(&key, &RateRequest::new(2, w, algo))
            .await
            .unwrap();
        assert!(kv.exists(&key).await.unwrap());
        clock.advance_us(5_000_000);
        assert!(
            !kv.exists(&key).await.unwrap(),
            "{algo:?} state outlived its window"
        );
    }
}

// ---------------------------------------------------------------------------------------------------------------------
// Bus details

#[tokio::test]
async fn subscribers_only_see_messages_published_after_they_subscribed() {
    let bus = MemoryBus::new(16);
    bus.publish(keys::CH_BAN, b"before").await.unwrap();
    let mut sub = bus.subscribe(keys::CH_BAN).await.unwrap();
    bus.publish(keys::CH_BAN, b"after").await.unwrap();
    assert_eq!(
        sub.recv().await,
        BusEvent::Message {
            revision: 2,
            payload: b"after".to_vec()
        },
        "a late subscriber starts at the current revision without a false gap"
    );
}

#[tokio::test]
async fn every_subscriber_gets_every_message_and_a_closed_bus_ends_the_stream() {
    let bus = MemoryBus::new(16);
    let mut a = bus.subscribe("hdd:events:config").await.unwrap();
    let mut b = bus.subscribe("hdd:events:config").await.unwrap();
    for i in 0..3u8 {
        bus.publish("hdd:events:config", &[i]).await.unwrap();
    }
    for sub in [&mut a, &mut b] {
        for i in 0..3u8 {
            assert!(
                matches!(sub.recv().await, BusEvent::Message { revision, ref payload } if revision == u64::from(i) + 1 && payload == &[i])
            );
        }
    }
    assert_eq!(bus.published_total(), 3);
    drop(bus);
    assert_eq!(a.recv().await, BusEvent::Closed);
}

#[tokio::test]
async fn a_slow_subscriber_is_resynced_and_the_buffer_stays_bounded() {
    let bus = MemoryBus::new(4);
    let mut slow = bus.subscribe("hdd:events:ban").await.unwrap();
    for i in 0..100u8 {
        bus.publish("hdd:events:ban", &[i]).await.unwrap();
    }
    assert!(
        matches!(slow.recv().await, BusEvent::Resync(ResyncReason::Lagged { missed }) if missed >= 96)
    );
    // the buffer holds the newest four messages
    let mut got = Vec::new();
    for _ in 0..4 {
        if let BusEvent::Message { revision, .. } = slow.recv().await {
            got.push(revision);
        }
    }
    assert_eq!(got, vec![97, 98, 99, 100]);
    assert_eq!(slow.resyncs(), 1);
}

#[tokio::test]
async fn bus_arguments_are_validated() {
    let bus = MemoryBus::new(4);
    assert!(matches!(
        bus.publish("", b"x").await,
        Err(KvError::BadKey(_))
    ));
    assert!(matches!(
        bus.subscribe("bad\nname").await,
        Err(KvError::BadKey(_))
    ));
    assert!(matches!(
        bus.publish("hdd:events:config", &vec![0u8; super::MAX_VALUE_BYTES + 1])
            .await,
        Err(KvError::ValueTooLarge { .. })
    ));
}

// ---------------------------------------------------------------------------------------------------------------------
// Keys

#[test]
fn keys_follow_b5_12_and_reject_separators_in_parts() {
    assert_eq!(keys::ban("o", "s", "ip").unwrap(), "hdd:ban:o:s:ip");
    assert_eq!(keys::ban_global("ip").unwrap(), "hdd:ban:g:ip");
    assert_eq!(
        keys::rate_limit("s", "ip", "1.2.3.4").unwrap(),
        "hdd:rl:s:ip:1.2.3.4"
    );
    assert_eq!(keys::offence("o", "ip").unwrap(), "hdd:offence:o:ip");
    assert_eq!(keys::session("h").unwrap(), "hdd:sess:h");
    assert_eq!(keys::challenge_nonce("n").unwrap(), "hdd:chal:nonce:n");
    assert_eq!(keys::credential_failures("s", "u").unwrap(), "hdd:cred:s:u");
    assert_eq!(keys::campaign("s", "sig").unwrap(), "hdd:camp:s:sig");
    assert_eq!(keys::firewall_ack(7).unwrap(), "hdd:fw:ack:7");
    assert_eq!(keys::node_heartbeat("n1").unwrap(), "hdd:node:n1:hb");
    assert_eq!(keys::site_events("s").unwrap(), "hdd:events:s");
    assert_eq!(keys::gate_session("s", "t").unwrap(), "hdd:gate:sess:s:t");
    assert_eq!(keys::flow("s", "f", "k").unwrap(), "hdd:flow:s:f:k");
    assert_eq!(keys::loopback_identity("h").unwrap(), "hdd:lo:h");
    assert_eq!(
        keys::acme_challenge("tok").unwrap(),
        "hdd:acme:challenge:tok"
    );
    // a caller-controlled part cannot address another namespace
    for bad in ["a:b", "", "a b", "a\nb"] {
        assert!(keys::ban("o", "s", bad).is_err(), "{bad:?}");
        assert!(keys::rate_limit(bad, "ip", "k").is_err(), "{bad:?}");
    }
    assert!(keys::session(&"h".repeat(600)).is_err());
}

// ---------------------------------------------------------------------------------------------------------------------
// A3: rehydration from a fixture durable source

pub(super) struct Fixture(Vec<DurableRow>);

impl DurableSource for Fixture {
    async fn load(&self) -> Result<Vec<DurableRow>, String> {
        Ok(self.0.clone())
    }
}

struct Broken;

impl DurableSource for Broken {
    async fn load(&self) -> Result<Vec<DurableRow>, String> {
        Err("connection refused".into())
    }
}

pub(super) fn fixture(now: i64) -> Fixture {
    let hour = 3_600_000;
    Fixture(vec![
        DurableRow::Ban {
            key: keys::ban("o", "s", "ip1").unwrap(),
            member: "ip1".into(),
            fields: vec![
                ("reason".into(), b"sqli".to_vec()),
                ("step".into(), b"2".to_vec()),
            ],
            expires_unix_ms: now + hour,
        },
        DurableRow::Ban {
            key: keys::ban("o", "s", "ip-old").unwrap(),
            member: "ip-old".into(),
            fields: vec![("reason".into(), b"x".to_vec())],
            expires_unix_ms: now - 1,
        },
        DurableRow::Offence {
            key: keys::offence("o", "ip1").unwrap(),
            count: 4,
            last_unix_ms: now - 150_000,
            decay: Duration::from_secs(60),
            ttl: Duration::from_secs(3600),
        },
        DurableRow::Offence {
            key: keys::offence("o", "ip-forgiven").unwrap(),
            count: 1,
            last_unix_ms: now - 600_000,
            decay: Duration::from_secs(60),
            ttl: Duration::from_secs(7200),
        },
        DurableRow::Session {
            key: keys::session("abc").unwrap(),
            fields: vec![("user".into(), b"u1".to_vec())],
            expires_unix_ms: now + 60_000,
        },
    ])
}

#[tokio::test]
async fn a3_rehydration_rebuilds_bans_offences_and_sessions_and_reports_rows_and_time() {
    let now = 1_700_000_000_000i64;
    let (kv, clock) = store(MemoryLimits::default());
    let report = rehydrate(&kv, &fixture(now), now).await.unwrap();
    assert_eq!((report.bans, report.offences, report.sessions), (1, 1, 1));
    assert_eq!(
        report.skipped_expired, 2,
        "the expired ban and the fully forgiven offence"
    );
    assert_eq!(report.rows(), 3);
    assert!(
        report
            .render_prometheus()
            .contains("hdd_kv_rehydrate_rows{kind=\"ban\"} 1")
    );
    assert!(
        report
            .render_prometheus()
            .contains("hdd_kv_rehydrate_seconds")
    );

    let ban = keys::ban("o", "s", "ip1").unwrap();
    assert_eq!(
        kv.hget(&ban, "reason").await.unwrap().as_deref(),
        Some(&b"sqli"[..])
    );
    let left = kv.ttl(&ban).await.unwrap().unwrap();
    assert!(left <= Duration::from_secs(3600) && left > Duration::from_secs(3590));
    assert_eq!(
        kv.zrange_by_score(keys::BANNED_IPS, 0.0, f64::MAX, 10)
            .await
            .unwrap(),
        vec![("ip1".to_owned(), (now + 3_600_000) as f64)]
    );
    assert!(
        !kv.exists(&keys::ban("o", "s", "ip-old").unwrap())
            .await
            .unwrap()
    );
    assert_eq!(
        kv.hget(&keys::session("abc").unwrap(), "user")
            .await
            .unwrap()
            .as_deref(),
        Some(&b"u1"[..])
    );
    // 4 offences minus two whole decay steps in 150 s = 2; the next offence makes 3
    let o = keys::offence("o", "ip1").unwrap();
    assert_eq!(
        kv.offence_incr_with_decay(
            &o,
            Duration::from_secs(365 * 24 * 3600),
            Duration::from_secs(60)
        )
        .await
        .unwrap(),
        3
    );
    // session expiry is honored after the restart
    clock.advance_us(61_000_000);
    assert!(!kv.exists(&keys::session("abc").unwrap()).await.unwrap());
}

#[tokio::test]
async fn rehydration_fails_loudly_when_the_source_fails_or_the_pinned_cap_is_too_small() {
    let (kv, _) = store(MemoryLimits::default());
    assert!(
        matches!(rehydrate(&kv, &Broken, 0).await, Err(KvError::Backend(m)) if m.contains("refused"))
    );

    let now = 1_700_000_000_000i64;
    let (small, _) = store(MemoryLimits {
        shards: 1,
        max_keys: 100,
        max_bytes: 1 << 20,
        pinned_max_keys: 1,
    });
    let err = rehydrate(&small, &fixture(now), now).await.unwrap_err();
    assert!(matches!(err, KvError::PinnedFull { .. }), "{err:?}");
}

#[tokio::test]
async fn non_durable_state_is_not_rehydrated_and_resets_on_restart() {
    let now = 1_700_000_000_000i64;
    let (before, _) = store(MemoryLimits::default());
    before
        .rate_window_check(
            "hdd:rl:s:ip:1",
            &RateRequest::new(1, Duration::from_secs(60), Algorithm::Exact),
        )
        .await
        .unwrap();
    before
        .set(
            &keys::challenge_nonce("n1").unwrap(),
            b"v",
            Some(Duration::from_secs(60)),
        )
        .await
        .unwrap();
    // "restart": a new store rebuilt from the durable source only
    let (after, _) = store(MemoryLimits::default());
    rehydrate(&after, &fixture(now), now).await.unwrap();
    assert!(!after.exists("hdd:rl:s:ip:1").await.unwrap());
    assert!(
        !after
            .exists(&keys::challenge_nonce("n1").unwrap())
            .await
            .unwrap()
    );
    let d = after
        .rate_window_check(
            "hdd:rl:s:ip:1",
            &RateRequest::new(1, Duration::from_secs(60), Algorithm::Exact),
        )
        .await
        .unwrap();
    assert!(d.allowed, "a reset only forgives");
}

// ---------------------------------------------------------------------------------------------------------------------
// Start-up refusal and metrics

#[test]
fn memory_with_hosted_and_several_service_processes_is_refused() {
    let many = ServiceRegistry { processes: 3 };
    let one = ServiceRegistry { processes: 1 };
    let err = startup_check(KvBackend::Memory, RuntimeProfile::Hosted, many).unwrap_err();
    assert!(matches!(err, KvError::MemoryBackendRefused(_)));
    assert!(err.to_string().contains("HDD_KV_BACKEND=redis"));
    assert!(startup_check(KvBackend::Memory, RuntimeProfile::Hosted, one).is_ok());
    assert!(startup_check(KvBackend::Memory, RuntimeProfile::Local, many).is_ok());
    assert!(startup_check(KvBackend::Redis, RuntimeProfile::Hosted, many).is_ok());
}

#[tokio::test]
async fn operations_are_counted_and_timed_by_backend_op_and_result() {
    let metrics = Arc::new(KvMetrics::new());
    let kv = Instrumented::new(MemoryKv::new(), Arc::clone(&metrics));
    kv.set("hdd:t:m", b"v", None).await.unwrap();
    kv.get("hdd:t:m").await.unwrap();
    kv.get("hdd:t:m").await.unwrap();
    assert!(kv.get("").await.is_err());
    assert_eq!(metrics.ops("memory", "get", "ok"), 2);
    assert_eq!(metrics.ops("memory", "get", "error"), 1);
    assert_eq!(metrics.ops("memory", "set", "ok"), 1);
    let text = metrics.render_prometheus();
    assert!(
        text.contains("hdd_kv_ops_total{backend=\"memory\",op=\"get\",result=\"ok\"} 2"),
        "{text}"
    );
    assert!(
        text.contains("hdd_kv_latency_seconds_count{backend=\"memory\",op=\"get\"} 3"),
        "{text}"
    );
    assert!(text.contains("le=\"+Inf\""));
}

#[tokio::test]
async fn limiter_over_an_instrumented_store_counts_rate_checks() {
    let metrics = Arc::new(KvMetrics::new());
    let kv = Arc::new(Instrumented::new(MemoryKv::new(), Arc::clone(&metrics)));
    let l = Limiter::new(kv);
    l.check(
        &["hdd:rl:s:ip:a", "hdd:rl:s:ip:b"],
        5,
        Duration::from_secs(1),
        Algorithm::Counter,
    )
    .await
    .unwrap();
    assert_eq!(metrics.ops("memory", "rate_window_check", "ok"), 2);
}
