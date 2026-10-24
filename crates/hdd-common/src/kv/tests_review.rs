//! Tests added for the findings of the independent review of 2026-10-19 (see docs/evidence/P33/hostile-review.md).
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    reason = "tests"
)]

use std::sync::Arc;
use std::time::Duration;

use super::keys;
use super::limiter::Limiter;
use super::memory::{MemoryKv, MemoryLimits, parse_redis_int};
use super::rate::{Algorithm, RateRequest};
use super::rehydrate::rehydrate;
use super::tests::{fixture, store};
use super::{KvError, KvStore, MAX_FLOW_SIGNALS, MAX_MEMBERS};

#[tokio::test]
async fn the_expiry_heap_stays_proportional_to_the_live_keys_without_a_sweeper() {
    let (kv, clock) = store(MemoryLimits::default());
    let req = RateRequest::new(100_000, Duration::from_secs(3600), Algorithm::Counter);
    for i in 0..100_000u64 {
        clock.advance_us(10);
        kv.rate_window_check("hdd:rl:s:ip:one", &req).await.unwrap();
        if i % 7 == 0 {
            kv.set("hdd:t:other", b"v", Some(Duration::from_secs(5)))
                .await
                .unwrap();
        }
    }
    let heap = kv.expiry_heap_len();
    // each shard compacts its own heap at 4 * its keys + 1024; the two live keys may sit in different shards
    assert!(
        heap <= 2 * (4 * kv.len() + 1030),
        "{heap} heap entries for {} keys",
        kv.len()
    );
}

#[tokio::test]
async fn a_pinned_key_can_still_be_updated_at_the_cap_and_a_refused_insert_leaks_nothing() {
    let (kv, _) = store(MemoryLimits {
        shards: 1,
        max_keys: 100,
        max_bytes: 1 << 20,
        pinned_max_keys: 1,
    });
    kv.set("hdd:ban:o:s:a", b"v1", None).await.unwrap();
    kv.set("hdd:ban:o:s:a", b"v2", None).await.unwrap();
    assert_eq!(
        kv.get("hdd:ban:o:s:a").await.unwrap().as_deref(),
        Some(&b"v2"[..])
    );
    assert!(
        kv.compare_and_set("hdd:ban:o:s:a", Some(b"v2"), b"v3", None)
            .await
            .unwrap()
    );
    assert!(matches!(
        kv.set("hdd:ban:o:s:b", b"x", None).await,
        Err(KvError::PinnedFull { .. })
    ));
    assert_eq!(kv.pinned_len(), 1, "a refused insert must not leak a slot");
    assert_eq!(
        kv.get("hdd:ban:o:s:a").await.unwrap().as_deref(),
        Some(&b"v3"[..])
    );
    // replacing a key of another type keeps the accounting right
    kv.hset("hdd:t:h", "f", b"1", None).await.unwrap();
    kv.set("hdd:t:h", b"now a string", None).await.unwrap();
    assert_eq!(
        kv.get("hdd:t:h").await.unwrap().as_deref(),
        Some(&b"now a string"[..])
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn concurrent_pinned_inserts_never_overshoot_the_cap() {
    let (kv, _) = store(MemoryLimits {
        shards: 16,
        max_keys: 100_000,
        max_bytes: 1 << 28,
        pinned_max_keys: 10,
    });
    let kv = Arc::new(kv);
    let mut handles = Vec::new();
    for t in 0..8 {
        let kv = Arc::clone(&kv);
        handles.push(tokio::spawn(async move {
            let mut ok = 0;
            for i in 0..50 {
                if kv
                    .hset(&format!("hdd:sess:{t}-{i}"), "u", b"1", None)
                    .await
                    .is_ok()
                {
                    ok += 1;
                }
            }
            ok
        }));
    }
    let mut accepted = 0;
    for h in handles {
        accepted += h.await.unwrap();
    }
    assert_eq!(accepted, 10, "exactly the cap was accepted");
    assert_eq!(kv.pinned_len(), 10);
}

#[tokio::test]
async fn expired_pinned_keys_do_not_block_new_ones_even_without_a_sweep() {
    let (kv, clock) = store(MemoryLimits {
        shards: 1,
        max_keys: 100,
        max_bytes: 1 << 20,
        pinned_max_keys: 2,
    });
    kv.hset("hdd:ban:o:s:a", "r", b"x", Some(Duration::from_secs(1)))
        .await
        .unwrap();
    kv.hset("hdd:ban:o:s:b", "r", b"x", Some(Duration::from_secs(1)))
        .await
        .unwrap();
    clock.advance_us(2_000_000);
    kv.hset("hdd:ban:o:s:c", "r", b"x", Some(Duration::from_secs(60)))
        .await
        .unwrap();
    assert_eq!(kv.pinned_len(), 1);
}

#[tokio::test]
async fn one_collection_cannot_grow_without_bound() {
    let (kv, _) = store(MemoryLimits::default());
    let cap = MAX_MEMBERS;
    for i in 0..cap {
        kv.sadd("hdd:camp:s:sig", &format!("m{i}"), None)
            .await
            .unwrap();
    }
    assert!(matches!(
        kv.sadd("hdd:camp:s:sig", "one-more", None).await,
        Err(KvError::CollectionFull { .. })
    ));
    assert!(
        !kv.sadd("hdd:camp:s:sig", "m5", None).await.unwrap(),
        "an existing member is still accepted"
    );
    for i in 0..cap {
        kv.hset("hdd:t:h", &format!("f{i}"), b"v", None)
            .await
            .unwrap();
    }
    assert!(matches!(
        kv.hset("hdd:t:h", "extra", b"v", None).await,
        Err(KvError::CollectionFull { .. })
    ));
    kv.hset("hdd:t:h", "f1", b"changed", None).await.unwrap();
    for i in 0..cap {
        kv.zadd("hdd:t:z", i as f64, &format!("m{i}"), None)
            .await
            .unwrap();
    }
    assert!(matches!(
        kv.zadd("hdd:t:z", 0.0, "extra", None).await,
        Err(KvError::CollectionFull { .. })
    ));
    assert!(!kv.zadd("hdd:t:z", 9.0, "m1", None).await.unwrap());
    for i in 0..MAX_FLOW_SIGNALS {
        kv.flow_signal_update(
            "hdd:flow:s:f:k",
            &format!("sig{i}"),
            Duration::from_secs(60),
        )
        .await
        .unwrap();
    }
    assert!(matches!(
        kv.flow_signal_update("hdd:flow:s:f:k", "extra", Duration::from_secs(60))
            .await,
        Err(KvError::CollectionFull { .. })
    ));
    kv.flow_signal_update("hdd:flow:s:f:k", "sig0", Duration::from_secs(60))
        .await
        .unwrap();
}

#[test]
fn incr_accepts_exactly_the_integers_redis_accepts() {
    for (s, want) in [
        ("0", Some(0)),
        ("5", Some(5)),
        ("-5", Some(-5)),
        ("9223372036854775807", Some(i64::MAX)),
        ("-9223372036854775808", Some(i64::MIN)),
    ] {
        assert_eq!(parse_redis_int(s.as_bytes()), want, "{s}");
    }
    for s in [
        "",
        "+5",
        "007",
        "-0",
        " 5",
        "5 ",
        "5.0",
        "0x10",
        "9223372036854775808",
        "--5",
        "-",
        "1e3",
    ] {
        assert_eq!(parse_redis_int(s.as_bytes()), None, "{s:?}");
    }
    assert_eq!(parse_redis_int(&[0xff, 0xfe]), None);
}

#[tokio::test]
async fn a_nan_score_bound_is_refused() {
    let (kv, _) = store(MemoryLimits::default());
    kv.zadd("hdd:t:z", 1.0, "a", None).await.unwrap();
    assert!(matches!(
        kv.zrange_by_score("hdd:t:z", f64::NAN, 5.0, 10).await,
        Err(KvError::InvalidArgument(_))
    ));
    assert!(matches!(
        kv.zrange_by_score("hdd:t:z", 0.0, f64::NAN, 10).await,
        Err(KvError::InvalidArgument(_))
    ));
    assert_eq!(
        kv.zrange_by_score("hdd:t:z", f64::NEG_INFINITY, f64::INFINITY, 10)
            .await
            .unwrap()
            .len(),
        1
    );
}

#[tokio::test]
async fn a_client_over_its_own_limit_does_not_use_up_the_shared_budget() {
    let l = Limiter::new(Arc::new(MemoryKv::new()));
    let w = Duration::from_secs(60);
    let own = RateRequest::new(2, w, Algorithm::Exact);
    for _ in 0..2 {
        assert!(
            l.check_request(&["hdd:rl:s:ip:a", "hdd:rl:s:g:x"], &own)
                .await
                .unwrap()
                .allowed
        );
    }
    for _ in 0..40 {
        let d = l
            .check_request(&["hdd:rl:s:ip:a", "hdd:rl:s:g:x"], &own)
            .await
            .unwrap();
        assert!(!d.allowed);
    }
    let probe = l
        .check_request(
            &["hdd:rl:s:g:x"],
            &RateRequest::new(100, w, Algorithm::Exact),
        )
        .await
        .unwrap();
    assert_eq!(
        probe.remaining,
        100 - 2 - 1,
        "only the two allowed attempts (and this probe) were charged to the shared scope"
    );
}

#[tokio::test]
async fn rehydration_is_idempotent_and_never_overwrites_live_state() {
    let now = 1_700_000_000_000i64;
    let (kv, _) = store(MemoryLimits::default());
    let first = rehydrate(&kv, &fixture(now), now).await.unwrap();
    assert_eq!(first.rows(), 3);
    let o = keys::offence("o", "ip1").unwrap();
    // a live process extended the ban and raised the offence count after the database row was written
    kv.zadd(keys::BANNED_IPS, (now + 99_000_000) as f64, "ip1", None)
        .await
        .unwrap();
    for _ in 0..3 {
        kv.offence_incr_with_decay(
            &o,
            Duration::from_secs(365 * 24 * 3600),
            Duration::from_secs(3600),
        )
        .await
        .unwrap();
    }
    let second = rehydrate(&kv, &fixture(now), now).await.unwrap();
    assert_eq!(second.rows(), 0, "{second:?}");
    assert_eq!(second.already_present, 3);
    let ban_score = kv
        .zrange_by_score(keys::BANNED_IPS, 0.0, f64::MAX, 10)
        .await
        .unwrap();
    assert_eq!(
        ban_score,
        vec![("ip1".to_owned(), (now + 99_000_000) as f64)],
        "the live score is kept"
    );
    assert_eq!(
        kv.offence_incr_with_decay(
            &o,
            Duration::from_secs(365 * 24 * 3600),
            Duration::from_secs(60)
        )
        .await
        .unwrap(),
        2 + 3 + 1,
        "2 rebuilt, 3 live, plus this one: nothing was added by the second call"
    );
}

#[tokio::test]
async fn parity_needs_two_different_backends() {
    use crate::parity::{Case, Observation, Outcome, ParityBackend, Suite, run};
    struct Same;
    impl ParityBackend for Same {
        fn name(&self) -> &str {
            "same"
        }
        fn run(&self, _c: &Case) -> Result<Observation, String> {
            Ok(Observation::default())
        }
    }
    let case = Case {
        id: "c".into(),
        suite: Suite::CoreSqli,
        input: String::new(),
    };
    assert!(matches!(
        run(&[case], Some(&Same), Some(&Same)),
        Outcome::Unverified(_)
    ));
}
