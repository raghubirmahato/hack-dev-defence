//! Tests added for the findings of the independent review of 2026-10-19.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    reason = "tests"
)]

use std::sync::Arc;
use std::time::Duration;

use super::*;
use crate::kv::clock::ManualClock;

#[test]
fn a_probe_that_never_reports_does_not_lock_the_breaker_forever() {
    let clock = Arc::new(ManualClock::new(0));
    let b = Breaker::new(1, Duration::from_secs(1), clock.clone());
    b.failure();
    clock.advance_ms(1000);
    assert!(b.allow(), "the probe starts");
    // its future is dropped: neither success() nor failure() is ever called
    assert!(!b.allow());
    clock.advance_ms(999);
    assert!(!b.allow());
    clock.advance_ms(1);
    assert!(b.allow(), "after another cooldown a new probe is allowed");
    b.success();
    assert!(!b.is_open());
}

#[test]
fn the_scripts_check_the_collection_cap_and_clamp_a_backwards_clock() {
    for s in [LUA_HSET, LUA_ZADD, LUA_SADD, LUA_FLOW] {
        assert!(s.contains("COLLECTIONFULL"));
    }
    assert!(LUA_OFFENCE.contains("if d < 0 then d = 0 end"));
    assert!(LUA_RATE.contains("math.max(limit - sum, 0)"));
    assert!(
        !LUA_RATE.contains("LRANGE', KEYS[2], 0, -1"),
        "the whole log is never fetched"
    );
}
