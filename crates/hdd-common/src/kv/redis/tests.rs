//! The parts of the Redis backend that need no server: connection policy, circuit breaker, wire format, script table.
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
fn only_tls_urls_with_a_password_are_accepted() {
    assert!(RedisConfig::new("rediss://:s3cret@redis.example:6380/0").is_ok());
    assert!(RedisConfig::new("rediss://hdd:s3cret@redis.example").is_ok()); // hdd-secret-scan:allow (test vector)
    for bad in [
        "redis://:s3cret@redis.example",
        "rediss://redis.example",
        "rediss://hdd@redis.example",
        "rediss://hdd:@redis.example",
        "rediss://:@redis.example",
        "http://:pw@redis.example",
        "redis.example:6379",
        "rediss://:pw@",
        "",
    ] {
        assert!(RedisConfig::new(bad).is_err(), "{bad}");
    }
}

#[test]
fn the_error_and_debug_output_never_contain_the_url() {
    let err = RedisConfig::new("redis://:topsecretpw@redis.example").unwrap_err();
    assert!(!err.to_string().contains("topsecretpw") && !err.to_string().contains("redis.example"));
    let cfg = RedisConfig::new("rediss://:topsecretpw@redis.example").unwrap();
    assert!(!format!("{cfg:?}").contains("topsecretpw"));
}

#[test]
fn plain_connections_are_for_loopback_tests_only() {
    assert!(RedisConfig::insecure_loopback_for_tests("redis://127.0.0.1:6379").is_ok());
    assert!(RedisConfig::insecure_loopback_for_tests("redis://localhost").is_ok());
    assert!(RedisConfig::insecure_loopback_for_tests("redis://[::1]:6379/2").is_ok());
    for bad in [
        "redis://10.0.0.5:6379",
        "redis://redis.example",
        "redis://127.0.0.1.evil.example",
        "redis://x@evil.example/127.0.0.1",
    ] {
        assert!(
            RedisConfig::insecure_loopback_for_tests(bad).is_err(),
            "{bad}"
        );
    }
    assert!(
        RedisConfig::insecure_loopback_for_tests("redis://127.0.0.1")
            .unwrap()
            .is_insecure_loopback()
    );
    assert!(
        !RedisConfig::new("rediss://:pw@h.example")
            .unwrap()
            .is_insecure_loopback()
    );
}

#[test]
fn the_breaker_opens_after_the_threshold_probes_once_and_closes_on_success() {
    let clock = Arc::new(ManualClock::new(0));
    let b = Breaker::new(3, Duration::from_secs(1), clock.clone());
    assert!(b.allow());
    b.failure();
    b.failure();
    assert!(
        b.allow() && !b.is_open(),
        "two failures are below the threshold"
    );
    b.success();
    b.failure();
    b.failure();
    assert!(!b.is_open(), "a success resets the count");
    b.failure();
    assert!(
        b.is_open() && !b.allow(),
        "three consecutive failures open it"
    );
    clock.advance_ms(999);
    assert!(!b.allow());
    clock.advance_ms(1);
    assert!(
        b.allow(),
        "the first caller after the cooldown is the probe"
    );
    assert!(
        !b.allow(),
        "nobody else passes while the probe is in flight"
    );
    b.failure();
    assert!(!b.allow(), "a failed probe reopens it");
    clock.advance_ms(1000);
    assert!(b.allow());
    b.success();
    assert!(!b.is_open() && b.allow() && b.allow());
}

#[test]
fn the_wire_format_is_revision_colon_payload() {
    assert_eq!(parse_wire(b"7:hello"), Some((7, b"hello".to_vec())));
    assert_eq!(parse_wire(b"7:"), Some((7, Vec::new())));
    assert_eq!(parse_wire(b"12:a:b:c"), Some((12, b"a:b:c".to_vec())));
    assert_eq!(parse_wire(b"7:\x00\xff"), Some((7, vec![0, 255])));
    for bad in [&b"nocolon"[..], b":x", b"-1:x", b"x:1", b""] {
        assert_eq!(parse_wire(bad), None, "{bad:?}");
    }
}

#[test]
fn every_script_id_has_a_script_and_the_table_has_no_duplicates() {
    assert_eq!(Sc::Publish as usize + 1, SCRIPTS.len());
    let mut seen = std::collections::BTreeSet::new();
    for (i, s) in SCRIPTS.iter().enumerate() {
        assert!(!s.trim().is_empty(), "script {i} is empty");
        assert!(seen.insert(*s), "script {i} duplicates another");
    }
}

#[test]
fn scripts_format_timestamps_without_exponents_and_do_no_unsafe_division() {
    // Lua 5.1 prints numbers with %.14g: every stored timestamp must go through string.format('%.0f')
    for (name, s) in [("rate", LUA_RATE), ("offence", LUA_OFFENCE)] {
        assert!(s.contains("string.format('%.0f'"), "{name}");
    }
    // no plain `/` between possibly non-divisible integers outside idiv and the explicit exact forms
    assert!(
        !LUA_RATE.contains("math.floor("),
        "floor of a double quotient can be off by one near integers"
    );
    assert!(LUA_RATE.contains("math.fmod"));
}

#[test]
fn replies_are_converted_without_panics() {
    assert_eq!(reply_bytes(&Value::Nil), None);
    assert_eq!(
        reply_bytes(&Value::BulkString(b"abc".to_vec())),
        Some(b"abc".to_vec())
    );
    assert!(reply_i64(&Value::Nil).is_err());
    assert_eq!(reply_i64(&Value::Int(5)).unwrap(), 5);
    let bulk = |s: &str| Value::BulkString(s.as_bytes().to_vec());
    let pairs = reply_pairs(Value::Array(vec![
        bulk("a"),
        bulk("1"),
        bulk("b"),
        bulk("2"),
    ]))
    .unwrap();
    assert_eq!(
        pairs,
        vec![
            ("a".to_owned(), b"1".to_vec()),
            ("b".to_owned(), b"2".to_vec())
        ]
    );
    assert!(
        reply_pairs(Value::Array(vec![bulk("odd")]))
            .unwrap()
            .is_empty()
    );
    assert!(reply_array(Value::Nil).is_empty());
}

#[test]
fn the_subscriber_connection_asks_for_resp3() {
    assert_eq!(
        resp3_url("rediss://:pw@h:6380/0"),
        "rediss://:pw@h:6380/0?protocol=resp3"
    );
    assert_eq!(
        resp3_url("rediss://:pw@h/0?x=1"),
        "rediss://:pw@h/0?x=1&protocol=resp3"
    );
    assert_eq!(
        resp3_url("rediss://:pw@h/0?protocol=resp3"),
        "rediss://:pw@h/0?protocol=resp3"
    );
}
