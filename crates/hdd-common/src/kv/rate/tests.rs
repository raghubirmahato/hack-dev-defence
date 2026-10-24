//! Worked examples of the three algorithms (the random-sequence comparison with independent models is in the conformance suite).
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    reason = "tests"
)]

use super::*;

const S: u64 = 1_000_000;

fn req(limit: u32, window_s: u64, algo: Algorithm) -> RateRequest {
    RateRequest::new(limit, Duration::from_secs(window_s), algo)
}

fn run(e: &mut RateEntry, now: u64, r: &RateRequest) -> RateDecision {
    e.check(now, r)
}

#[test]
fn exact_counts_the_last_window_and_an_entry_exactly_one_window_old_is_gone() {
    let r = req(3, 10, Algorithm::Exact);
    let mut e = RateEntry::new(Algorithm::Exact);
    let d = run(&mut e, 0, &r);
    assert_eq!((d.allowed, d.remaining), (true, 2));
    run(&mut e, 4 * S, &r);
    run(&mut e, 5 * S, &r);
    let d = run(&mut e, 9 * S, &r);
    assert_eq!((d.allowed, d.remaining, d.violations), (false, 0, 1));
    // the oldest entry (t = 0) expires at 10 s: a retry then succeeds, one microsecond earlier it does not
    assert_eq!(d.reset_ms, 1_000, "retry in 1 s");
    assert!(!run(&mut e, 10 * S - 1, &r).allowed);
    let d = run(&mut e, 10 * S, &r);
    assert!(d.allowed, "{d:?}");
}

#[test]
fn exact_with_cost_frees_enough_entries_before_allowing() {
    let r = req(4, 10, Algorithm::Exact);
    let mut e = RateEntry::new(Algorithm::Exact);
    for t in [0, 2 * S, 4 * S] {
        assert!(run(&mut e, t, &r).allowed);
    }
    let big = RateRequest { cost: 3, ..r };
    let d = run(&mut e, 5 * S, &big);
    assert!(!d.allowed);
    // cost 3 needs sum <= 1: both the t=0 and the t=2 entries must expire, so the wait is until 12 s
    assert_eq!(d.reset_ms, 7_000);
    assert!(run(&mut e, 12 * S, &big).allowed);
}

#[test]
fn gcra_allows_a_burst_of_limit_then_one_per_interval() {
    let r = req(10, 10, Algorithm::Gcra);
    let mut e = RateEntry::new(Algorithm::Gcra);
    for i in 0..10 {
        let d = run(&mut e, 0, &r);
        assert!(d.allowed, "burst unit {i}");
        assert_eq!(d.remaining, 9 - i);
    }
    let d = run(&mut e, 0, &r);
    assert!(!d.allowed);
    assert_eq!(d.reset_ms, 1_000, "one emission interval of 1 s");
    assert!(!run(&mut e, S - 1, &r).allowed);
    assert!(run(&mut e, S, &r).allowed);
    assert!(!run(&mut e, S, &r).allowed);
    // after a long pause the bucket is full again, no more than limit
    for _ in 0..10 {
        assert!(run(&mut e, 100 * S, &r).allowed);
    }
    assert!(!run(&mut e, 100 * S, &r).allowed);
}

#[test]
fn counter_uses_the_weighted_previous_window() {
    let r = req(10, 10, Algorithm::Counter);
    let mut e = RateEntry::new(Algorithm::Counter);
    // 10 requests early in window 0
    for _ in 0..10 {
        assert!(run(&mut e, S, &r).allowed);
    }
    assert!(!run(&mut e, 2 * S, &r).allowed);
    // at 15 s (halfway through window 1) the previous window still weighs 5/10 of its count: 10 * 0.5 = 5 used
    let d = run(&mut e, 15 * S, &r);
    assert!(d.allowed);
    assert_eq!(d.remaining, 4, "10 - 5 - 1");
    // four more fit, the fifth does not
    for _ in 0..4 {
        assert!(run(&mut e, 15 * S, &r).allowed);
    }
    assert!(!run(&mut e, 15 * S, &r).allowed);
    // two windows later everything is forgotten
    assert!(run(&mut e, 40 * S, &r).allowed);
}

#[test]
fn burst_of_one_hundred_against_sixty_per_ten_seconds() {
    // T-0333 A1 as a property of the algorithms: exactly 60 for the exact ones, within 5% for the counter
    for algo in [Algorithm::Exact, Algorithm::Gcra] {
        let r = req(60, 10, algo);
        let mut e = RateEntry::new(algo);
        let allowed = (0..100).filter(|_| run(&mut e, 0, &r).allowed).count();
        assert_eq!(allowed, 60, "{algo:?}");
    }
    let r = req(60, 10, Algorithm::Counter);
    let mut e = RateEntry::new(Algorithm::Counter);
    let allowed = (0..100).filter(|_| run(&mut e, 3 * S, &r).allowed).count();
    assert!((57..=63).contains(&allowed), "{allowed}");
}

#[test]
fn counter_retry_after_is_tight_in_the_three_cases() {
    // Case 1: the previous window still weighs enough that waiting inside the current window helps
    let r = req(10, 10, Algorithm::Counter);
    let mut e = RateEntry::new(Algorithm::Counter);
    for _ in 0..10 {
        run(&mut e, 9 * S, &r);
    }
    // at 10.0 s: window 1 offset 0, prev = 10, curr = 0 -> estimate 10, full; the previous weight falls by 1 per second
    let d = run(&mut e, 10 * S, &r);
    assert!(!d.allowed);
    assert_eq!(d.reset_ms, 1_000);
    let mut again = e.clone();
    assert!(!run(&mut again, 11 * S - 1, &r).allowed);
    let mut again = e.clone();
    assert!(run(&mut again, 11 * S, &r).allowed);

    // Case 2: limit equals cost, so only an empty previous and current window helps: two windows later at the latest
    let r1 = req(1, 10, Algorithm::Counter);
    let mut e = RateEntry::new(Algorithm::Counter);
    assert!(run(&mut e, 5 * S, &r1).allowed);
    let d = run(&mut e, 6 * S, &r1);
    assert!(!d.allowed);
    let wait = d.reset_ms * 1000;
    let mut again = e.clone();
    assert!(!run(&mut again, 6 * S + wait - 1000, &r1).allowed);
    let mut again = e.clone();
    assert!(run(&mut again, 6 * S + wait, &r1).allowed);
}

#[test]
fn violations_count_denials_and_reset_after_a_quiet_window() {
    let r = req(1, 10, Algorithm::Exact);
    let mut e = RateEntry::new(Algorithm::Exact);
    assert_eq!(run(&mut e, 0, &r).violations, 0);
    assert_eq!(run(&mut e, S, &r).violations, 1);
    assert_eq!(run(&mut e, 2 * S, &r).violations, 2);
    // a denial 9 s later is still within 10 s of the last denial
    assert_eq!(run(&mut e, 9 * S, &r).violations, 3);
    // quiet for a whole window: the first request after is allowed (the entry at 0 expired) and reports none
    let d = run(&mut e, 30 * S, &r);
    assert!(d.allowed);
    assert_eq!(d.violations, 0);
    assert_eq!(run(&mut e, 31 * S, &r).violations, 1);
}

#[test]
fn the_algorithm_name_and_the_keep_time_follow_the_state() {
    let r = req(2, 10, Algorithm::Gcra);
    let mut e = RateEntry::new(Algorithm::Gcra);
    run(&mut e, 0, &r);
    assert_eq!(e.algorithm(), Algorithm::Gcra);
    assert_eq!(
        e.keep_for_us(0, 10 * S),
        5 * S,
        "tat is one emission interval ahead"
    );
    let mut c = RateEntry::new(Algorithm::Counter);
    run(&mut c, 0, &req(2, 10, Algorithm::Counter));
    assert_eq!(c.keep_for_us(0, 10 * S), 20 * S);
    assert_eq!(Algorithm::Counter.name(), "counter");
    assert_eq!(Algorithm::Exact.name(), "exact");
    assert_eq!(Algorithm::Gcra.name(), "gcra");
}

#[test]
fn the_exact_log_never_grows_beyond_the_limit() {
    let r = req(5, 1, Algorithm::Exact);
    let mut e = RateEntry::new(Algorithm::Exact);
    for i in 0..10_000u64 {
        run(&mut e, i * 1000, &r);
        if let RateState::Exact { log, sum } = &e.state {
            assert!(log.len() <= 5 && *sum <= 5);
        }
    }
}

#[test]
fn lowering_a_limit_below_what_is_recorded_neither_panics_nor_underflows() {
    let mut e = RateEntry::new(Algorithm::Exact);
    let wide = req(5, 10, Algorithm::Exact);
    for _ in 0..5 {
        assert!(run(&mut e, 0, &wide).allowed);
    }
    let narrow = req(2, 10, Algorithm::Exact);
    let d = run(&mut e, S, &narrow);
    assert!(!d.allowed);
    assert_eq!(d.remaining, 0);
    assert!(d.reset_ms > 0);
}
