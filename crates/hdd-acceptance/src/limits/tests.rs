//! Limiter tests: the functional profile is measured (not assumed) to allow at most 20 requests in any 1000 ms window for a
//! half-open 5-minute duration, the other profiles enforce their ladder ceilings, a check cannot raise a hard ceiling, and the
//! shared/own budget combination refuses without consuming (A2, A-2, A-10).

use std::collections::{BTreeMap, VecDeque};
use std::sync::Arc;

use hdd_common::kv::clock::ManualClock;

use super::*;

fn limiter(profile: LoadProfile, clock: &Arc<ManualClock>) -> Limiter {
    Limiter::new(profile, clock.clone())
}

fn manual() -> Arc<ManualClock> {
    Arc::new(ManualClock::new(0))
}

fn budget(shared: Limiter, own: LoadProfile, clock: &Arc<ManualClock>) -> RateBudget {
    RateBudget::new(
        Arc::new(Mutex::new(shared)),
        Limiter::new(own, clock.clone()),
    )
}

#[test]
fn the_five_profiles_are_the_spec_set_and_parse_as_whole_tokens() {
    assert_eq!(LoadProfile::ALL.len(), 5);
    let names: Vec<&str> = LoadProfile::ALL.iter().map(|p| p.as_str()).collect();
    assert_eq!(
        names,
        vec!["functional", "burst", "protocol-abuse", "load", "lab"]
    );
    for profile in LoadProfile::ALL {
        assert_eq!(LoadProfile::parse(profile.as_str()), Some(profile));
        assert_eq!(profile.to_string(), profile.as_str());
    }
    for bad in [
        "",
        "FUNCTIONAL",
        "full",
        "load-run",
        "lab-full",
        "protocol abuse",
    ] {
        assert_eq!(LoadProfile::parse(bad), None, "{bad:?}");
    }
    assert!(LoadProfile::Load.requires_written_approval());
    for other in [
        LoadProfile::Functional,
        LoadProfile::Burst,
        LoadProfile::ProtocolAbuse,
        LoadProfile::Lab,
    ] {
        assert!(!other.requires_written_approval());
    }
}

#[test]
fn a_profile_rank_decides_whether_a_check_may_use_it() {
    assert_eq!(LoadProfile::Functional.rank(), 0);
    assert_eq!(LoadProfile::Load.rank(), 4);
    for (check, run, exceeds) in [
        (LoadProfile::Functional, LoadProfile::Lab, false),
        (LoadProfile::Lab, LoadProfile::Functional, true),
        (LoadProfile::Burst, LoadProfile::ProtocolAbuse, false),
        (LoadProfile::Load, LoadProfile::Load, false),
    ] {
        assert_eq!(check.exceeds(run), exceeds, "{check} vs {run}");
    }
}

#[test]
fn a10_the_functional_window_allows_at_most_twenty_requests_in_any_one_second() {
    let clock = manual();
    let mut limiter = limiter(LoadProfile::Functional, &clock);
    for _ in 0..20 {
        assert_eq!(limiter.acquire(Lane::Http, 1), Ok(()));
    }
    assert_eq!(
        limiter.acquire(Lane::Http, 1),
        Err(LimitDenial::RateExceeded {
            lane: Lane::Http,
            retry_after_ms: 1_001
        }),
        "the 21st request in the same instant is over 20 in a closed one-second window (review item S-9)"
    );
    // non-aligned instants inside the first window: still refused
    clock.advance_us(500_000);
    assert!(matches!(
        limiter.acquire(Lane::Http, 1),
        Err(LimitDenial::RateExceeded { .. })
    ));
    clock.advance_us(499_000);
    assert!(matches!(
        limiter.acquire(Lane::Http, 1),
        Err(LimitDenial::RateExceeded { .. })
    ));
    // The window is closed (review item S-9): at exactly one second the first grants are still counted; they leave one
    // microsecond later, so a fresh 20 is allowed at 1.000001 s.
    clock.advance_us(1_001);
    for _ in 0..20 {
        assert_eq!(limiter.acquire(Lane::Http, 1), Ok(()));
    }
    assert!(matches!(
        limiter.acquire(Lane::Http, 1),
        Err(LimitDenial::RateExceeded { .. })
    ));
}

#[test]
fn a10_a_burst_cannot_double_the_rate_inside_one_second() {
    // The defect the review found: capacity 20 plus a refill rate let 20 pass at t=0 and 20 more by t=1 s (40 in a second).
    let clock = manual();
    let mut limiter = limiter(LoadProfile::Functional, &clock);
    for _ in 0..20 {
        assert_eq!(limiter.acquire(Lane::Http, 1), Ok(()));
    }
    let mut extra = 0;
    for _ in 0..499 {
        clock.advance_ms(2);
        if limiter.acquire(Lane::Http, 1).is_ok() {
            extra += 1;
        }
    }
    assert_eq!(
        extra, 0,
        "no extra request may pass before the one-second window has elapsed"
    );
}

#[test]
fn a10_the_duration_cap_is_half_open_at_exactly_three_hundred_seconds() {
    let clock = manual();
    let mut limiter = limiter(LoadProfile::Functional, &clock);
    assert_eq!(limiter.acquire(Lane::Http, 1), Ok(()));
    clock.advance_us(299_999_999);
    assert_eq!(limiter.acquire(Lane::Http, 1), Ok(()), "still inside 300 s");
    clock.advance_us(1);
    assert_eq!(
        limiter.acquire(Lane::Http, 1),
        Err(LimitDenial::DurationExceeded {
            lane: Lane::Http,
            limit_s: 300
        }),
        "at exactly the duration boundary the request is refused (half-open)"
    );
}

#[test]
fn a2_the_measured_run_holds_twenty_per_second_for_all_three_hundred_seconds() {
    let clock = manual();
    let mut limiter = limiter(LoadProfile::Functional, &clock);
    let mut granted = 0u64;
    for second in 0..300u64 {
        if second > 0 {
            // Closed window (review item S-9): 1001 ms per second so the previous second's grants are all older than the
            // 1000 ms window.
            clock.advance_ms(1_001);
        }
        let mut in_this_second = 0u64;
        while limiter.acquire(Lane::Http, 1).is_ok() {
            in_this_second += 1;
            granted += 1;
            assert!(
                in_this_second <= 20,
                "more than 20 requests in second {second}"
            );
        }
        assert_eq!(in_this_second, 20, "second {second}");
    }
    assert_eq!(granted, 6_000, "20 req/s for 300 s");
    clock.advance_ms(701); // 299 * 1001 ms + 701 ms = exactly 300 s
    assert_eq!(
        limiter.acquire(Lane::Http, 1),
        Err(LimitDenial::DurationExceeded {
            lane: Lane::Http,
            limit_s: 300
        })
    );
}

#[test]
fn a_refused_request_does_not_consume_the_window_it_was_refused_from() {
    let clock = manual();
    let mut limiter = limiter(LoadProfile::Functional, &clock);
    for _ in 0..20 {
        assert_eq!(limiter.acquire(Lane::Http, 1), Ok(()));
    }
    for _ in 0..5 {
        assert!(matches!(
            limiter.acquire(Lane::Http, 1),
            Err(LimitDenial::RateExceeded { .. })
        ));
    }
    clock.advance_ms(1_001); // the closed window keeps the grants for exactly 1000 ms (review item S-9)
    let mut granted = 0;
    while limiter.acquire(Lane::Http, 1).is_ok() {
        granted += 1;
    }
    assert_eq!(granted, 20, "only the refused window's grants are consumed");
}

#[test]
fn a_check_cannot_raise_the_functional_ceiling_but_may_lower_it() {
    for asked in [
        RequestedCaps::http(21, 20, 300),
        RequestedCaps::http(20, 21, 300),
        RequestedCaps::http(20, 20, 301),
    ] {
        assert!(
            matches!(
                Limiter::with_requested(LoadProfile::Functional, &asked, manual()),
                Err(LimitDenial::AboveCeiling {
                    lane: Lane::Http,
                    ..
                })
            ),
            "{asked:?}"
        );
    }
    let lower = RequestedCaps::http(5, 5, 60);
    let clock = manual();
    let mut limiter = Limiter::with_requested(LoadProfile::Functional, &lower, clock.clone())
        .expect("lower caps");
    assert_eq!(limiter.profile(), LoadProfile::Functional);
    for _ in 0..5 {
        assert_eq!(limiter.acquire(Lane::Http, 1), Ok(()));
    }
    assert!(matches!(
        limiter.acquire(Lane::Http, 1),
        Err(LimitDenial::RateExceeded { .. })
    ));
    clock.advance_ms(60_000);
    assert_eq!(
        limiter.acquire(Lane::Http, 1),
        Err(LimitDenial::DurationExceeded {
            lane: Lane::Http,
            limit_s: 60
        })
    );
}

#[test]
fn a_window_refund_gives_the_grant_back() {
    let clock = manual();
    let mut limiter = limiter(LoadProfile::Functional, &clock);
    for _ in 0..20 {
        assert_eq!(limiter.acquire(Lane::Http, 1), Ok(()));
    }
    assert!(matches!(
        limiter.acquire(Lane::Http, 1),
        Err(LimitDenial::RateExceeded { .. })
    ));
    limiter.refund(Lane::Http, 1);
    assert_eq!(
        limiter.acquire(Lane::Http, 1),
        Ok(()),
        "the refunded grant can be spent again"
    );
    assert!(matches!(
        limiter.acquire(Lane::Http, 1),
        Err(LimitDenial::RateExceeded { .. })
    ));
}

#[test]
fn one_limiter_is_shared_by_every_check_of_the_run() {
    let clock = manual();
    let mut shared = limiter(LoadProfile::Functional, &clock);
    for _ in 0..10 {
        assert_eq!(shared.acquire(Lane::Http, 1), Ok(()));
    }
    for _ in 0..10 {
        assert_eq!(shared.acquire(Lane::Http, 1), Ok(()));
    }
    assert!(matches!(
        shared.acquire(Lane::Http, 1),
        Err(LimitDenial::RateExceeded { .. })
    ));
}

#[test]
fn a2_the_shared_and_the_check_budget_are_both_enforced_and_a_shared_refusal_refunds_the_check() {
    let clock = manual();
    // shared total 20 (burst) and the check rate 20: both allow exactly 20.
    let mut requested = RequestedCaps::default();
    requested.totals.insert(Lane::Http, 20);
    let shared = Limiter::with_requested(LoadProfile::Burst, &requested, clock.clone())
        .expect("shared total");
    let mut budget = budget(shared, LoadProfile::Functional, &clock);
    for _ in 0..20 {
        assert_eq!(budget.acquire(Lane::Http, 1), Ok(()));
    }
    assert_eq!(budget.own_window_len(), 20);
    // a new second (past the closed window): the check window is clear but the shared total is used up; the check grant is
    // refunded.
    clock.advance_ms(1_001);
    assert_eq!(
        budget.acquire(Lane::Http, 1),
        Err(LimitDenial::TotalExceeded {
            lane: Lane::Http,
            ceiling: 20
        })
    );
    assert_eq!(
        budget.own_window_len(),
        0,
        "a shared-limiter refusal must refund the check-level grant"
    );
}

#[test]
fn a2_the_check_level_ceiling_binds_below_the_shared_one() {
    let clock = manual();
    let mut budget = budget(
        limiter(LoadProfile::Lab, &clock),
        LoadProfile::Functional,
        &clock,
    );
    for _ in 0..20 {
        assert_eq!(budget.acquire(Lane::Http, 1), Ok(()));
    }
    assert!(matches!(
        budget.acquire(Lane::Http, 1),
        Err(LimitDenial::RateExceeded { .. })
    ));
}

#[test]
fn the_burst_profile_caps_one_hundred_http_requests_and_five_hundred_dns_queries() {
    let clock = manual();
    let mut limiter = limiter(LoadProfile::Burst, &clock);
    for _ in 0..100 {
        assert_eq!(limiter.acquire(Lane::Http, 1), Ok(()));
    }
    assert_eq!(
        limiter.acquire(Lane::Http, 1),
        Err(LimitDenial::TotalExceeded {
            lane: Lane::Http,
            ceiling: 100
        })
    );
    for _ in 0..500 {
        assert_eq!(limiter.acquire(Lane::Dns, 1), Ok(()));
    }
    assert_eq!(
        limiter.acquire(Lane::Dns, 1),
        Err(LimitDenial::TotalExceeded {
            lane: Lane::Dns,
            ceiling: 500
        })
    );
    clock.advance_ms(60_000);
    assert!(matches!(
        limiter.acquire(Lane::Http, 1),
        Err(LimitDenial::TotalExceeded { .. })
    ));
}

#[test]
fn the_protocol_abuse_profile_caps_connections_frames_and_bytes() {
    let clock = manual();
    let mut limiter = limiter(LoadProfile::ProtocolAbuse, &clock);
    for _ in 0..5 {
        assert_eq!(limiter.acquire(Lane::Connections, 1), Ok(()));
    }
    assert_eq!(
        limiter.acquire(Lane::Connections, 1),
        Err(LimitDenial::TotalExceeded {
            lane: Lane::Connections,
            ceiling: 5
        })
    );
    for _ in 0..2_000 {
        assert_eq!(limiter.acquire(Lane::Frames, 1), Ok(()));
    }
    assert_eq!(
        limiter.acquire(Lane::Frames, 1),
        Err(LimitDenial::TotalExceeded {
            lane: Lane::Frames,
            ceiling: 2_000
        })
    );
    assert_eq!(limiter.acquire(Lane::Bytes, 10 * MIB), Ok(()));
    assert_eq!(
        limiter.acquire(Lane::Bytes, 1),
        Err(LimitDenial::TotalExceeded {
            lane: Lane::Bytes,
            ceiling: 10 * MIB
        })
    );
    assert_eq!(
        limiter.acquire(Lane::Http, 1),
        Err(LimitDenial::LaneNotInProfile { lane: Lane::Http })
    );
}

#[test]
fn the_lab_and_load_ceilings_are_five_hundred_and_one_hundred_per_second() {
    assert_eq!(
        LoadProfile::Lab.hard_caps().http,
        Some(HttpLane {
            rate_per_s: 500,
            burst: 500,
            duration_s: 600
        })
    );
    assert_eq!(
        LoadProfile::Load.hard_caps().http,
        Some(HttpLane {
            rate_per_s: 100,
            burst: 100,
            duration_s: 600
        })
    );
    let clock = manual();
    let mut lab = limiter(LoadProfile::Lab, &clock);
    for _ in 0..500 {
        assert_eq!(lab.acquire(Lane::Http, 1), Ok(()));
    }
    assert_eq!(
        lab.acquire(Lane::Http, 1),
        Err(LimitDenial::RateExceeded {
            lane: Lane::Http,
            retry_after_ms: 1_001
        })
    );
    clock.advance_ms(1_001);
    for _ in 0..500 {
        assert_eq!(lab.acquire(Lane::Http, 1), Ok(()));
    }
    assert!(matches!(
        lab.acquire(Lane::Http, 1),
        Err(LimitDenial::RateExceeded { .. })
    ));
    clock.advance_ms(599_000);
    assert_eq!(
        lab.acquire(Lane::Http, 1),
        Err(LimitDenial::DurationExceeded {
            lane: Lane::Http,
            limit_s: 600
        })
    );
}

#[test]
fn the_denial_messages_name_the_lane_and_the_ceiling() {
    let denial = LimitDenial::RateExceeded {
        lane: Lane::Http,
        retry_after_ms: 1_000,
    };
    assert!(denial.to_string().contains("http"));
    assert!(denial.to_string().contains("sliding-window"));
    assert_eq!(denial.lane(), Lane::Http);
    let above = LimitDenial::AboveCeiling {
        lane: Lane::Http,
        requested: 40,
        ceiling: 20,
    };
    assert!(above.to_string().contains("cannot raise"));
    let duration = LimitDenial::DurationExceeded {
        lane: Lane::Http,
        limit_s: 300,
    };
    assert!(duration.to_string().contains("half-open"));
    assert_eq!(Lane::ALL.len(), 5);
    for lane in Lane::ALL {
        assert_eq!(lane.to_string(), lane.as_str());
    }
}

/// Review items R-10 and S-9: expired grants are popped from the front, so a 300k-grant lab run stays cheap and bounded. The
/// window is one second at 500 req/s, so the deque never holds more than 500 grants however long the run is.
///
/// The limiter is built white-box without the profile duration on purpose: under the **closed** one-second window
/// (review item S-9) 300,000 grants at the lab rate need slightly more than 600 s of virtual time, which the lab profile's
/// 600 s duration cap would refuse. The purge/cost behaviour is what this test measures.
#[test]
fn r10_the_limiter_pops_expired_grants_and_300k_lab_grants_finish_quickly() {
    use hdd_common::kv::clock::Clock;
    let clock = manual();
    let mut lanes = BTreeMap::new();
    lanes.insert(
        Lane::Http,
        Bucket {
            kind: Kind::Rate {
                rate_per_s: 500,
                grants: VecDeque::new(),
                duration_us: None,
                first_us: None,
            },
        },
    );
    let mut limiter = Limiter {
        clock: clock.clone(),
        caps: LoadProfile::Lab.hard_caps(),
        lanes,
    };
    let started = std::time::Instant::now();
    // 600 batches of 500 grants at the same instant, then 1.001 ms past the closed window.
    for _ in 0..600u32 {
        for _ in 0..500u32 {
            assert_eq!(limiter.acquire(Lane::Http, 1), Ok(()));
        }
        clock.advance_us(1_000_001); // one microsecond past the closed one-second window
    }
    let elapsed = started.elapsed();
    assert!(
        elapsed < std::time::Duration::from_secs(5),
        "300k lab grants took {elapsed:?}"
    );
    let retained = match limiter.lanes.get(&Lane::Http).map(|bucket| &bucket.kind) {
        Some(Kind::Rate { grants, .. }) => grants.len(),
        _ => usize::MAX,
    };
    assert!(
        retained <= 500,
        "the limiter retains {retained} grants; expired grants were not popped from the front"
    );
    assert_eq!(clock.now_us(), 600 * 1_000_001, "600 batches of 1.000001 s");
}

// ---------------------------------------------------------------------------------------------------------------
// Round-3 review item S-9.
// ---------------------------------------------------------------------------------------------------------------

/// Review item S-9: a refund does not reset the check's duration clock, so an idle second cannot restart it.
#[test]
fn s9_a_refund_does_not_restart_the_duration_clock() {
    use hdd_common::kv::clock::Clock;
    let clock = manual();
    let lower = RequestedCaps::http(5, 5, 60);
    let mut limiter = Limiter::with_requested(LoadProfile::Functional, &lower, clock.clone())
        .expect("lower caps");
    assert_eq!(limiter.acquire(Lane::Http, 1), Ok(()));
    clock.advance_us(1_001_000); // the closed window has no grants left
    limiter
        .lanes
        .get_mut(&Lane::Http)
        .expect("http lane")
        .purge(clock.now_us());
    limiter.refund(Lane::Http, 1);
    // The duration window still started at t=0. At exactly 60 s the profile is over, half-open.
    clock.advance_us(60_000_000 - clock.now_us());
    assert_eq!(
        limiter.acquire(Lane::Http, 1),
        Err(LimitDenial::DurationExceeded {
            lane: Lane::Http,
            limit_s: 60
        }),
        "a refund must not restart the duration clock (review item S-9)"
    );
}

/// Review item S-9: the window is closed, so no 1000 ms interval contains two full allowances.
#[test]
fn s9_a_closed_one_second_window_cannot_contain_two_allowances() {
    let clock = manual();
    let mut limiter = limiter(LoadProfile::Functional, &clock);
    for _ in 0..20 {
        assert_eq!(limiter.acquire(Lane::Http, 1), Ok(()));
    }
    clock.advance_us(999_000);
    assert!(
        matches!(
            limiter.acquire(Lane::Http, 1),
            Err(LimitDenial::RateExceeded { .. })
        ),
        "at 999 ms the first grants are still counted (closed interval, review item S-9)"
    );
    clock.advance_us(1_000);
    assert!(
        matches!(
            limiter.acquire(Lane::Http, 1),
            Err(LimitDenial::RateExceeded { .. })
        ),
        "at exactly 1000 ms the first grants are still counted (closed interval, review item S-9)"
    );
    clock.advance_us(1);
    for _ in 0..20 {
        assert_eq!(limiter.acquire(Lane::Http, 1), Ok(()));
    }
}

/// Review item S-9: a check cannot ask for a zero rate on a profile rate lane (that would remove the rate limit).
#[test]
fn s9_a_check_cannot_turn_a_rate_lane_into_a_total_bucket() {
    let zero = RequestedCaps::http(0, 20, 60);
    assert_eq!(
        Limiter::with_requested(LoadProfile::Functional, &zero, manual()).err(),
        Some(LimitDenial::ZeroRateOnRateLane { lane: Lane::Http })
    );
    // The `burst` profile's own HTTP lane is a total bucket already, so the same request shape is allowed there.
    assert!(
        Limiter::with_requested(
            LoadProfile::Burst,
            &RequestedCaps::http(0, 100, 60),
            manual()
        )
        .is_ok()
    );
}
