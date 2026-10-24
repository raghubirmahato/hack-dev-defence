//! T-0561 step 5: the parity harness compares exactly the fields of R-31 and never passes vacuously.
#![allow(clippy::expect_used, clippy::unwrap_used, reason = "tests")]

use super::*;

struct Fixed {
    name: &'static str,
    obs: Observation,
}

impl ParityBackend for Fixed {
    fn name(&self) -> &str {
        self.name
    }
    fn run(&self, _case: &Case) -> Result<Observation, String> {
        Ok(self.obs.clone())
    }
}

struct Failing;

impl ParityBackend for Failing {
    fn name(&self) -> &str {
        "failing"
    }
    fn run(&self, _case: &Case) -> Result<Observation, String> {
        Err("backend not ready".into())
    }
}

fn blocked() -> Observation {
    Observation {
        decision: Decision {
            action: "would_block".into(),
            category: "sqli".into(),
            subtype: "tautology".into(),
            rule_id: "SQLI-001".into(),
            hardness: "hard".into(),
            score: 90,
            threshold: 60,
            vector: "query".into(),
            field: "id".into(),
            evidence: "' OR '1'='1".into(),
        },
        ban: Some(BanIntent {
            reason: "sqli_hard".into(),
            scope: "site".into(),
            ttl_step: 1,
        }),
        identity_key: "ip:203.0.113.9".into(),
        enforcement_backend: "nftables".into(),
        config_revision: 7,
        at_unix_ms: 1_000,
    }
}

fn case(id: &str) -> Case {
    Case {
        id: id.into(),
        suite: Suite::CoreSqli,
        input: "GET /?id=1' OR '1'='1".into(),
    }
}

#[test]
fn identical_decisions_with_different_excluded_fields_are_zero_differences() {
    let a = blocked();
    let mut b = blocked();
    b.identity_key = "lo:ua:Mozilla".into();
    b.enforcement_backend = "noop".into();
    b.config_revision = 99;
    b.at_unix_ms = 5_000_000;
    assert!(diff("m1", &a, &b).is_empty());
}

#[test]
fn every_compared_field_is_detected() {
    type Mutation = (&'static str, fn(&mut Observation));
    let mutations: [Mutation; 13] = [
        ("decision.action", |o| o.decision.action = "allow".into()),
        ("decision.category", |o| o.decision.category = "xss".into()),
        ("decision.subtype", |o| o.decision.subtype = "union".into()),
        ("decision.rule_id", |o| {
            o.decision.rule_id = "SQLI-002".into()
        }),
        ("decision.hardness", |o| o.decision.hardness = "soft".into()),
        ("decision.score", |o| o.decision.score = 91),
        ("decision.threshold", |o| o.decision.threshold = 61),
        ("decision.vector", |o| o.decision.vector = "body".into()),
        ("decision.field", |o| o.decision.field = "q".into()),
        ("decision.evidence", |o| {
            o.decision.evidence = "other".into()
        }),
        ("ban.reason", |o| {
            o.ban.as_mut().expect("ban").reason = "x".into();
        }),
        ("ban.scope", |o| {
            o.ban.as_mut().expect("ban").scope = "global".into();
        }),
        ("ban.ttl_step", |o| {
            o.ban.as_mut().expect("ban").ttl_step = 2;
        }),
    ];
    for (field, mutate) in mutations {
        let mut b = blocked();
        mutate(&mut b);
        let d = diff("m1", &blocked(), &b);
        assert_eq!(d.len(), 1, "{field}: {d:?}");
        assert_eq!(d.first().map(|x| x.field), Some(field));
    }
}

#[test]
fn a_ban_on_one_side_only_is_a_difference() {
    let mut b = blocked();
    b.ban = None;
    let d = diff("m1", &blocked(), &b);
    assert_eq!(d.len(), 1);
    assert_eq!(d.first().map(|x| x.field), Some("ban"));
    assert!(d.first().is_some_and(|x| x.right == "no ban"));
    assert!(diff("m1", &b, &b).is_empty());
}

#[test]
fn a_run_with_matching_backends_is_clean_and_counts_the_cases() {
    let a = Fixed {
        name: "local",
        obs: blocked(),
    };
    let mut other = blocked();
    other.enforcement_backend = "noop".into();
    let b = Fixed {
        name: "hosted",
        obs: other,
    };
    let cases = [case("m1"), case("m2")];
    match run(&cases, Some(&a), Some(&b)) {
        Outcome::Compared(r) => {
            assert!(r.is_clean());
            assert_eq!(r.compared, 2);
        }
        other => panic!("{other:?}"),
    }
}

#[test]
fn a_run_reports_differences_per_case() {
    let a = Fixed {
        name: "local",
        obs: blocked(),
    };
    let mut changed = blocked();
    changed.decision.score = 10;
    let b = Fixed {
        name: "hosted",
        obs: changed,
    };
    match run(&[case("m1")], Some(&a), Some(&b)) {
        Outcome::Compared(r) => {
            assert!(!r.is_clean());
            assert_eq!(r.differences.len(), 1);
            assert!(
                r.differences
                    .first()
                    .unwrap()
                    .to_string()
                    .starts_with("m1: decision.score")
            );
        }
        other => panic!("{other:?}"),
    }
}

#[test]
fn a_backend_error_is_an_error_not_a_pass() {
    let a = Fixed {
        name: "local",
        obs: blocked(),
    };
    match run(&[case("m1")], Some(&a), Some(&Failing)) {
        Outcome::Compared(r) => {
            assert!(!r.is_clean());
            assert_eq!(r.compared, 0);
            assert_eq!(r.errors.len(), 1);
        }
        other => panic!("{other:?}"),
    }
}

#[test]
fn nothing_to_compare_is_unverified_never_clean() {
    let a = Fixed {
        name: "local",
        obs: blocked(),
    };
    assert!(matches!(
        run(&[case("m1")], Some(&a), None),
        Outcome::Unverified(_)
    ));
    assert!(matches!(
        run(&[case("m1")], None, None),
        Outcome::Unverified(_)
    ));
    assert!(matches!(
        run(&[], Some(&a), Some(&a)),
        Outcome::Unverified(_)
    ));
}
