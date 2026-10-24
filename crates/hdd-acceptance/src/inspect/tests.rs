//! Inspect-gate tests (A5): a false `would_block`, a changed `config_revision`, a transport failure, the mode/safe-mode
//! evidence and the happy path — all with a scripted client, no socket.

use std::collections::VecDeque;
use std::sync::{Arc, Mutex};

use super::*;
use crate::guard::PayloadClass;

struct Scripted {
    answers: VecDeque<Result<InspectResponse, InspectClientError>>,
    calls: Arc<Mutex<Vec<InspectRequest>>>,
}

impl Scripted {
    fn new(answers: Vec<Result<InspectResponse, InspectClientError>>) -> Scripted {
        Scripted {
            answers: answers.into_iter().collect(),
            calls: Arc::new(Mutex::new(Vec::new())),
        }
    }

    fn calls(&self) -> Arc<Mutex<Vec<InspectRequest>>> {
        Arc::clone(&self.calls)
    }
}

impl InspectClient for Scripted {
    fn inspect(&mut self, request: &InspectRequest) -> Result<InspectResponse, InspectClientError> {
        match self.calls.lock() {
            Ok(mut calls) => calls.push(request.clone()),
            Err(poisoned) => poisoned.into_inner().push(request.clone()),
        }
        self.answers
            .pop_front()
            .unwrap_or(Err(InspectClientError::Transport {
                message: "the scripted client ran out of answers".to_owned(),
            }))
    }
}

fn call_count(calls: &Arc<Mutex<Vec<InspectRequest>>>) -> usize {
    match calls.lock() {
        Ok(calls) => calls.len(),
        Err(poisoned) => poisoned.into_inner().len(),
    }
}

fn request() -> InspectRequest {
    InspectRequest::for_attempt(
        "shop-site.org",
        "/?id=1' OR '1'='1",
        Method::Get,
        Method::Get.as_str(),
        PayloadClass::A,
        &[],
        b"",
    )
}

fn answer(would_block: bool, revision: &str) -> Result<InspectResponse, InspectClientError> {
    Ok(InspectResponse {
        would_block,
        config_revision: revision.to_owned(),
        mode: SiteMode::Block,
        safe_mode: false,
        category: Some("sqli".to_owned()),
    })
}

#[test]
fn a5_a_false_would_block_fails_the_gate_without_a_ticket() {
    let scripted = Scripted::new(vec![answer(false, "rev-7")]);
    let calls = scripted.calls();
    let mut gate = InspectGate::new(scripted, "rev-7");
    let error = gate.check(&request()).expect_err("must refuse");
    assert_eq!(
        error,
        InspectGateError::WouldNotBlock {
            site: "shop-site.org".to_owned(),
            category: Some("sqli".to_owned())
        }
    );
    assert!(error.to_string().contains("would_block=false"), "{error}");
    assert_eq!(
        call_count(&calls),
        1,
        "only the inspect call itself is made"
    );
}

#[test]
fn a5_a_changed_config_revision_fails_the_gate() {
    let scripted = Scripted::new(vec![answer(true, "rev-8")]);
    let mut gate = InspectGate::new(scripted, "rev-7");
    let error = gate.check(&request()).expect_err("must refuse");
    assert_eq!(
        error,
        InspectGateError::ConfigRevisionChanged {
            expected: "rev-7".to_owned(),
            observed: "rev-8".to_owned()
        }
    );
}

#[test]
fn a_transport_failure_fails_closed() {
    let scripted = Scripted::new(vec![Err(InspectClientError::Transport {
        message: "connection refused".to_owned(),
    })]);
    let mut gate = InspectGate::new(scripted, "rev-7");
    let error = gate.check(&request()).expect_err("must refuse");
    assert!(
        matches!(error, InspectGateError::Transport { .. }),
        "{error:?}"
    );
    assert!(error.to_string().contains("failing closed"));
}

#[test]
fn a_malformed_answer_fails_closed() {
    for bad in [
        Err(InspectClientError::Malformed {
            message: "missing field would_block".to_owned(),
        }),
        Ok(InspectResponse {
            would_block: true,
            config_revision: String::new(),
            mode: SiteMode::Block,
            safe_mode: false,
            category: None,
        }),
    ] {
        let mut gate = InspectGate::new(Scripted::new(vec![bad]), "rev-7");
        let error = gate.check(&request()).expect_err("must refuse");
        assert!(
            matches!(
                error,
                InspectGateError::Malformed { .. } | InspectGateError::Transport { .. }
            ),
            "{error:?}"
        );
    }
}

#[test]
fn the_happy_path_issues_a_ticket_bound_to_the_request_revision_and_enforcement_state() {
    let scripted = Scripted::new(vec![answer(true, "rev-7")]);
    let mut gate = InspectGate::new(scripted, "rev-7");
    let ticket = gate.check(&request()).expect("ticket");
    assert_eq!(ticket.request(), &request());
    assert_eq!(ticket.revision(), "rev-7");
    assert_eq!(ticket.category(), Some("sqli"));
    assert_eq!(ticket.mode(), SiteMode::Block);
    assert!(!ticket.safe_mode());
    assert!(ticket.site_is_enforcing(), "block mode, safe mode off");
    assert!(ticket.covers(
        "shop-site.org",
        Method::Get,
        &request().path,
        PayloadClass::A
    ));
    assert!(!ticket.covers(
        "other.example",
        Method::Get,
        &request().path,
        PayloadClass::A
    ));
    assert!(!ticket.covers(
        "shop-site.org",
        Method::Head,
        &request().path,
        PayloadClass::A
    ));
    assert_eq!(gate.expected_revision(), "rev-7");
}

#[test]
fn a_monitor_site_or_safe_mode_is_not_enforcing() {
    for (mode, safe_mode) in [(SiteMode::Monitor, false), (SiteMode::Block, true)] {
        let scripted = Scripted::new(vec![Ok(InspectResponse {
            would_block: true,
            config_revision: "rev-7".to_owned(),
            mode,
            safe_mode,
            category: None,
        })]);
        let mut gate = InspectGate::new(scripted, "rev-7");
        let ticket = gate.check(&request()).expect("the gate records the state");
        assert!(
            !ticket.site_is_enforcing(),
            "{mode} safe_mode={safe_mode} may not support a live enforcement test"
        );
    }
}

#[test]
fn the_inspect_request_uses_the_documented_endpoint() {
    let request = request();
    assert_eq!(request.endpoint(), "/api/v1/waf/inspect");
    assert_eq!(INSPECT_PATH, "/api/v1/waf/inspect");
}

#[test]
fn an_empty_site_is_refused_without_calling_the_client() {
    let scripted = Scripted::new(vec![answer(true, "rev-7")]);
    let calls = scripted.calls();
    let mut gate = InspectGate::new(scripted, "rev-7");
    let mut empty = request();
    empty.site = "  ".to_owned();
    assert!(matches!(
        gate.check(&empty),
        Err(InspectGateError::Malformed { .. })
    ));
    assert_eq!(call_count(&calls), 0);
}

#[test]
fn the_gate_calls_the_client_once_per_check() {
    let scripted = Scripted::new(vec![answer(true, "rev-7"), answer(true, "rev-7")]);
    let calls = scripted.calls();
    let mut gate = InspectGate::new(scripted, "rev-7");
    assert!(gate.check(&request()).is_ok());
    assert!(gate.check(&request()).is_ok());
    assert_eq!(call_count(&calls), 2);
    let on_endpoint = match calls.lock() {
        Ok(calls) => calls
            .iter()
            .filter(|r| r.endpoint() == INSPECT_PATH)
            .count(),
        Err(poisoned) => poisoned.into_inner().iter().count(),
    };
    assert_eq!(on_endpoint, 2);
}
