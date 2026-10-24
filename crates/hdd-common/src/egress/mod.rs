//! The single outbound path (R-22): allowlist, SSRF guard, target guard, kill switch and the client that enforces them (T-0009).
//!
//! * [`allow`]: allowlist entries and matching (`egress_allowlist` of the profile);
//! * [`ssrf`]: address classification and the origin address policy (section 2.9);
//! * [`url`]: strict URL parsing;
//! * [`resolver`]: resolver trait, system resolver, stub resolver over UDP with CNAME visibility;
//! * [`client`]: [`Client`] (allowlist) and [`UserUrlClient`] (SSRF-guarded);
//! * [`target`]: [`TargetGuard`], the target set of acceptance and scanning tools;
//! * [`killswitch`]: the kill-switch file watcher;
//! * [`denylog`]: structured, rate-limited record of denied attempts.
//!
//! Every outbound connection of HDD must go through this module; `cargo xtask verify` fails on a direct socket or HTTP client
//! construction elsewhere (rule `rules`, R-22).

pub mod allow;
pub mod client;
pub mod denylog;
pub mod killswitch;
pub mod probe;
pub mod resolver;
pub mod ssrf;
pub mod target;
pub mod url;

pub use client::{Client, EgressConfig, EgressError, Limits, Request, Response, UserUrlClient};
pub use denylog::DenyLog;
pub use killswitch::KillSwitch;
pub use target::{TargetDenied, TargetGuard, TargetMode};

#[cfg(test)]
mod tests;

/// Entry point for a coverage-guided fuzz target (`fuzz/fuzz_targets/egress_url.rs` once `cargo-fuzz` is available, T-0259):
/// feeds arbitrary bytes to every parser of this module. It must never panic; the property tests in this crate call it with
/// arbitrary input today.
pub fn fuzz_entry(data: &[u8]) {
    let text = String::from_utf8_lossy(data);
    if let Ok(u) = url::parse_url(&text) {
        let _ = u.display_no_query();
        let _ = u.host_header();
        let _ = u.join(&text);
        let _ = u.join("../a?b#c");
    }
    let _ = allow::Allowlist::parse(&[text.as_ref()]);
    let _ = crate::net::validate_hostname(&text);
    let _ = text.parse::<crate::net::Cidr>();
    if let Ok(entry) = allow::AllowEntry::parse(&text) {
        let _ = entry.matches(allow::Scheme::Https, &text, 443, &text);
    }
    let _ = resolver::wire::parse_response(data, 1, "a.example.com", resolver::wire::TYPE_A);
    let _ = resolver::wire::read_name(data, 0);
}

#[cfg(test)]
mod fuzz_tests {
    use proptest::prelude::*;

    proptest! {
        #[test]
        fn fuzz_entry_never_panics_on_arbitrary_bytes(data in proptest::collection::vec(any::<u8>(), 0..400)) {
            super::fuzz_entry(&data);
        }

        #[test]
        fn fuzz_entry_never_panics_on_url_shaped_text(s in r"(https?://)?[a-z0-9.:@/?#%*\[\]-]{0,120}") {
            super::fuzz_entry(s.as_bytes());
        }
    }

    #[test]
    fn fuzz_entry_handles_known_hostile_inputs() {
        let long = "a".repeat(100_000);
        let brackets = "[".repeat(5000);
        for input in [
            "",
            "http://",
            "http://[",
            "https://a:99999999999999999999/",
            "*",
            "*.",
            "tcp://::1:1",
            "https://\u{0}",
            long.as_str(),
            brackets.as_str(),
        ] {
            super::fuzz_entry(input.as_bytes());
        }
    }
}
