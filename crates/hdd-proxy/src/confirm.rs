//! The owner-triggered "confirm vulnerability" probe (Addendum 6 item 2).
//!
//! Four **inert, read-only** probes are sent to the finding's registered site origin through the same origin-forwarding
//! path as normal traffic (origin secret injected, `Host`/base path handled, redirects never followed), with detection
//! deliberately skipped and recorded as such in the audit log:
//!
//! 1. `baseline` â€” a benign value in the finding's field;
//! 2. `quote` â€” `X'`;
//! 3. `boolean_true` â€” `X' AND '1'='1`;
//! 4. `boolean_false` â€” `X' AND '1'='2`.
//!
//! The verdict compares status, redirect target and body length: a difference between baseline and the quote probe, or
//! between the boolean pair, is `confirmed_injectable`; everything equal is `not_confirmed`; a transport failure makes
//! it `inconclusive`. The probes never extract data, never use UNION, SLEEP or stacked statements, and the probe
//! bodies/credentials are never logged (only the fixed payload labels, statuses and lengths).

use std::net::IpAddr;

use http_body_util::BodyExt;

use crate::api::{ConfirmProbeResult, ConfirmRequest, ConfirmResponse, FindingView};
use crate::forward;
use crate::state::{AppState, SiteRuntime};
use crate::util;

/// The largest origin response body the confirm comparison measures (a larger body keeps counting to the cap only).
const PROBE_BODY_CAP: usize = 1024 * 1024;
/// The benign value used for the baseline probe.
pub const BASELINE_VALUE: &str = "hdd_confirm_benign_1";
/// The quote probe value.
pub const QUOTE_VALUE: &str = "hdd_confirm_x'";
/// The true boolean probe value.
pub const BOOLEAN_TRUE_VALUE: &str = "hdd_confirm_x' AND '1'='1";
/// The false boolean probe value.
pub const BOOLEAN_FALSE_VALUE: &str = "hdd_confirm_x' AND '1'='2";
/// The benign password sent with the non-password probes (never a real credential).
const BENIGN_PASSWORD: &str = "BenignLabPassword1";
/// The benign username sent with a password-field probe (never a real credential).
const BENIGN_USERNAME: &str = "benign_lab_user";

/// Why a confirm request was refused before any probe was sent.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConfirmError {
    /// No finding with that id exists.
    NotFound,
    /// The finding's site is not a registered site.
    UnregisteredSite,
    /// The typed confirmation did not equal the finding's site host.
    WrongConfirmation(String),
    /// The finding's vector has no single form field to probe safely (only `form_body` findings are confirmable).
    UnsupportedVector,
}

impl ConfirmError {
    /// The HTTP status for the refusal.
    #[must_use]
    pub fn status(&self) -> u16 {
        match self {
            Self::NotFound => 404,
            Self::UnregisteredSite | Self::WrongConfirmation(_) => 403,
            Self::UnsupportedVector => 400,
        }
    }

    /// The stable machine-readable code for the refusal.
    #[must_use]
    pub fn code(&self) -> &'static str {
        match self {
            Self::NotFound => "finding_not_found",
            Self::UnregisteredSite => "site_not_registered",
            Self::WrongConfirmation(_) => "confirmation_mismatch",
            Self::UnsupportedVector => "unsupported_vector",
        }
    }

    /// The human message (never contains a probe value or a credential).
    #[must_use]
    pub fn message(&self) -> String {
        match self {
            Self::NotFound => "no finding with that id".to_owned(),
            Self::UnregisteredSite => {
                "the finding's site is not configured, so no probe may be sent".to_owned()
            }
            Self::WrongConfirmation(host) => format!(
                "type the site host exactly (`{host}`) to confirm that you own the site before probing it"
            ),
            Self::UnsupportedVector => {
                "this finding has no single form field to probe (only form-body findings are confirmable); \
                 the confirm probe stays disabled rather than sending an unsafe request"
                    .to_owned()
            }
        }
    }
}

/// What one probe observed.
#[derive(Debug, Clone)]
struct Observation {
    /// The fixed probe label (never a payload body).
    name: &'static str,
    /// The upstream request line (method and path only).
    request: String,
    /// The status code, when the origin answered.
    status: Option<u16>,
    /// The redirect target path, when the origin redirected.
    redirect: Option<String>,
    /// The response body length in bytes, when measurable.
    body_length: Option<usize>,
    /// Whether the request/response completed (false => transport error/timeout).
    transport_ok: bool,
    /// A short human note for the response row.
    note: String,
}

/// Run the confirm flow: refuse early (unknown finding/site/typed confirmation) or send at most four inert probes.
///
/// # Errors
/// Returns [`ConfirmError`] for the documented refusals; the probes themselves are represented in the response.
pub async fn run(
    state: &AppState,
    finding: &FindingView,
    request: &ConfirmRequest,
    actor: &str,
    client_ip: IpAddr,
) -> Result<ConfirmResponse, ConfirmError> {
    let Some(site) = state.site(&finding.site) else {
        return Err(ConfirmError::UnregisteredSite);
    };
    let typed = request.confirmation.trim();
    if typed != finding.site {
        return Err(ConfirmError::WrongConfirmation(finding.site.clone()));
    }
    if finding.field.trim().is_empty() || finding.vector != "form_body" {
        return Err(ConfirmError::UnsupportedVector);
    }
    let ray_id = util::new_ray_id();
    let probes = [
        ("baseline", BASELINE_VALUE),
        ("quote", QUOTE_VALUE),
        ("boolean_true", BOOLEAN_TRUE_VALUE),
        ("boolean_false", BOOLEAN_FALSE_VALUE),
    ];
    let mut observations: Vec<Observation> = Vec::with_capacity(probes.len());
    for (name, value) in probes {
        observations.push(send_probe(state, &site, finding, name, value, client_ip, &ray_id).await);
    }
    let verdict_bool = compare(&observations);
    let (verdict, summary) = match verdict_bool {
        Verdict::Confirmed => {
            let _ = state.findings.mark_confirmed(&finding.id);
            (
                "confirmed_injectable".to_owned(),
                comparison_summary(
                    &observations,
                    "a probe response differs from the baseline comparison",
                ),
            )
        }
        Verdict::NotConfirmed => (
            "not_confirmed".to_owned(),
            comparison_summary(
                &observations,
                "all four probes answered the same (status, redirect and body length)",
            ),
        ),
        Verdict::Inconclusive => (
            "inconclusive".to_owned(),
            comparison_summary(
                &observations,
                "a probe failed in transport, so the comparison is incomplete",
            ),
        ),
    };
    state.events.audit(
        actor,
        "finding.confirm_probe",
        &finding.site,
        &format!(
            "ray {ray_id}: 4 inert POST probes on {} field `{}`, detection deliberately skipped; verdict {verdict}; \
             statuses {}; response bodies and credentials were not logged",
            probe_request_line(finding),
            util::truncate_utf8(&finding.field, 64),
            observations
                .iter()
                .map(|probe| format!("{}={}", probe.name, status_text(probe.status)))
                .collect::<Vec<_>>()
                .join(",")
        ),
    );
    let updated = state
        .findings
        .get(&finding.id)
        .unwrap_or_else(|| finding.clone());
    Ok(ConfirmResponse {
        verdict,
        probes: observations.iter().map(to_probe_row).collect(),
        summary,
        detection_skipped: true,
        ray_id,
        finding: updated,
    })
}

/// The three possible verdicts of the comparison.
enum Verdict {
    /// A difference was observed.
    Confirmed,
    /// All probes answered identically.
    NotConfirmed,
    /// A probe failed in transport.
    Inconclusive,
}

/// Compare the four observations.
fn compare(observations: &[Observation]) -> Verdict {
    let baseline = observations.first();
    let quote = observations.get(1);
    let boolean_true = observations.get(2);
    let boolean_false = observations.get(3);
    let baseline_ok = baseline.is_some_and(|probe| probe.transport_ok);
    let quote_diff = baseline_ok
        && quote.is_some_and(|probe| probe.transport_ok)
        && differs(baseline.unwrap_or(&FALLBACK), quote.unwrap_or(&FALLBACK));
    let boolean_pair_diff = boolean_true
        .zip(boolean_false)
        .is_some_and(|(left, right)| {
            left.transport_ok && right.transport_ok && differs(left, right)
        });
    if quote_diff || boolean_pair_diff {
        return Verdict::Confirmed;
    }
    if !baseline_ok || observations.iter().any(|probe| !probe.transport_ok) {
        return Verdict::Inconclusive;
    }
    Verdict::NotConfirmed
}

/// A neutral observation used only when an expected probe row is missing (never sent to the origin).
static FALLBACK: Observation = Observation {
    name: "missing",
    status: None,
    redirect: None,
    body_length: None,
    transport_ok: false,
    note: String::new(),
    request: String::new(),
};

/// Whether two observations differ in status, redirect target or body length.
fn differs(left: &Observation, right: &Observation) -> bool {
    left.status != right.status
        || left.redirect != right.redirect
        || left.body_length != right.body_length
}

/// A human comparison summary (statuses and lengths only; never a body).
fn comparison_summary(observations: &[Observation], conclusion: &str) -> String {
    let rows: Vec<String> = observations
        .iter()
        .map(|probe| {
            format!(
                "{}={} ({} bytes{})",
                probe.name,
                status_text(probe.status),
                probe.body_length.unwrap_or(0),
                probe
                    .redirect
                    .as_deref()
                    .map_or_else(String::new, |target| format!(", redirect {target}"))
            )
        })
        .collect();
    util::truncate_utf8(&format!("{conclusion}: {}", rows.join("; ")), 512).to_owned()
}

/// The status as text for a note/summary.
fn status_text(status: Option<u16>) -> String {
    status.map_or_else(|| "no_answer".to_owned(), |code| code.to_string())
}

/// The fixed request line of a probe (`POST <path>`, never the body or a credential).
fn probe_request_line(finding: &FindingView) -> String {
    format!("POST {}", util::truncate_utf8(&finding.path, 256))
}

/// Send one probe through the proxy's origin-forwarding path and observe the comparison facts.
async fn send_probe(
    state: &AppState,
    site: &SiteRuntime,
    finding: &FindingView,
    name: &'static str,
    value: &str,
    client_ip: IpAddr,
    ray_id: &str,
) -> Observation {
    let body = probe_form_body(&finding.field, value);
    let target = probe_target(site, &finding.path);
    let secret = match (site.origin_secret_header(), site.origin_secret_value()) {
        (Some(header), Some(secret)) => Some((header, secret)),
        _ => None,
    };
    let headers = forward::upstream_headers(
        &[],
        site.origin(),
        site.preserve_host(),
        site.upstream_host(),
        secret,
        &finding.site,
        client_ip,
        "http",
        ray_id,
    );
    let request = match forward::build_request(
        "POST",
        &target,
        headers,
        util::full_body(body.into_bytes()),
    ) {
        Ok(request) => request,
        Err(error) => {
            return Observation {
                name,
                request: format!("POST {target}"),
                status: None,
                redirect: None,
                body_length: None,
                transport_ok: false,
                note: format!(
                    "the probe request could not be built: {}",
                    forward::error_summary(&error)
                ),
            };
        }
    };
    match state.forwarder.send(site.origin(), request).await {
        Ok(response) => {
            let status = response.status().as_u16();
            let redirect = response
                .headers()
                .get(hyper::header::LOCATION)
                .and_then(|value| value.to_str().ok())
                .map(normalise_redirect);
            let mut incoming = response.into_body();
            let mut measured = 0_usize;
            let mut transport_ok = true;
            while let Some(frame) = incoming.frame().await {
                match frame {
                    Ok(frame) => {
                        if let Some(data) = frame.data_ref() {
                            measured = measured.saturating_add(data.len());
                        }
                        if measured >= PROBE_BODY_CAP {
                            break;
                        }
                    }
                    Err(_) => {
                        transport_ok = false;
                        break;
                    }
                }
            }
            let note = format!(
                "HTTP {status}, {} body bytes{}",
                measured,
                redirect
                    .as_deref()
                    .map_or_else(String::new, |target| format!(", redirect {target}"))
            );
            Observation {
                name,
                request: format!("POST {target}"),
                status: Some(status),
                redirect,
                body_length: Some(measured),
                transport_ok,
                note,
            }
        }
        Err(error) => Observation {
            name,
            request: format!("POST {target}"),
            status: None,
            redirect: None,
            body_length: None,
            transport_ok: false,
            note: format!("transport failure: {}", forward::error_summary(&error)),
        },
    }
}

/// Map one observation to the frozen `ConfirmProbeResult` DTO.
fn to_probe_row(observation: &Observation) -> ConfirmProbeResult {
    ConfirmProbeResult {
        name: observation.name.to_owned(),
        request: observation.request.clone(),
        status: observation.status,
        redirect: observation.redirect.clone(),
        body_length: observation.body_length,
        note: util::truncate_utf8(&observation.note, 256).to_owned(),
    }
}

/// Build the `application/x-www-form-urlencoded` probe body: the finding field plus a benign default for the other
/// usual login field. Never contains a real credential.
fn probe_form_body(field: &str, value: &str) -> String {
    let mut pairs: Vec<(String, String)> = vec![(field.to_owned(), value.to_owned())];
    if field.eq_ignore_ascii_case("password") {
        pairs.push(("username".to_owned(), BENIGN_USERNAME.to_owned()));
    } else if field.eq_ignore_ascii_case("username")
        || field.eq_ignore_ascii_case("user")
        || field.eq_ignore_ascii_case("login")
    {
        pairs.push(("password".to_owned(), BENIGN_PASSWORD.to_owned()));
    } else {
        pairs.push(("username".to_owned(), BENIGN_USERNAME.to_owned()));
        pairs.push(("password".to_owned(), BENIGN_PASSWORD.to_owned()));
    }
    pairs
        .iter()
        .map(|(name, value)| {
            format!(
                "{}={}",
                util::percent_encode_component(name),
                util::percent_encode_component(value)
            )
        })
        .collect::<Vec<_>>()
        .join("&")
}

/// The upstream request target for a probe: origin base path + the finding path.
fn probe_target(site: &SiteRuntime, finding_path: &str) -> String {
    let path = if finding_path.starts_with('/') {
        finding_path.to_owned()
    } else {
        format!("/{finding_path}")
    };
    let base = site.origin().base_path.as_str();
    if base.is_empty() {
        path
    } else {
        format!("{base}{path}")
    }
}

/// Normalise a redirect header to a path-only value (no host, no query, no fragment).
fn normalise_redirect(location: &str) -> String {
    let trimmed = location.trim();
    let path = if let Some((_, rest)) = trimmed.split_once("://") {
        let end = rest.find(['/', '?', '#']).unwrap_or(rest.len());
        rest.get(end..).unwrap_or("/")
    } else {
        trimmed
    };
    let path = path.split(['?', '#']).next().unwrap_or(path);
    let path = if path.is_empty() { "/" } else { path };
    util::truncate_utf8(path, 256).to_owned()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn probe_form_bodies_are_fixed_and_never_real_credentials() {
        let body = probe_form_body("username", BASELINE_VALUE);
        assert!(body.starts_with("username=hdd_confirm_benign_1"));
        assert!(body.contains("password=") || body.contains("username="));
        assert!(!body.contains("admin'"));
        let quoted = probe_form_body("username", QUOTE_VALUE);
        assert!(quoted.contains("hdd_confirm_x%27"), "quoted: {quoted}");
    }

    #[test]
    fn redirect_targets_are_reduced_to_paths() {
        assert_eq!(normalise_redirect("https://demo.test/admin?x=1"), "/admin");
        assert_eq!(normalise_redirect("/admin"), "/admin");
        assert_eq!(normalise_redirect("relative"), "relative");
    }

    #[test]
    fn comparison_uses_status_redirect_and_body_length() {
        let base = Observation {
            name: "baseline",
            status: Some(200),
            redirect: None,
            body_length: Some(100),
            transport_ok: true,
            note: String::new(),
            request: String::new(),
        };
        let same = Observation {
            name: "quote",
            ..base.clone()
        };
        assert!(!differs(&base, &same));
        let different_status = Observation {
            status: Some(500),
            ..base.clone()
        };
        assert!(differs(&base, &different_status));
        let different_redirect = Observation {
            redirect: Some("/admin".to_owned()),
            ..base.clone()
        };
        assert!(differs(&base, &different_redirect));
        let different_length = Observation {
            body_length: Some(101),
            ..base.clone()
        };
        assert!(differs(&base, &different_length));
    }

    #[test]
    fn verdict_prefers_a_difference_over_a_transport_error() {
        let mut baseline = Observation {
            name: "baseline",
            status: Some(200),
            redirect: None,
            body_length: Some(10),
            transport_ok: true,
            note: String::new(),
            request: String::new(),
        };
        let quote = Observation {
            name: "quote",
            body_length: Some(11),
            ..baseline.clone()
        };
        let true_probe = Observation {
            name: "boolean_true",
            transport_ok: false,
            status: None,
            body_length: None,
            ..baseline.clone()
        };
        let false_probe = Observation {
            name: "boolean_false",
            transport_ok: false,
            status: None,
            body_length: None,
            ..baseline.clone()
        };
        assert!(matches!(
            compare(&[baseline.clone(), quote, true_probe, false_probe]),
            Verdict::Confirmed
        ));
        let all_same = vec![
            baseline.clone(),
            Observation {
                name: "quote",
                ..baseline.clone()
            },
            Observation {
                name: "boolean_true",
                ..baseline.clone()
            },
            Observation {
                name: "boolean_false",
                ..baseline.clone()
            },
        ];
        assert!(matches!(compare(&all_same), Verdict::NotConfirmed));
        baseline.transport_ok = false;
        let with_failure = vec![
            baseline,
            Observation {
                name: "quote",
                transport_ok: false,
                ..all_same[1].clone()
            },
            all_same[2].clone(),
            all_same[3].clone(),
        ];
        assert!(matches!(compare(&with_failure), Verdict::Inconclusive));
    }
}
