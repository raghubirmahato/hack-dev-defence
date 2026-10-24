//! Origin lockdown and verify-protection probes (COLLAB.md Addenda 3 and 5; R-34: a site is not "protected" while it
//! can be bypassed).
//!
//! * `lockdown-check` sends **one** direct request to the site's own origin **without** the origin secret header. A
//!   `2xx` means the origin is reachable directly (not protected); `401`/`403` means it refused the bypass (protected).
//!   For a front-door site (Addendum 7) the origin is the wrapper itself: the direct request is forwarded by the wrapper
//!   to HDD, whose neutral unknown-host `404` carries an HDD Ray ID. That response shows the app was not served
//!   directly, so it counts as a refusal; a Ray-ID-less `404` stays an error, and a `2xx` still means reachable.
//! * `verify` sends **at most two** inert, clearly labelled requests and only to the registered site: the M1 payload of
//!   spec C4.1 as a GET query value, plus one benign GET. The blocked probe carries `Sec-Fetch-Site: cross-site` and
//!   `Sec-Fetch-Dest: image` so that it is still refused by the proxy but cannot ban the proxy's own address (spec
//!   C6.5); the loopback safety net below removes any ban against the probe source that still appears.

use std::net::IpAddr;

use crate::api::{LockdownCheckResponse, VerifyCheck, VerifyRequest, VerifyResponse};
use crate::state::{AppState, SiteRuntime};
use crate::util;

/// The M1 payload of spec C4.1, sent as an inert GET query value only to the registered site.
pub const M1_PAYLOAD: &str = "' OR 1=1--";

/// The lockdown-check outcome for one origin, plus the recorded site state update.
pub async fn check_lockdown(
    state: &AppState,
    site: &SiteRuntime,
    actor: &str,
) -> LockdownCheckResponse {
    let host_header = site
        .upstream_host()
        .map_or_else(|| site.origin().authority(), str::to_owned);
    let path = if site.origin().base_path.is_empty() {
        "/".to_owned()
    } else {
        format!("{}/", site.origin().base_path)
    };
    let header_name = site
        .origin_secret_header()
        .unwrap_or("the origin secret header");
    let outcome = state
        .forwarder
        .probe_origin(site.origin(), &host_header, &path)
        .await;
    match outcome {
        Ok(probe) => {
            let status = probe.status.as_u16();
            if probe.status.is_success() {
                site.set_lockdown_verified(false);
                let detail = format!(
                    "a direct request to the origin returned HTTP {status} without `{header_name}`; the origin is \
                     reachable directly, so this site is not protected yet (R-34)"
                );
                audit(state, actor, site.host(), &detail);
                LockdownCheckResponse {
                    result: "reachable".to_owned(),
                    detail,
                    protected: false,
                    status_code: Some(status),
                }
            } else if status == 401 || status == 403 {
                site.set_lockdown_verified(true);
                let detail = format!(
                    "a direct request to the origin was refused with HTTP {status}; the origin lock-down holds"
                );
                audit(state, actor, site.host(), &detail);
                LockdownCheckResponse {
                    result: "refused".to_owned(),
                    detail,
                    protected: true,
                    status_code: Some(status),
                }
            } else if status == 404 && probe.header("hdd-ray-id").is_some_and(util::is_ray_id) {
                // Addendum 7: for a front door the origin *is* the wrapper. A direct request without the secret is
                // forwarded by the wrapper to HDD, which answers its neutral unknown-host 404 (that page always carries
                // an HDD Ray ID). The app was therefore not served directly: the hop added by the front door is what the
                // check sees, and this is the front-door equivalent of a refusal. A 404 from anything other than HDD
                // (no Ray ID) stays an error below, and a 2xx still means the app answered directly.
                site.set_lockdown_verified(true);
                let detail = format!(
                    "a direct request to the origin returned HTTP {status} with an HDD Ray ID: the front-door wrapper \
                     forwarded it to HDD (which answered its neutral unknown-host page), so the app was not served \
                     directly and the front-door lock-down holds"
                );
                audit(state, actor, site.host(), &detail);
                LockdownCheckResponse {
                    result: "refused".to_owned(),
                    detail,
                    protected: true,
                    status_code: Some(status),
                }
            } else {
                site.set_lockdown_verified(false);
                let hint = if status >= 500 {
                    "; a server error often means the lock code pasted into the app has a mistake (for example Next.js \
                     code in a plain Node file): remove it, paste the Node snippet from the guide at the very end of the \
                     handler file, and redeploy"
                } else {
                    ""
                };
                let detail = format!(
                    "a direct request to the origin returned HTTP {status}, which is neither a refusal (401/403) \
                     nor a success; lock-down cannot be confirmed{hint}"
                );
                audit(state, actor, site.host(), &detail);
                LockdownCheckResponse {
                    result: "error".to_owned(),
                    detail,
                    protected: false,
                    status_code: Some(status),
                }
            }
        }
        Err(error) => {
            site.set_lockdown_verified(false);
            let detail = format!(
                "the direct request to the origin failed: {}",
                crate::forward::error_summary(&error)
            );
            audit(state, actor, site.host(), &detail);
            LockdownCheckResponse {
                result: "error".to_owned(),
                detail,
                protected: false,
                status_code: None,
            }
        }
    }
}

/// Run the verify-protection flow (at most two inert requests, only to the registered site).
///
/// # Errors
/// Returns a message when the typed confirmation does not match or the site's `public_url` is unsafe to probe.
pub async fn verify(
    state: &AppState,
    site: &SiteRuntime,
    request: &VerifyRequest,
    actor: &str,
) -> Result<VerifyResponse, String> {
    let typed = request.confirmation.trim();
    if typed != site.host() {
        return Err(format!(
            "type the site host exactly (`{}`) to confirm that you own it",
            site.host()
        ));
    }
    let base = match site.public_url() {
        Some(public_url) => public_url.to_owned(),
        None => state.proxy_base_url(),
    };
    let base_origin = util::Origin::parse(&base).map_err(|message| {
        format!("the site public_url is not usable for verification: {message}")
    })?;
    if !probe_target_is_registered(&base_origin, site) {
        return Err(format!(
            "refusing to verify: the probe target `{base}` is neither the registered host `{}` nor this proxy's own \
             loopback listener",
            site.host()
        ));
    }
    let mut checks: Vec<VerifyCheck> = Vec::with_capacity(3);
    if site.lockdown_verified() {
        checks.push(VerifyCheck {
            name: "origin_lockdown".to_owned(),
            status: "PASS".to_owned(),
            detail: "the last origin lock-down check saw the origin refuse a direct request"
                .to_owned(),
        });
    } else {
        checks.push(VerifyCheck {
            name: "origin_lockdown".to_owned(),
            status: "UNVERIFIED".to_owned(),
            detail:
                "the origin lock-down has not been verified; run the lock-down check first (R-34)"
                    .to_owned(),
        });
    }

    // Probe 1: one benign GET through the same public URL (proves the normal path still works). It goes first: the
    // block probe can ban the probing address, which would make a later benign request fail for the wrong reason.
    let benign_headers = vec![("Accept".to_owned(), "text/html".to_owned())];
    match state
        .forwarder
        .probe_url(&base, "/?hdd_verify=benign", &benign_headers)
        .await
    {
        Ok(probe) => {
            let status = probe.status.as_u16();
            if (200..400).contains(&status) {
                checks.push(VerifyCheck {
                    name: "benign_probe".to_owned(),
                    status: "PASS".to_owned(),
                    detail: format!("a benign GET got HTTP {status} through the public URL"),
                });
            } else if status == 403 {
                // Every response carries a Ray ID, so tell the two causes apart by the ban list instead.
                let probe_is_banned = base_origin
                    .host
                    .parse::<IpAddr>()
                    .is_ok_and(|ip| state.bans.active(ip).is_some());
                let detail = if probe_is_banned {
                    "a benign GET was refused by HDD with HTTP 403 because the probe address is banned; remove the ban and verify again"
                } else {
                    "a benign GET was refused with HTTP 403: most likely the origin rejected HDD's secret header. The secret stored in the origin (for example the Vercel HDD_ORIGIN_SECRET variable) must be exactly the value HDD sends; set it, redeploy, then verify again"
                };
                checks.push(VerifyCheck {
                    name: "benign_probe".to_owned(),
                    status: "FAIL".to_owned(),
                    detail: detail.to_owned(),
                });
            } else {
                checks.push(VerifyCheck {
                    name: "benign_probe".to_owned(),
                    status: "FAIL".to_owned(),
                    detail: format!(
                        "a benign GET got HTTP {status}; the proxy cannot reach the origin through the public URL"
                    ),
                });
            }
        }
        Err(error) => {
            checks.push(VerifyCheck {
                name: "benign_probe".to_owned(),
                status: "UNVERIFIED".to_owned(),
                detail: format!(
                    "the benign probe could not be sent: {}",
                    crate::forward::error_summary(&error)
                ),
            });
        }
    }

    // Probe 2: the M1 payload as a GET query value. Cross-site subresource context keeps this from banning us.
    let mut ray_id: Option<String> = None;
    let mut blocked = false;
    let block_target = format!("/?q={}", encode_query_value(M1_PAYLOAD));
    let probe_headers = vec![
        ("Sec-Fetch-Site".to_owned(), "cross-site".to_owned()),
        ("Sec-Fetch-Dest".to_owned(), "image".to_owned()),
        ("Accept".to_owned(), "text/html".to_owned()),
    ];
    match state
        .forwarder
        .probe_url(&base, &block_target, &probe_headers)
        .await
    {
        Ok(probe) => {
            let status = probe.status.as_u16();
            // A 403 only counts as HDD's block when HDD recorded a block for this probe's Ray ID: an origin that rejects
            // HDD's secret also answers 403, and that is not protection.
            let probe_ray = probe
                .header("hdd-ray-id")
                .map(str::trim)
                .filter(|value| util::is_ray_id(value))
                .map(str::to_owned);
            let hdd_blocked = status == 403
                && probe_ray.as_deref().is_some_and(|ray| {
                    state
                        .events
                        .query(&crate::events::EventFilter {
                            site: Some(site.host()),
                            action: Some("block"),
                            q: None,
                            limit: 200,
                        })
                        .iter()
                        .any(|event| event.ray_id == ray)
                });
            if status == 403 && !hdd_blocked {
                checks.push(VerifyCheck {
                    name: "block_probe".to_owned(),
                    status: "FAIL".to_owned(),
                    detail: format!(
                        "the inert M1 payload got HTTP 403 but HDD did not record a block for it, so the 403 came from the origin \
                         (its lock rejected HDD's secret); the site is in `{}` mode",
                        site.mode().as_str()
                    ),
                });
            } else if hdd_blocked {
                blocked = true;
                ray_id = probe_ray;
                checks.push(VerifyCheck {
                    name: "block_probe".to_owned(),
                    status: "PASS".to_owned(),
                    detail: format!(
                        "the inert M1 payload in a GET query value was refused with HTTP 403{}",
                        ray_id
                            .as_deref()
                            .map_or_else(String::new, |ray| format!(" (Ray ID {ray})"))
                    ),
                });
            } else if (300..400).contains(&status) {
                checks.push(VerifyCheck {
                    name: "block_probe".to_owned(),
                    status: "FAIL".to_owned(),
                    detail: format!(
                        "the inert M1 payload got HTTP {status} (a redirect) instead of a block; traffic may still be \
                         going directly to the origin"
                    ),
                });
            } else {
                checks.push(VerifyCheck {
                    name: "block_probe".to_owned(),
                    status: "FAIL".to_owned(),
                    detail: format!(
                        "the inert M1 payload got HTTP {status} instead of a block; the site is in `{}` mode or DNS \
                         still points at the origin",
                        site.mode().as_str()
                    ),
                });
            }
        }
        Err(error) => {
            checks.push(VerifyCheck {
                name: "block_probe".to_owned(),
                status: "UNVERIFIED".to_owned(),
                detail: format!(
                    "the block probe could not be sent: {}",
                    crate::forward::error_summary(&error)
                ),
            });
        }
    }

    // Safety net: never leave the proxy's own loopback address banned by its own verification probe (R-19).
    if let Ok(loopback_ip) = base_origin.host.parse::<IpAddr>()
        && loopback_ip.is_loopback()
        && state.bans.remove(loopback_ip)
    {
        state.events.audit(
            "system",
            "ban.removed",
            &loopback_ip.to_string(),
            "removed the ban created by the verify probe on the proxy's own loopback address",
        );
    }

    let benign_ok = checks
        .iter()
        .any(|check| check.name == "benign_probe" && check.status == "PASS");
    let protected = blocked && site.lockdown_verified() && benign_ok;
    let summary = if protected {
        "protection verified: the origin refused a direct bypass, the inert payload was blocked and normal requests still reach the site"
            .to_owned()
    } else if blocked && site.lockdown_verified() {
        "the inert payload was blocked and the origin refuses direct access, but normal requests do not reach the site through HDD, so visitors would see errors; fix the failing check below"
            .to_owned()
    } else if blocked {
        "the inert payload was blocked, but the origin lock-down is not verified, so the site is not protected yet \
         (R-34)"
            .to_owned()
    } else {
        "protection is not verified; the inert payload was not blocked through the public URL"
            .to_owned()
    };
    state.events.audit(
        actor,
        "protection.verify",
        site.host(),
        &format!(
            "protected={protected}; ray={}",
            ray_id.as_deref().unwrap_or("none")
        ),
    );
    Ok(VerifyResponse {
        protected,
        checks,
        ray_id,
        summary,
    })
}

/// Whether a verify probe target is the registered site or this proxy's own loopback listener.
fn probe_target_is_registered(origin: &util::Origin, site: &SiteRuntime) -> bool {
    if origin.host.eq_ignore_ascii_case(site.host()) {
        return true;
    }
    origin
        .host
        .parse::<IpAddr>()
        .map(|address| address.is_loopback())
        .unwrap_or(false)
}

/// Percent-encode one query value (unreserved characters kept; everything else `%XX`).
fn encode_query_value(value: &str) -> String {
    let mut out = String::with_capacity(value.len() * 3);
    for byte in value.bytes() {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~') {
            out.push(char::from(byte));
        } else {
            out.push('%');
            let high = byte >> 4;
            let low = byte & 0x0f;
            out.push(hex_digit(high));
            out.push(hex_digit(low));
        }
    }
    out
}

/// One upper-case hex digit for the query encoder.
fn hex_digit(value: u8) -> char {
    match value {
        0..=9 => char::from(b'0' + value),
        _ => char::from(b'A' + (value - 10)),
    }
}

/// Write an audit line for a probe run (target is the site host, never a payload).
fn audit(state: &AppState, actor: &str, target: &str, detail: &str) {
    state.events.audit(actor, "lockdown.check", target, detail);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn payload_encoder_produces_a_safe_query_value() {
        assert_eq!(encode_query_value(M1_PAYLOAD), "%27%20OR%201%3D1--");
        assert_eq!(encode_query_value("safe-._~"), "safe-._~");
    }
}
