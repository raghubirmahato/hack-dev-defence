//! The download of the pinned archive, through the single egress path (R-22).
//!
//! Nothing here opens a socket itself. The caller supplies the allowlist entries (normally the `egress_allowlist` of the live
//! profile, or the entries the operator passes on the command line: adding an egress destination is the operator's decision);
//! [`super::manifest::Manifest::egress_entries`] says which ones this download needs. The downloaded file is only a candidate:
//! `Embedded::install` verifies its size and SHA-256 against the manifest before anything is extracted.

use std::fs;
use std::path::{Path, PathBuf};
use std::time::Duration;

use hdd_common::egress::allow::Allowlist;
use hdd_common::egress::{Client, EgressConfig, EgressError, Limits, Request};

use super::manifest::{Manifest, Target};
use super::{PgError, PgResult};

/// Fetch the archive of `target` into `cache_dir` and return its path. Blocking: runs its own small runtime.
pub fn download(
    manifest: &Manifest,
    target: &Target,
    allow: &[String],
    cache_dir: &Path,
) -> PgResult<PathBuf> {
    if allow.is_empty() {
        return Err(PgError::Download(format!(
            "no egress allowlist entries were given; the download needs: {}",
            manifest.egress_entries().join(" ")
        )));
    }
    let allowlist = Allowlist::parse(allow).map_err(|errs| {
        PgError::Download(format!(
            "invalid allowlist entry number {}",
            errs.first().map_or(0, |(i, _)| *i + 1)
        ))
    })?;
    let limits = Limits {
        connect_timeout: Duration::from_secs(15),
        total_timeout: Duration::from_secs(20 * 60),
        // the archives are 40 to 95 MB; the cap leaves room for the pinned size and nothing more
        max_response_bytes: usize::try_from(target.size.saturating_add(1024 * 1024))
            .unwrap_or(usize::MAX),
        max_request_bytes: 0,
    };
    let client = Client::with_config(allowlist, EgressConfig::new("hdd-local-pg").limits(limits))
        .map_err(PgError::Download)?;
    let url = manifest.url(target);
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|e| PgError::Download(format!("cannot start the runtime: {e}")))?;
    let response = rt
        .block_on(client.send(Request::get(url.clone()).follow_redirects(3)))
        .map_err(|e| match e {
            EgressError::Denied { reason, destination } => PgError::Download(format!(
                "denied by the egress policy ({reason}) for {destination}; the download needs these allowlist entries: {}",
                manifest.egress_entries().join(" ")
            )),
            other => PgError::Download(other.to_string()),
        })?;
    if response.status != 200 {
        return Err(PgError::Download(format!(
            "the server answered {} for {}",
            response.status, target.file
        )));
    }
    super::files::create_private_dir(cache_dir)?;
    let partial = cache_dir.join(format!("{}.partial", target.file));
    fs::write(&partial, &response.body)?;
    let finished = cache_dir.join(&target.file);
    fs::rename(&partial, &finished)?;
    Ok(finished)
}
