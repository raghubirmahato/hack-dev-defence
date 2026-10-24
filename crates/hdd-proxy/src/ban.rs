//! The progressive-TTL IP ban store (COLLAB.md HK1 brief; spec C6.3 ladder, C6.5 cross-site rule).
//!
//! A ban is a time-limited denial for one IP key, site-scoped in this slice, enforced at the proxy listener before any
//! inspection or forwarding happens. The ladder step grows with the offence count (quiet resets after [`QUIET_DECAY`]),
//! and the last ladder entry repeats. The store is in memory and bounded: expired records are purged on every access
//! (`BanStore::open` also keeps them in `bans.json` in the data directory, so a restart does not release an attacker),
//! and the ban list is capped so a hostile scan cannot grow memory without limit (`MAX_ACTIVE_BANS`).
//!
//! Cross-site ban-poisoning resistance lives in [`is_cross_site_subresource`]: a block verdict caused by a cross-site
//! subresource request is still refused **and still bans**, but the hit counts at a lower ladder weight (review R1-6:
//! the `Sec-Fetch-*` headers are client-controlled, so skipping the ban would be a trivial evasion).
//!
//! IPv6 bans are keyed per /64 (spec C6.2) so rotation inside the prefix does not evade a ban; IPv4 keeps /32 keys.

use std::collections::HashMap;
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::{Duration, Instant, SystemTime};

use serde::{Deserialize, Serialize};

use crate::api::BanView;
use crate::util;

/// How long a quiet period resets the offence counter (spec C6.3 default: 30 days).
pub const QUIET_DECAY: Duration = Duration::from_secs(30 * 24 * 3600);
/// The hard cap on simultaneously active bans; the oldest expiry is evicted first (spec C6.6 item 5, reduced for HK1).
pub const MAX_ACTIVE_BANS: usize = 100_000;
/// Ladder weight units of one direct attack hit (a full offence step).
const DIRECT_OFFENCE_UNITS: u32 = 2;
/// Ladder weight units of one cross-site subresource hit (half a step: it counts, but slower; review R1-6).
const CROSS_SITE_OFFENCE_UNITS: u32 = 1;

/// The request context of a ban-creating block verdict.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BanContext {
    /// A direct request (no cross-site browser context): a full offence step.
    Direct,
    /// A cross-site subresource request: still banned, with a lower ladder weight (review R1-6).
    CrossSite,
}

impl BanContext {
    /// The ladder-weight units this context adds to the offence counter.
    #[must_use]
    fn units(self) -> u32 {
        match self {
            Self::Direct => DIRECT_OFFENCE_UNITS,
            Self::CrossSite => CROSS_SITE_OFFENCE_UNITS,
        }
    }
}

/// One active ban.
#[derive(Debug, Clone)]
struct BanRecord {
    /// The banned IP key (IPv4 /32 address or the IPv6 /64 network address).
    ip: IpAddr,
    /// The site the ban was created for.
    site: Option<String>,
    /// The human-readable reason (`block verdict, rule ..., vector ...`).
    reason: String,
    /// The rule id that caused the ban.
    rule_id: Option<String>,
    /// The attack category.
    category: Option<String>,
    /// RFC 3339 UTC creation time.
    created_at: String,
    /// RFC 3339 UTC expiry time.
    expires_at: String,
    /// When the ban expires.
    expires_instant: Instant,
    /// The TTL of the current ladder step.
    ttl_seconds: u64,
    /// The ladder step (1-based).
    step: u32,
}

/// The offence counter for one IP key.
#[derive(Debug, Clone, Copy)]
struct Offence {
    /// Ladder weight units accumulated within the decay window (a direct hit is two units, a cross-site hit one).
    units: u32,
    /// When the last offence happened.
    last: Instant,
}

/// The ban store.
pub struct BanStore {
    /// Bans and offence counters behind one mutex.
    inner: Mutex<Inner>,
    /// Where the bans are kept across restarts (`None` for an in-memory store).
    path: Option<PathBuf>,
}

/// The on-disk form of the store: wall-clock times, because an `Instant` means nothing after a restart.
#[derive(Debug, Default, Serialize, Deserialize)]
struct Saved {
    bans: Vec<SavedBan>,
    offences: Vec<SavedOffence>,
}

#[derive(Debug, Serialize, Deserialize)]
struct SavedBan {
    ip: String,
    site: Option<String>,
    reason: String,
    rule_id: Option<String>,
    category: Option<String>,
    created_at: String,
    expires_at: String,
    expires_unix: u64,
    ttl_seconds: u64,
    step: u32,
}

#[derive(Debug, Serialize, Deserialize)]
struct SavedOffence {
    ip: String,
    units: u32,
    last_unix: u64,
}

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .map_or(0, |elapsed| elapsed.as_secs())
}

/// Mutable state of the ban store.
struct Inner {
    /// Active bans keyed by IP.
    bans: HashMap<IpAddr, BanRecord>,
    /// Offence counters keyed by IP.
    offences: HashMap<IpAddr, Offence>,
}

impl BanStore {
    /// Create an empty store.
    #[must_use]
    pub fn new() -> Self {
        Self {
            inner: Mutex::new(Inner {
                bans: HashMap::new(),
                offences: HashMap::new(),
            }),
            path: None,
        }
    }

    /// Open a store that keeps its bans and offence counters in `path` (best effort: an unreadable file starts empty,
    /// a failed write leaves the in-memory store authoritative).
    #[must_use]
    pub fn open(path: &Path) -> Self {
        let mut store = Self::new();
        store.path = Some(path.to_path_buf());
        let saved: Saved = std::fs::read_to_string(path)
            .ok()
            .and_then(|text| serde_json::from_str(&text).ok())
            .unwrap_or_default();
        let now = Instant::now();
        let wall = unix_now();
        {
            let mut inner = util::lock(&store.inner);
            for ban in saved.bans {
                let Ok(ip) = ban.ip.parse::<IpAddr>() else {
                    continue;
                };
                if ban.expires_unix <= wall {
                    continue;
                }
                inner.bans.insert(
                    ip,
                    BanRecord {
                        ip,
                        site: ban.site,
                        reason: ban.reason,
                        rule_id: ban.rule_id,
                        category: ban.category,
                        created_at: ban.created_at,
                        expires_at: ban.expires_at,
                        expires_instant: now + Duration::from_secs(ban.expires_unix - wall),
                        ttl_seconds: ban.ttl_seconds,
                        step: ban.step,
                    },
                );
            }
            for offence in saved.offences {
                let Ok(ip) = offence.ip.parse::<IpAddr>() else {
                    continue;
                };
                let age = Duration::from_secs(wall.saturating_sub(offence.last_unix));
                if age > QUIET_DECAY {
                    continue;
                }
                inner.offences.insert(
                    ip,
                    Offence {
                        units: offence.units,
                        last: now.checked_sub(age).unwrap_or(now),
                    },
                );
            }
        }
        store
    }

    /// Write the current bans and offence counters to disk (no-op for an in-memory store).
    fn save(&self, inner: &Inner) {
        let Some(path) = &self.path else {
            return;
        };
        let now = Instant::now();
        let wall = unix_now();
        let saved = Saved {
            bans: inner
                .bans
                .values()
                .map(|record| SavedBan {
                    ip: record.ip.to_string(),
                    site: record.site.clone(),
                    reason: record.reason.clone(),
                    rule_id: record.rule_id.clone(),
                    category: record.category.clone(),
                    created_at: record.created_at.clone(),
                    expires_at: record.expires_at.clone(),
                    expires_unix: wall.saturating_add(
                        record
                            .expires_instant
                            .saturating_duration_since(now)
                            .as_secs(),
                    ),
                    ttl_seconds: record.ttl_seconds,
                    step: record.step,
                })
                .collect(),
            offences: inner
                .offences
                .iter()
                .map(|(ip, offence)| SavedOffence {
                    ip: ip.to_string(),
                    units: offence.units,
                    last_unix: wall
                        .saturating_sub(now.saturating_duration_since(offence.last).as_secs()),
                })
                .collect(),
        };
        let Ok(text) = serde_json::to_string(&saved) else {
            return;
        };
        let temp = path.with_extension("json.tmp");
        if std::fs::write(&temp, text).is_ok() {
            let _ = std::fs::rename(&temp, path);
        }
    }

    /// Whether `ip` is currently banned, returning its view (purging expired bans on the way).
    ///
    /// IPv6 addresses are matched through their /64 key (spec C6.2).
    #[must_use]
    pub fn active(&self, ip: IpAddr) -> Option<BanView> {
        let mut inner = util::lock(&self.inner);
        let now = Instant::now();
        purge_expired(&mut inner.bans, now);
        inner
            .bans
            .get(&ban_key(ip))
            .map(|record| view_of(record, now))
    }

    /// Create (or replace) a ban for `ip`, advancing the ladder by the context's offence weight.
    ///
    /// The returned view is what the API and the JSONL audit line carry; the caller records the audit event.
    #[allow(clippy::too_many_arguments)]
    pub fn create(
        &self,
        ip: IpAddr,
        site: Option<&str>,
        reason: &str,
        rule_id: Option<&str>,
        category: Option<&str>,
        ladder: &[u64],
        context: BanContext,
    ) -> BanView {
        let key = ban_key(ip);
        let now = Instant::now();
        let mut inner = util::lock(&self.inner);
        purge_expired(&mut inner.bans, now);
        let offence = inner.offences.entry(key).or_insert(Offence {
            units: 0,
            last: now,
        });
        if now.duration_since(offence.last) > QUIET_DECAY {
            offence.units = 0;
        }
        offence.units = offence.units.saturating_add(context.units());
        offence.last = now;
        let step = offence.units.saturating_add(1) / 2;
        let ttl_seconds = ladder_ttl(ladder, step);
        let record = BanRecord {
            ip: key,
            site: site.map(str::to_owned),
            reason: reason.to_owned(),
            rule_id: rule_id.map(str::to_owned),
            category: category.map(str::to_owned),
            created_at: util::rfc3339(SystemTime::now()),
            expires_at: util::rfc3339(SystemTime::now() + Duration::from_secs(ttl_seconds)),
            expires_instant: now + Duration::from_secs(ttl_seconds),
            ttl_seconds,
            step,
        };
        let view = view_of(&record, now);
        inner.bans.insert(key, record);
        if inner.bans.len() > MAX_ACTIVE_BANS {
            evict_oldest(&mut inner.bans);
        }
        self.save(&inner);
        view
    }

    /// Remove the ban for `ip`. Returns whether a ban was active.
    pub fn remove(&self, ip: IpAddr) -> bool {
        let mut inner = util::lock(&self.inner);
        purge_expired(&mut inner.bans, Instant::now());
        let removed = inner.bans.remove(&ban_key(ip)).is_some();
        if removed {
            self.save(&inner);
        }
        removed
    }

    /// Purge expired bans and offence counters that have been quiet longer than [`QUIET_DECAY`].
    ///
    /// Called on every mutation as before and from a background timer ([`crate::server`]) so a long-running process
    /// that sees no traffic still releases expired state and does not grow the offence map without bound.
    pub fn prune(&self) {
        let now = Instant::now();
        let mut inner = util::lock(&self.inner);
        purge_expired(&mut inner.bans, now);
        inner
            .offences
            .retain(|_, offence| !offence_is_expired(offence, now));
    }

    /// All active bans, soonest expiry first.
    #[must_use]
    pub fn list(&self) -> Vec<BanView> {
        let now = Instant::now();
        let mut inner = util::lock(&self.inner);
        purge_expired(&mut inner.bans, now);
        let mut bans: Vec<BanView> = inner
            .bans
            .values()
            .map(|record| view_of(record, now))
            .collect();
        bans.sort_by_key(|ban| ban.remaining_seconds);
        bans
    }

    /// The number of currently active bans.
    #[must_use]
    pub fn active_count(&self) -> u64 {
        let mut inner = util::lock(&self.inner);
        purge_expired(&mut inner.bans, Instant::now());
        inner.bans.len() as u64
    }
}

impl Default for BanStore {
    fn default() -> Self {
        Self::new()
    }
}

/// The TTL of ladder step `step` (1-based); the last entry repeats for later offences.
#[must_use]
pub fn ladder_ttl(ladder: &[u64], step: u32) -> u64 {
    if ladder.is_empty() {
        return 60;
    }
    let index = usize::try_from(step.saturating_sub(1)).unwrap_or(usize::MAX);
    ladder
        .get(index)
        .copied()
        .or_else(|| ladder.last().copied())
        .unwrap_or(60)
}

/// The ban key for an address: IPv4 stays /32, IPv6 is masked to its /64 network (spec C6.2).
#[must_use]
pub fn ban_key(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V4(address) => IpAddr::V4(address),
        IpAddr::V6(address) => {
            let mut segments = address.segments();
            for segment in segments.iter_mut().skip(4) {
                *segment = 0;
            }
            IpAddr::V6(std::net::Ipv6Addr::from(segments))
        }
    }
}

/// Whether an offence counter has been quiet for longer than [`QUIET_DECAY`].
fn offence_is_expired(offence: &Offence, now: Instant) -> bool {
    now.duration_since(offence.last) > QUIET_DECAY
}

/// Remove bans whose expiry has passed.
fn purge_expired(bans: &mut HashMap<IpAddr, BanRecord>, now: Instant) {
    bans.retain(|_, record| record.expires_instant > now);
}

/// Evict the ban with the soonest expiry (collateral-damage cap; manual bans do not go through this store in HK1).
fn evict_oldest(bans: &mut HashMap<IpAddr, BanRecord>) {
    if let Some(oldest_ip) = bans
        .iter()
        .min_by_key(|(_, record)| record.expires_instant)
        .map(|(ip, _)| *ip)
    {
        bans.remove(&oldest_ip);
    }
}

/// Build the API view of one ban at `now`.
fn view_of(record: &BanRecord, now: Instant) -> BanView {
    let remaining_seconds = record
        .expires_instant
        .saturating_duration_since(now)
        .as_secs();
    BanView {
        ip: record.ip.to_string(),
        site: record.site.clone(),
        reason: record.reason.clone(),
        rule_id: record.rule_id.clone(),
        category: record.category.clone(),
        created_at: record.created_at.clone(),
        expires_at: record.expires_at.clone(),
        ttl_seconds: record.ttl_seconds,
        remaining_seconds,
        step: record.step,
    }
}

/// Whether a request carries cross-site subresource context (spec C6.5).
///
/// The brief pins the HK1 rule: `Sec-Fetch-Site: cross-site` **and** `Sec-Fetch-Dest` present and not `document`.
/// These headers are client-controlled, so this context only lowers the ladder weight; it never skips the ban
/// (review R1-6). Requests without `Sec-Fetch-*` headers (tools, scanners, curl) ban at the full weight.
#[must_use]
pub fn is_cross_site_subresource(headers: &[(String, String)]) -> bool {
    let site = util::header(headers, "sec-fetch-site");
    let destination = util::header(headers, "sec-fetch-dest");
    let is_cross_site = site.is_some_and(|value| value.trim().eq_ignore_ascii_case("cross-site"));
    let is_subresource = destination.is_some_and(|value| {
        let value = value.trim();
        !value.is_empty() && !value.eq_ignore_ascii_case("document")
    });
    is_cross_site && is_subresource
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(text: &str) -> IpAddr {
        text.parse()
            .unwrap_or(IpAddr::V4(std::net::Ipv4Addr::LOCALHOST))
    }

    #[test]
    fn bans_and_the_ladder_survive_a_restart() {
        let dir = std::env::temp_dir().join(format!("hdd-ban-persist-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        assert!(std::fs::create_dir_all(&dir).is_ok());
        let path = dir.join("bans.json");
        let ladder = [60, 600, 3600];
        {
            let store = BanStore::open(&path);
            let first = store.create(
                ip("203.0.113.9"),
                Some("shop.test"),
                "block verdict",
                Some("H1-001"),
                Some("sqli"),
                &ladder,
                BanContext::Direct,
            );
            assert_eq!(first.ttl_seconds, 60);
        }
        let reopened = BanStore::open(&path);
        let view = reopened.active(ip("203.0.113.9"));
        assert!(view.is_some(), "the ban is still active after a restart");
        assert!(view.is_some_and(|ban| ban.remaining_seconds > 0 && ban.remaining_seconds <= 60));
        let second = reopened.create(
            ip("203.0.113.9"),
            Some("shop.test"),
            "block verdict",
            Some("H1-001"),
            Some("sqli"),
            &ladder,
            BanContext::Direct,
        );
        assert_eq!(second.ttl_seconds, 600, "the offence counter survived too");
        assert!(reopened.remove(ip("203.0.113.9")));
        assert!(BanStore::open(&path).active(ip("203.0.113.9")).is_none());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn ladder_steps_grow_then_repeat_the_last_entry() {
        let ladder = [60, 600, 3600];
        assert_eq!(ladder_ttl(&ladder, 1), 60);
        assert_eq!(ladder_ttl(&ladder, 2), 600);
        assert_eq!(ladder_ttl(&ladder, 3), 3600);
        assert_eq!(ladder_ttl(&ladder, 4), 3600);
        assert_eq!(ladder_ttl(&[], 1), 60);
    }

    #[test]
    fn bans_are_active_listed_and_removable() {
        let store = BanStore::new();
        let client = ip("198.51.100.9");
        assert!(store.active(client).is_none());
        let created = store.create(
            client,
            Some("demo.test"),
            "block verdict",
            Some("H1-001"),
            Some("sqli"),
            &[60, 600],
            BanContext::Direct,
        );
        assert_eq!(created.step, 1);
        assert_eq!(created.ttl_seconds, 60);
        assert!(created.remaining_seconds <= 60);
        assert!(store.active(client).is_some());
        let listed = store.list();
        assert_eq!(listed.len(), 1);
        assert_eq!(
            listed.first().map(|ban| ban.ip.as_str()),
            Some("198.51.100.9")
        );
        assert!(store.remove(client));
        assert!(!store.remove(client));
        assert!(store.active(client).is_none());
    }

    #[test]
    fn repeated_offences_advance_the_ladder() {
        let store = BanStore::new();
        let client = ip("203.0.113.5");
        let first = store.create(
            client,
            None,
            "first",
            None,
            None,
            &[1, 2, 3],
            BanContext::Direct,
        );
        assert_eq!((first.step, first.ttl_seconds), (1, 1));
        let _ = store.remove(client);
        let second = store.create(
            client,
            None,
            "second",
            None,
            None,
            &[1, 2, 3],
            BanContext::Direct,
        );
        assert_eq!((second.step, second.ttl_seconds), (2, 2));
    }

    #[test]
    fn cross_site_context_still_bans_but_with_a_lower_ladder_weight() {
        let store = BanStore::new();
        let client = ip("198.51.100.44");
        let spoofed = store.create(
            client,
            None,
            "spoofed context",
            None,
            None,
            &[5, 6, 7],
            BanContext::CrossSite,
        );
        assert_eq!(
            (spoofed.step, spoofed.ttl_seconds),
            (1, 5),
            "a cross-site hit still creates a ban"
        );
        assert!(store.active(client).is_some());
        // A direct hit after the spoofed one escalates past the first step: the spoofed hit was counted.
        let direct = store.create(
            client,
            None,
            "direct",
            None,
            None,
            &[5, 6, 7],
            BanContext::Direct,
        );
        assert_eq!(
            (direct.step, direct.ttl_seconds),
            (2, 6),
            "direct weight (2) + cross-site weight (1) = 3 units = step 2"
        );
        // Two direct hits reach step 2 on their own (4 units).
        let store = BanStore::new();
        let other = ip("198.51.100.45");
        let first = store.create(
            other,
            None,
            "d1",
            None,
            None,
            &[5, 6, 7],
            BanContext::Direct,
        );
        assert_eq!(first.step, 1);
        let second = store.create(
            other,
            None,
            "d2",
            None,
            None,
            &[5, 6, 7],
            BanContext::Direct,
        );
        assert_eq!(second.step, 2);
    }

    #[test]
    fn ipv6_bans_are_keyed_per_64() {
        let store = BanStore::new();
        let member = ip("2001:db8:1:2:aaaa::1");
        let neighbour = ip("2001:db8:1:2:bbbb::9");
        let elsewhere = ip("2001:db8:1:3:aaaa::1");
        assert_eq!(
            ban_key(member).to_string(),
            "2001:db8:1:2::",
            "IPv6 ban keys are the /64 network"
        );
        let created = store.create(member, None, "ipv6", None, None, &[60], BanContext::Direct);
        assert_eq!(created.ip, "2001:db8:1:2::");
        assert!(store.active(neighbour).is_some(), "same /64 is covered");
        assert!(
            store.active(elsewhere).is_none(),
            "another /64 is not covered"
        );
        assert!(store.remove(neighbour), "removal uses the /64 key");
        assert!(store.active(member).is_none());
        assert_eq!(
            ban_key(ip("198.51.100.7")).to_string(),
            "198.51.100.7",
            "IPv4 keys stay /32"
        );
    }

    #[test]
    fn prune_drops_expired_bans_and_quiet_offences() {
        let store = BanStore::new();
        let client = ip("192.0.2.90");
        let _ = store.create(
            client,
            None,
            "ttl zero",
            None,
            None,
            &[0],
            BanContext::Direct,
        );
        std::thread::sleep(Duration::from_millis(5));
        // The expired ban disappears through the explicit prune path too (the background timer calls this).
        store.prune();
        assert!(store.list().is_empty());
        // An offence entry quiet for longer than the decay window is pruned; a fresh one is kept.
        let now = Instant::now();
        let old = Offence {
            units: 4,
            last: now
                .checked_sub(QUIET_DECAY + Duration::from_secs(1))
                .unwrap_or(now),
        };
        let fresh = Offence {
            units: 2,
            last: now,
        };
        assert!(offence_is_expired(&old, now));
        assert!(!offence_is_expired(&fresh, now));
    }

    #[test]
    fn expired_bans_disappear() {
        let store = BanStore::new();
        let client = ip("192.0.2.77");
        let created = store.create(client, None, "short", None, None, &[0], BanContext::Direct);
        assert_eq!(created.ttl_seconds, 0);
        std::thread::sleep(Duration::from_millis(5));
        assert!(store.active(client).is_none());
        assert!(store.list().is_empty());
        assert_eq!(store.active_count(), 0);
    }

    #[test]
    fn cross_site_subresource_context_is_detected() {
        let cross_image = vec![
            ("Sec-Fetch-Site".to_owned(), "cross-site".to_owned()),
            ("Sec-Fetch-Dest".to_owned(), "image".to_owned()),
        ];
        assert!(is_cross_site_subresource(&cross_image));
        let document = vec![
            ("Sec-Fetch-Site".to_owned(), "cross-site".to_owned()),
            ("Sec-Fetch-Dest".to_owned(), "document".to_owned()),
        ];
        assert!(!is_cross_site_subresource(&document));
        let no_headers: Vec<(String, String)> = Vec::new();
        assert!(!is_cross_site_subresource(&no_headers));
        let same_site = vec![
            ("Sec-Fetch-Site".to_owned(), "same-site".to_owned()),
            ("Sec-Fetch-Dest".to_owned(), "image".to_owned()),
        ];
        assert!(!is_cross_site_subresource(&same_site));
    }
}
