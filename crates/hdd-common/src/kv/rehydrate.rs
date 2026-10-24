//! The restart contract of C18.3: `MemoryKv` starts empty, and everything durable must be rebuilt from Postgres before listeners
//! open. [`rehydrate`] loads bans, offences and sessions from a [`DurableSource`] into any [`KvStore`] and reports how many rows
//! it loaded and how long it took (`hdd_kv_rehydrate_rows`, `hdd_kv_rehydrate_seconds`, registered in
//! `docs/registries/ADDITIONS.md`).
//!
//! Non-durable state (rate counters, challenge nonces, campaign sets, flow counters) is not rehydrated: it resets on restart,
//! which only forgives and never blocks.
//!
//! **Idempotent and safe against live state.** A key that already exists is left alone (and counted in
//! [`RehydrateReport::already_present`]): against a shared Redis that other processes are writing, a second start must not add
//! offences to a live counter or overwrite the score of a ban that was extended after the database row was written.

use std::future::Future;
use std::time::{Duration, Instant};

use super::keys::BANNED_IPS;
use super::{KvError, KvResult, KvStore};

/// Largest offence count the contract rebuilds (a ladder has a handful of steps).
pub const MAX_OFFENCE_COUNT: u32 = 1000;

/// One durable row, already mapped to its store key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DurableRow {
    /// An `ip_bans` row.
    Ban {
        /// The detail hash key (`hdd:ban:...`).
        key: String,
        /// Member of the `hdd:banned_ips` zset.
        member: String,
        /// Hash fields of the detail.
        fields: Vec<(String, Vec<u8>)>,
        /// When the ban ends, in unix milliseconds.
        expires_unix_ms: i64,
    },
    /// A `ban_offences` row.
    Offence {
        /// The counter key (`hdd:offence:...`).
        key: String,
        /// Count at the last offence.
        count: u32,
        /// Time of the last offence, unix milliseconds.
        last_unix_ms: i64,
        /// One step of the count is forgiven per `decay`.
        decay: Duration,
        /// How long the counter lives after the last offence.
        ttl: Duration,
    },
    /// A `user_sessions` row.
    Session {
        /// The session hash key (`hdd:sess:...` or `hdd:gate:sess:...`).
        key: String,
        /// Hash fields.
        fields: Vec<(String, Vec<u8>)>,
        /// When the session ends, unix milliseconds.
        expires_unix_ms: i64,
    },
}

/// Where the durable rows come from (Postgres in production, a fixture in tests).
pub trait DurableSource: Send + Sync {
    /// All rows that may still matter.
    fn load(&self) -> impl Future<Output = Result<Vec<DurableRow>, String>> + Send;
}

/// What a rehydration did.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct RehydrateReport {
    /// Bans loaded.
    pub bans: usize,
    /// Offence counters loaded.
    pub offences: usize,
    /// Sessions loaded.
    pub sessions: usize,
    /// Rows skipped because they had already expired.
    pub skipped_expired: usize,
    /// Rows skipped because the store already holds the key (another process wrote it, or this is a second call).
    pub already_present: usize,
    /// Time taken.
    pub elapsed: Duration,
}

impl RehydrateReport {
    /// Rows loaded in total (`hdd_kv_rehydrate_rows`).
    pub fn rows(&self) -> usize {
        self.bans + self.offences + self.sessions
    }

    /// Prometheus text for the two metrics.
    pub fn render_prometheus(&self) -> String {
        format!(
            "# TYPE hdd_kv_rehydrate_rows gauge\nhdd_kv_rehydrate_rows{{kind=\"ban\"}} {}\nhdd_kv_rehydrate_rows{{kind=\"offence\"}} {}\nhdd_kv_rehydrate_rows{{kind=\"session\"}} {}\n# TYPE hdd_kv_rehydrate_seconds gauge\nhdd_kv_rehydrate_seconds {}\n",
            self.bans,
            self.offences,
            self.sessions,
            self.elapsed.as_secs_f64()
        )
    }
}

fn remaining(expires_unix_ms: i64, now_unix_ms: i64) -> Option<Duration> {
    let ms = expires_unix_ms.checked_sub(now_unix_ms)?;
    u64::try_from(ms)
        .ok()
        .filter(|m| *m > 0)
        .map(Duration::from_millis)
}

/// Rebuild the durable state of `kv` from `source`. Rows that have already expired are skipped. A pinned namespace that is too
/// small for the rows fails the whole call with [`KvError::PinnedFull`], so a start-up never silently drops bans.
pub async fn rehydrate<K: KvStore>(
    kv: &K,
    source: &impl DurableSource,
    now_unix_ms: i64,
) -> KvResult<RehydrateReport> {
    let start = Instant::now();
    let rows = source.load().await.map_err(KvError::Backend)?;
    let mut report = RehydrateReport::default();
    for row in rows {
        match row {
            DurableRow::Ban {
                key,
                member,
                fields,
                expires_unix_ms,
            } => {
                let Some(left) = remaining(expires_unix_ms, now_unix_ms) else {
                    report.skipped_expired += 1;
                    continue;
                };
                if kv.exists(&key).await? {
                    report.already_present += 1;
                    continue;
                }
                for (field, value) in &fields {
                    kv.hset(&key, field, value, Some(left)).await?;
                }
                kv.zadd(BANNED_IPS, expires_unix_ms as f64, &member, None)
                    .await?;
                report.bans += 1;
            }
            DurableRow::Offence {
                key,
                count,
                last_unix_ms,
                decay,
                ttl,
            } => {
                let age_ms = u64::try_from(now_unix_ms.saturating_sub(last_unix_ms)).unwrap_or(0);
                let Some(left) = ttl
                    .checked_sub(Duration::from_millis(age_ms))
                    .filter(|d| !d.is_zero())
                else {
                    report.skipped_expired += 1;
                    continue;
                };
                let steps = age_ms
                    .checked_div(u64::try_from(decay.as_millis()).unwrap_or(u64::MAX).max(1))
                    .unwrap_or(0);
                let now_count = u64::from(count.min(MAX_OFFENCE_COUNT)).saturating_sub(steps);
                if now_count == 0 {
                    report.skipped_expired += 1;
                    continue;
                }
                if kv.exists(&key).await? {
                    report.already_present += 1;
                    continue;
                }
                // Rebuild the count with the store's own operation; a decay longer than the load makes the increments exact.
                for _ in 0..now_count {
                    kv.offence_incr_with_decay(&key, Duration::from_secs(365 * 24 * 3600), left)
                        .await?;
                }
                report.offences += 1;
            }
            DurableRow::Session {
                key,
                fields,
                expires_unix_ms,
            } => {
                let Some(left) = remaining(expires_unix_ms, now_unix_ms) else {
                    report.skipped_expired += 1;
                    continue;
                };
                if kv.exists(&key).await? {
                    report.already_present += 1;
                    continue;
                }
                for (field, value) in &fields {
                    kv.hset(&key, field, value, Some(left)).await?;
                }
                report.sessions += 1;
            }
        }
    }
    report.elapsed = start.elapsed();
    Ok(report)
}
