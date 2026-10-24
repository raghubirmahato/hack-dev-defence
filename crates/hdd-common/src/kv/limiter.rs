//! `Limiter`: rate limiting over any [`KvStore`] (C18.3). One call checks up to [`MAX_SCOPES`] keys (for example the same client
//! by IP, by session and globally) and answers with the most restrictive result. Scopes are checked in the order given and the
//! check **stops at the first denial**: a client that is already over its own limit must not use up a shared budget (the site or
//! the whole platform) that other clients depend on. Scopes checked before the denial have recorded the attempt; put the most
//! specific scope (the client) first and the shared ones after it.

use std::sync::Arc;
use std::time::Duration;

use super::rate::{Algorithm, RateDecision, RateRequest};
use super::{KvError, KvResult, KvStore};

/// Most scopes one call may check.
pub const MAX_SCOPES: usize = 4;

/// Rate limiter over a store.
pub struct Limiter<K: KvStore> {
    kv: Arc<K>,
}

impl<K: KvStore> Clone for Limiter<K> {
    fn clone(&self) -> Self {
        Limiter {
            kv: Arc::clone(&self.kv),
        }
    }
}

impl<K: KvStore> Limiter<K> {
    /// A limiter over `kv`.
    pub fn new(kv: Arc<K>) -> Limiter<K> {
        Limiter { kv }
    }

    /// Check one unit against every key.
    pub async fn check(
        &self,
        keys: &[&str],
        limit: u32,
        window: Duration,
        algorithm: Algorithm,
    ) -> KvResult<RateDecision> {
        self.check_request(keys, &RateRequest::new(limit, window, algorithm))
            .await
    }

    /// Check a request (with its cost) against every key.
    pub async fn check_request(&self, keys: &[&str], req: &RateRequest) -> KvResult<RateDecision> {
        if keys.is_empty() {
            return Err(KvError::InvalidArgument("at least one key is required"));
        }
        if keys.len() > MAX_SCOPES {
            return Err(KvError::TooManyScopes { got: keys.len() });
        }
        req.validate()?;
        let mut all_allowed = true;
        let mut remaining = u32::MAX;
        let mut reset_denied = 0u64;
        let mut reset_all = 0u64;
        let mut violations = 0u32;
        for key in keys {
            let d = self.kv.rate_window_check(key, req).await?;
            all_allowed &= d.allowed;
            remaining = remaining.min(d.remaining);
            reset_all = reset_all.max(d.reset_ms);
            if !d.allowed {
                reset_denied = reset_denied.max(d.reset_ms);
            }
            violations = violations.max(d.violations);
            if !d.allowed {
                break;
            }
        }
        Ok(RateDecision {
            allowed: all_allowed,
            remaining,
            reset_ms: if all_allowed { reset_all } else { reset_denied },
            violations,
        })
    }
}
