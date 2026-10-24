//! Key and channel names of B5.12. Every key has the `hdd:` prefix. Parts are validated so that a caller-controlled value
//! (a host name, a header) cannot contain the `:` separator and address another namespace.

use super::{KvError, KvResult, check_key};

/// Zset of platform-wide jail membership (score = expiry in unix ms).
pub const BANNED_IPS: &str = "hdd:banned_ips";
/// Pub/sub channel of configuration changes.
pub const CH_CONFIG: &str = "hdd:events:config";
/// Pub/sub channel of bans.
pub const CH_BAN: &str = "hdd:events:ban";
/// Pub/sub channel of unbans.
pub const CH_UNBAN: &str = "hdd:events:unban";
/// Pub/sub channel of notifications.
pub const CH_NOTIFY: &str = "hdd:events:notify";
/// Pub/sub channel of cache purge requests.
pub const CH_CACHE_PURGE: &str = "hdd:cache:purge";
/// Current shield state.
pub const SHIELD_STATE: &str = "hdd:shield:state";

fn part(p: &str) -> KvResult<&str> {
    if p.is_empty() || p.contains(':') || p.chars().any(|c| c.is_control() || c.is_whitespace()) {
        Err(KvError::BadKey(
            "a key part is empty or contains `:`, whitespace or a control character".into(),
        ))
    } else {
        Ok(p)
    }
}

fn build(prefix: &str, parts: &[&str]) -> KvResult<String> {
    let mut k = String::from(prefix);
    for p in parts {
        k.push(':');
        k.push_str(part(p)?);
    }
    check_key(&k)?;
    Ok(k)
}

/// `hdd:ban:{org}:{site}:{ip_key}`: ban detail (hash with TTL).
pub fn ban(org: &str, site: &str, ip_key: &str) -> KvResult<String> {
    build("hdd:ban", &[org, site, ip_key])
}

/// `hdd:ban:g:{ip_key}`: platform-wide ban (hash with TTL).
pub fn ban_global(ip_key: &str) -> KvResult<String> {
    build("hdd:ban:g", &[ip_key])
}

/// `hdd:rl:{site}:{scope}:{key}`: rate limiter state.
pub fn rate_limit(site: &str, scope: &str, key: &str) -> KvResult<String> {
    build("hdd:rl", &[site, scope, key])
}

/// `hdd:offence:{org}:{ip_key}`: progressive ban ladder.
pub fn offence(org: &str, ip_key: &str) -> KvResult<String> {
    build("hdd:offence", &[org, ip_key])
}

/// `hdd:acme:challenge:{token}`: HTTP-01 and DNS-01 values.
pub fn acme_challenge(token: &str) -> KvResult<String> {
    build("hdd:acme:challenge", &[token])
}

/// `hdd:sess:{session_hash}`: session cache (hash with TTL).
pub fn session(session_hash: &str) -> KvResult<String> {
    build("hdd:sess", &[session_hash])
}

/// `hdd:chal:nonce:{nonce}`: challenge replay protection.
pub fn challenge_nonce(nonce: &str) -> KvResult<String> {
    build("hdd:chal:nonce", &[nonce])
}

/// `hdd:cred:{site}:{user_hmac}`: per-username failure tracking.
pub fn credential_failures(site: &str, user_hmac: &str) -> KvResult<String> {
    build("hdd:cred", &[site, user_hmac])
}

/// `hdd:camp:{site}:{sig}`: rotating-IP campaign detection.
pub fn campaign(site: &str, sig: &str) -> KvResult<String> {
    build("hdd:camp", &[site, sig])
}

/// `hdd:fw:ack:{revision}`: firewall agents acknowledge a ban-set revision.
pub fn firewall_ack(revision: u64) -> KvResult<String> {
    build("hdd:fw:ack", &[&revision.to_string()])
}

/// `hdd:node:{id}:hb`: node heartbeat.
pub fn node_heartbeat(id: &str) -> KvResult<String> {
    let mut k = build("hdd:node", &[id])?;
    k.push_str(":hb");
    check_key(&k)?;
    Ok(k)
}

/// `hdd:events:{site}`: per-site live event feed channel.
pub fn site_events(site: &str) -> KvResult<String> {
    build("hdd:events", &[site])
}

/// `hdd:gate:sess:{site}:{token_hash}`: access-gate session (hash with TTL).
pub fn gate_session(site: &str, token_hash: &str) -> KvResult<String> {
    build("hdd:gate:sess", &[site, token_hash])
}

/// `hdd:flow:{site}:{flow}:{key}`: business-flow signals.
pub fn flow(site: &str, flow: &str, key: &str) -> KvResult<String> {
    build("hdd:flow", &[site, flow, key])
}

/// `hdd:lo:{ua_hash}`: loopback identity registry entry (local profile).
pub fn loopback_identity(ua_hash: &str) -> KvResult<String> {
    build("hdd:lo", &[ua_hash])
}
