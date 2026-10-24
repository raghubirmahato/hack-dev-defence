//! `RedisKv` and `RedisBus`: the hosted backend of the store traits on `redis-rs` (ADR-0028) (T-0562 step 2).
//!
//! **Verification status: UNVERIFIED(environment_unsupported) on a builder without Redis.** This code compiles and its pure parts
//! (URL policy, circuit breaker, script arguments) are unit-tested, but the Lua scripts and the pub/sub pump have not run
//! against a server here. The shared conformance suite (`tests/kv_redis.rs`, `cargo xtask verify` step `kv-redis`) runs them as
//! soon as `HDD_TEST_REDIS_URL` points at a Redis 7 or newer server.
//!
//! * **Security.** The URL must use `rediss://` (TLS, rustls with the ring provider) and carry credentials; plain `redis://`
//!   is accepted only for a loopback host and only when the caller says so (tests). The URL is never logged or returned in an
//!   error. All named operations are single Lua scripts, so each is atomic on the server.
//! * **Scripts.** Loaded on first use, called with `EVALSHA`, reloaded when the server answers `NOSCRIPT`. Timestamps are
//!   written with `%.0f` (Lua 5.1 would print 16-digit integers in exponent form), and all integer arithmetic is on values below
//!   2^50 so that doubles are exact (the request validation enforces `limit * window < 2^50`).
//! * **Time.** Rate decisions use the server clock (`TIME`) unless a [`Clock`] is supplied (tests).
//! * **Circuit breaker.** Five consecutive connection failures open the breaker for one second; then one probe is let through
//!   (half-open). While open, calls fail at once with a backend error instead of queueing.
//! * **Redis 7 or newer** is required (`HC-15`).

use std::collections::{BTreeMap, BTreeSet};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;

use ::redis::aio::{ConnectionManager, ConnectionManagerConfig};
use ::redis::{Client, PushKind, Script, Value};
use tokio::sync::mpsc;

use super::bus::{Bus, Source, Subscription};
use super::clock::{Clock, SystemClock};
use super::rate::{RateDecision, RateRequest};
use super::{KvError, KvResult, KvStore, MAX_FLOW_SIGNALS, MAX_MEMBERS, check_key, check_value};

/// Connection settings.
#[derive(Clone)]
pub struct RedisConfig {
    url: String,
    allow_insecure_loopback: bool,
}

impl std::fmt::Debug for RedisConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RedisConfig")
            .field("url", &"<redacted>")
            .field("allow_insecure_loopback", &self.allow_insecure_loopback)
            .finish()
    }
}

/// Split a connection URL (scheme, optional credentials, host, optional port and database) into `(scheme, has_password, host)`
/// without echoing any part.
fn parse_url(url: &str) -> Option<(&str, bool, &str)> {
    let (scheme, rest) = url.split_once("://")?;
    let authority = rest.split(['/', '?']).next()?;
    let (userinfo, hostport) = match authority.rsplit_once('@') {
        Some((u, h)) => (Some(u), h),
        None => (None, authority),
    };
    let has_password = userinfo
        .and_then(|u| u.split_once(':').map(|(_, p)| p))
        .is_some_and(|p| !p.is_empty());
    let host = if let Some(stripped) = hostport.strip_prefix('[') {
        stripped.split(']').next()?
    } else {
        hostport.split(':').next()?
    };
    Some((scheme, has_password, host))
}

impl RedisConfig {
    /// Validate the URL against the policy: `rediss://` with a password.
    pub fn new(url: &str) -> KvResult<RedisConfig> {
        let (scheme, has_password, host) = parse_url(url).ok_or(KvError::InvalidArgument(
            "the redis url is not a scheme, optional credentials, a host and an optional port",
        ))?;
        if host.is_empty() {
            return Err(KvError::InvalidArgument("the redis url has no host"));
        }
        if scheme != "rediss" {
            return Err(KvError::InvalidArgument(
                "the redis url must use rediss:// (TLS is required)",
            ));
        }
        if !has_password {
            return Err(KvError::InvalidArgument(
                "the redis url must carry a password (authentication is required)",
            ));
        }
        Ok(RedisConfig {
            url: url.to_owned(),
            allow_insecure_loopback: false,
        })
    }

    /// For tests against a local server: `redis://` without credentials, accepted only for `localhost`, `127.0.0.1` or `::1`.
    pub fn insecure_loopback_for_tests(url: &str) -> KvResult<RedisConfig> {
        let (scheme, _, host) = parse_url(url).ok_or(KvError::InvalidArgument(
            "the redis url is not scheme://host[:port]",
        ))?;
        if !matches!(scheme, "redis" | "rediss")
            || !matches!(host, "localhost" | "127.0.0.1" | "::1")
        {
            return Err(KvError::InvalidArgument(
                "insecure connections are allowed to a loopback host only",
            ));
        }
        Ok(RedisConfig {
            url: url.to_owned(),
            allow_insecure_loopback: true,
        })
    }

    /// True when this configuration skips the TLS and password policy (loopback tests).
    pub fn is_insecure_loopback(&self) -> bool {
        self.allow_insecure_loopback
    }
}

// ---------------------------------------------------------------------------------------------------------------------
// Circuit breaker

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum BreakerState {
    Closed {
        failures: u32,
    },
    Open {
        until_us: u64,
    },
    /// A probe is in flight since this time; if it never reports (the future was dropped) another one is allowed after the
    /// cooldown.
    HalfOpen {
        since_us: u64,
    },
}

/// Circuit breaker with half-open probes.
pub struct Breaker {
    state: Mutex<BreakerState>,
    threshold: u32,
    cooldown_us: u64,
    clock: Arc<dyn Clock>,
}

impl Breaker {
    /// Open after `threshold` consecutive failures, probe again after `cooldown`.
    pub fn new(threshold: u32, cooldown: Duration, clock: Arc<dyn Clock>) -> Breaker {
        Breaker {
            state: Mutex::new(BreakerState::Closed { failures: 0 }),
            threshold: threshold.max(1),
            cooldown_us: u64::try_from(cooldown.as_micros()).unwrap_or(u64::MAX),
            clock,
        }
    }

    /// May a call go to the backend now? Exactly one caller gets the half-open probe.
    pub fn allow(&self) -> bool {
        let mut s = self.state.lock().unwrap_or_else(PoisonError::into_inner);
        match *s {
            BreakerState::Closed { .. } => true,
            BreakerState::Open { until_us } => {
                let now = self.clock.now_us();
                if now >= until_us {
                    *s = BreakerState::HalfOpen { since_us: now };
                    true
                } else {
                    false
                }
            }
            BreakerState::HalfOpen { since_us } => {
                // a probe that never reported (its future was dropped) must not lock the breaker forever
                let now = self.clock.now_us();
                if now >= since_us.saturating_add(self.cooldown_us) {
                    *s = BreakerState::HalfOpen { since_us: now };
                    true
                } else {
                    false
                }
            }
        }
    }

    /// The call reached the backend and got an answer.
    pub fn success(&self) {
        *self.state.lock().unwrap_or_else(PoisonError::into_inner) =
            BreakerState::Closed { failures: 0 };
    }

    /// The call failed because the backend could not be reached or answered with a connection-level error.
    pub fn failure(&self) {
        let mut s = self.state.lock().unwrap_or_else(PoisonError::into_inner);
        let open = BreakerState::Open {
            until_us: self.clock.now_us().saturating_add(self.cooldown_us),
        };
        *s = match *s {
            BreakerState::Closed { failures } if failures + 1 >= self.threshold => open,
            BreakerState::Closed { failures } => BreakerState::Closed {
                failures: failures + 1,
            },
            BreakerState::HalfOpen { .. } | BreakerState::Open { .. } => open,
        };
    }

    /// True while calls are being refused.
    pub fn is_open(&self) -> bool {
        matches!(
            *self.state.lock().unwrap_or_else(PoisonError::into_inner),
            BreakerState::Open { .. } | BreakerState::HalfOpen { .. }
        )
    }
}

// ---------------------------------------------------------------------------------------------------------------------
// Scripts

const LUA_GET: &str = "return redis.call('GET', KEYS[1])";
const LUA_SET: &str = "
redis.call('SET', KEYS[1], ARGV[1])
if tonumber(ARGV[2]) > 0 then redis.call('PEXPIRE', KEYS[1], ARGV[2]) end
return 1";
const LUA_DEL: &str = "return redis.call('DEL', KEYS[1])";
const LUA_EXISTS: &str = "return redis.call('EXISTS', KEYS[1])";
const LUA_EXPIRE: &str = "return redis.call('PEXPIRE', KEYS[1], ARGV[1])";
const LUA_TTL: &str = "return redis.call('PTTL', KEYS[1])";
const LUA_INCR: &str = "
local created = redis.call('EXISTS', KEYS[1]) == 0
local n = redis.call('INCRBY', KEYS[1], ARGV[1])
if created and tonumber(ARGV[2]) > 0 then redis.call('PEXPIRE', KEYS[1], ARGV[2]) end
return n";
const LUA_HSET: &str = "
local created = redis.call('EXISTS', KEYS[1]) == 0
if redis.call('HEXISTS', KEYS[1], ARGV[1]) == 0 and redis.call('HLEN', KEYS[1]) >= tonumber(ARGV[4]) then return redis.error_reply('COLLECTIONFULL') end
redis.call('HSET', KEYS[1], ARGV[1], ARGV[2])
if created and tonumber(ARGV[3]) > 0 then redis.call('PEXPIRE', KEYS[1], ARGV[3]) end
return 1";
const LUA_HGET: &str = "return redis.call('HGET', KEYS[1], ARGV[1])";
const LUA_HGETALL: &str = "return redis.call('HGETALL', KEYS[1])";
const LUA_ZADD: &str = "
local created = redis.call('EXISTS', KEYS[1]) == 0
if not redis.call('ZSCORE', KEYS[1], ARGV[2]) and redis.call('ZCARD', KEYS[1]) >= tonumber(ARGV[4]) then return redis.error_reply('COLLECTIONFULL') end
local added = redis.call('ZADD', KEYS[1], ARGV[1], ARGV[2])
if created and tonumber(ARGV[3]) > 0 then redis.call('PEXPIRE', KEYS[1], ARGV[3]) end
return added";
const LUA_ZRANGE: &str = "return redis.call('ZRANGEBYSCORE', KEYS[1], ARGV[1], ARGV[2], 'WITHSCORES', 'LIMIT', 0, ARGV[3])";
const LUA_ZREM: &str = "return redis.call('ZREM', KEYS[1], ARGV[1])";
const LUA_ZCARD: &str = "return redis.call('ZCARD', KEYS[1])";
const LUA_SADD: &str = "
local created = redis.call('EXISTS', KEYS[1]) == 0
if redis.call('SISMEMBER', KEYS[1], ARGV[1]) == 0 and redis.call('SCARD', KEYS[1]) >= tonumber(ARGV[3]) then return redis.error_reply('COLLECTIONFULL') end
local added = redis.call('SADD', KEYS[1], ARGV[1])
if created and tonumber(ARGV[2]) > 0 then redis.call('PEXPIRE', KEYS[1], ARGV[2]) end
return added";
const LUA_SMEMBERS: &str = "return redis.call('SMEMBERS', KEYS[1])";
const LUA_CAS: &str = "
local cur = redis.call('GET', KEYS[1])
if ARGV[1] == '0' then
  if cur ~= false then return 0 end
else
  if cur == false or cur ~= ARGV[2] then return 0 end
end
redis.call('SET', KEYS[1], ARGV[3])
if tonumber(ARGV[4]) > 0 then redis.call('PEXPIRE', KEYS[1], ARGV[4]) end
return 1";
const LUA_NONCE: &str = "
local v = redis.call('GET', KEYS[1])
if v == false then return false end
redis.call('DEL', KEYS[1])
return v";
const LUA_OFFENCE: &str = "
local now = tonumber(ARGV[1])
if now == nil then local t = redis.call('TIME'); now = tonumber(t[1]) * 1000000 + tonumber(t[2]) end
local decay = tonumber(ARGV[2])
local h = redis.call('HMGET', KEYS[1], 'c', 'l')
local count = tonumber(h[1]) or 0
local last = tonumber(h[2]) or now
local d = now - last
if d < 0 then d = 0 end
local steps = (d - math.fmod(d, decay)) / decay
count = count - steps
if count < 0 then count = 0 end
count = count + 1
redis.call('HSET', KEYS[1], 'c', string.format('%.0f', count), 'l', string.format('%.0f', now))
redis.call('PEXPIRE', KEYS[1], ARGV[3])
return count";
const LUA_FLOW: &str = "
local created = redis.call('EXISTS', KEYS[1]) == 0
if redis.call('HEXISTS', KEYS[1], ARGV[1]) == 0 and redis.call('HLEN', KEYS[1]) >= tonumber(ARGV[3]) then return redis.error_reply('COLLECTIONFULL') end
redis.call('HINCRBY', KEYS[1], ARGV[1], 1)
if created then redis.call('PEXPIRE', KEYS[1], ARGV[2]) end
return redis.call('HGETALL', KEYS[1])";
const LUA_PUBLISH: &str = "
local rev = redis.call('INCR', KEYS[1])
redis.call('PUBLISH', ARGV[1], rev .. ':' .. ARGV[2])
return rev";

/// The rate-limit script: the same arithmetic as `rate.rs`, in integer microseconds.
const LUA_RATE: &str = "
local algo = ARGV[1]
local limit = tonumber(ARGV[2])
local w = tonumber(ARGV[3])
local cost = tonumber(ARGV[4])
local now = tonumber(ARGV[5])
if now == nil then local t = redis.call('TIME'); now = tonumber(t[1]) * 1000000 + tonumber(t[2]) end
local function fmt(x) return string.format('%.0f', x) end
local function imod(a, b) return math.fmod(a, b) end
local function idiv(a, b) return (a - math.fmod(a, b)) / b end

local function counter_retry(prev, curr, off)
  local rest = w - off
  if limit >= cost + curr and prev > 0 then
    local b = limit - cost - curr
    local max_rest = idiv(b * w, prev)
    if max_rest < rest then
      local t = rest - max_rest
      if t < rest and t >= 1 then return t end
    end
  end
  if curr == 0 then return rest end
  if limit < cost then return rest + w end
  local b = limit - cost
  local max_rest = idiv(b * w, curr)
  if max_rest > w then max_rest = w end
  local o2 = w - max_rest
  if o2 > w then o2 = w end
  return rest + o2
end

local st = redis.call('HMGET', KEYS[1], 'a', 'v', 'vu')
if st[1] ~= false and st[1] ~= algo then
  redis.call('DEL', KEYS[1], KEYS[2])
  st = {false, false, false}
end
local viol = tonumber(st[2]) or 0
local viol_until = tonumber(st[3]) or 0
local allowed, remaining, wait, keep = false, 0, 0, 0

if algo == 'counter' then
  local c = redis.call('HMGET', KEYS[1], 'i', 'c', 'p')
  local idx = tonumber(c[1]) or 0
  local curr = tonumber(c[2]) or 0
  local prev = tonumber(c[3]) or 0
  local cur_idx = idiv(now, w)
  local off = imod(now, w)
  if idx ~= cur_idx then
    if cur_idx == idx + 1 then prev = curr else prev = 0 end
    curr = 0
    idx = cur_idx
  end
  local est = prev * (w - off) + curr * w
  local cap = limit * w
  local need = cost * w
  if est + need <= cap then
    curr = curr + cost
    allowed = true
    remaining = idiv(cap - (est + need), w)
    wait = (w - off) + w
  else
    remaining = idiv(cap - math.min(est, cap), w)
    wait = counter_retry(prev, curr, off)
  end
  redis.call('HSET', KEYS[1], 'a', algo, 'i', fmt(idx), 'c', fmt(curr), 'p', fmt(prev))
  keep = w * 2
elseif algo == 'exact' then
  local sum = tonumber(redis.call('HGET', KEYS[1], 's')) or 0
  while true do
    local head = redis.call('LINDEX', KEYS[2], 0)
    if head == false then break end
    local ts, c = string.match(head, '^(%d+):(%d+)$')
    ts = tonumber(ts)
    c = tonumber(c)
    if ts + w <= now then
      redis.call('LPOP', KEYS[2])
      sum = sum - c
    else
      break
    end
  end
  if sum + cost <= limit then
    local merged = false
    local tail = redis.call('LINDEX', KEYS[2], -1)
    if tail ~= false then
      local ts, c = string.match(tail, '^(%d+):(%d+)$')
      if tonumber(ts) == now then
        redis.call('LSET', KEYS[2], -1, fmt(now) .. ':' .. fmt(tonumber(c) + cost))
        merged = true
      end
    end
    if not merged then redis.call('RPUSH', KEYS[2], fmt(now) .. ':' .. fmt(cost)) end
    sum = sum + cost
    allowed = true
    remaining = limit - sum
    wait = w
  else
    remaining = math.max(limit - sum, 0)
    local need = sum + cost - limit
    local freed = 0
    wait = w
    local from = 0
    local found = false
    while not found do
      local entries = redis.call('LRANGE', KEYS[2], from, from + 63)
      if #entries == 0 then break end
      for _, e in ipairs(entries) do
        local ts, c = string.match(e, '^(%d+):(%d+)$')
        freed = freed + tonumber(c)
        if freed >= need then
          wait = tonumber(ts) + w - now
          found = true
          break
        end
      end
      from = from + 64
    end
    if wait < 1 then wait = 1 end
  end
  redis.call('HSET', KEYS[1], 'a', algo, 's', fmt(sum))
  keep = w
else
  local tat = tonumber(redis.call('HGET', KEYS[1], 't')) or 0
  local t = idiv(w, limit)
  if t < 1 then t = 1 end
  local cap = limit * t
  local base = math.max(tat, now)
  local backlog = (base - now) + cost * t
  if backlog <= cap then
    tat = now + backlog
    allowed = true
    remaining = idiv(cap - backlog, t)
    wait = backlog
  else
    local current = base - now
    remaining = idiv(math.max(cap - current, 0), t)
    wait = backlog - cap
    if wait < 1 then wait = 1 end
  end
  redis.call('HSET', KEYS[1], 'a', algo, 't', fmt(tat))
  keep = math.max(tat - now, 0)
end

if not allowed then
  if now >= viol_until then viol = 0 end
  viol = viol + 1
  viol_until = now + w
end
local violations = 0
if now < viol_until then violations = viol end
redis.call('HSET', KEYS[1], 'v', fmt(viol), 'vu', fmt(viol_until))
keep = math.max(keep, viol_until - now, 1)
local ttl_ms = idiv(keep + 999, 1000)
redis.call('PEXPIRE', KEYS[1], ttl_ms)
if algo == 'exact' then redis.call('PEXPIRE', KEYS[2], ttl_ms) end
local a = 0
if allowed then a = 1 end
return { a, remaining, idiv(wait + 999, 1000), violations }";

/// Script ids (index into the table of loaded digests).
#[derive(Debug, Clone, Copy)]
#[repr(usize)]
enum Sc {
    Get,
    Set,
    Del,
    Exists,
    Expire,
    Ttl,
    Incr,
    Hset,
    Hget,
    Hgetall,
    Zadd,
    Zrange,
    Zrem,
    Zcard,
    Sadd,
    Smembers,
    Cas,
    Nonce,
    Offence,
    Flow,
    Rate,
    Publish,
}

const SCRIPTS: [&str; 22] = [
    LUA_GET,
    LUA_SET,
    LUA_DEL,
    LUA_EXISTS,
    LUA_EXPIRE,
    LUA_TTL,
    LUA_INCR,
    LUA_HSET,
    LUA_HGET,
    LUA_HGETALL,
    LUA_ZADD,
    LUA_ZRANGE,
    LUA_ZREM,
    LUA_ZCARD,
    LUA_SADD,
    LUA_SMEMBERS,
    LUA_CAS,
    LUA_NONCE,
    LUA_OFFENCE,
    LUA_FLOW,
    LUA_RATE,
    LUA_PUBLISH,
];

// ---------------------------------------------------------------------------------------------------------------------
// Argument and reply helpers

/// Script arguments are byte strings (Lua converts numbers with `tonumber`, so integers travel as decimal text).
type Arg = Vec<u8>;

fn int_arg(n: i64) -> Arg {
    n.to_string().into_bytes()
}

fn ms(ttl: Option<Duration>) -> i64 {
    ttl.map_or(0, |d| {
        i64::try_from(d.as_millis().max(1)).unwrap_or(i64::MAX)
    })
}

fn reply_bytes(v: &Value) -> Option<Vec<u8>> {
    match v {
        Value::BulkString(b) => Some(b.clone()),
        Value::SimpleString(s) => Some(s.clone().into_bytes()),
        _ => None,
    }
}

fn reply_string(v: &Value) -> Option<String> {
    reply_bytes(v).map(|b| String::from_utf8_lossy(&b).into_owned())
}

fn reply_i64(v: &Value) -> KvResult<i64> {
    match v {
        Value::Int(n) => Ok(*n),
        _ => Err(KvError::Backend(
            "unexpected reply type (integer expected)".into(),
        )),
    }
}

fn reply_array(v: Value) -> Vec<Value> {
    match v {
        Value::Array(a) => a,
        _ => Vec::new(),
    }
}

fn reply_pairs(v: Value) -> KvResult<Vec<(String, Vec<u8>)>> {
    let items = reply_array(v);
    let mut out = Vec::with_capacity(items.len() / 2);
    let mut it = items.into_iter();
    while let (Some(k), Some(val)) = (it.next(), it.next()) {
        let key = reply_string(&k)
            .ok_or_else(|| KvError::Backend("unexpected reply type (field name)".into()))?;
        let value = reply_bytes(&val)
            .ok_or_else(|| KvError::Backend("unexpected reply type (field value)".into()))?;
        out.push((key, value));
    }
    Ok(out)
}

fn short(text: &str) -> String {
    text.chars().take(200).collect()
}

/// Map a client error to the store type without ever including the connection URL.
fn map_error(key: &str, e: &::redis::RedisError) -> KvError {
    let text = e.to_string();
    if e.code() == Some("WRONGTYPE")
        || text.contains("WRONGTYPE")
        || text.contains("not an integer")
    {
        KvError::WrongType {
            key: key.chars().take(64).collect(),
        }
    } else if text.contains("COLLECTIONFULL") {
        KvError::CollectionFull { cap: MAX_MEMBERS }
    } else if text.contains("overflow") {
        KvError::InvalidArgument("integer overflow")
    } else {
        KvError::Backend(short(&text))
    }
}

fn is_connection_error(e: &::redis::RedisError) -> bool {
    e.is_io_error() || e.is_connection_dropped() || e.is_connection_refusal() || e.is_timeout()
}

/// Ask for RESP3 (needed for push messages on the subscriber connection).
fn resp3_url(url: &str) -> String {
    if url.contains("protocol=") {
        url.to_owned()
    } else if url.contains('?') {
        format!("{url}&protocol=resp3")
    } else {
        format!("{url}?protocol=resp3")
    }
}

// ---------------------------------------------------------------------------------------------------------------------
// RedisKv

/// The hosted store.
pub struct RedisKv {
    conn: ConnectionManager,
    scripts: Vec<Script>,
    clock: Option<Arc<dyn Clock>>,
    breaker: Breaker,
}

impl RedisKv {
    /// Connect and wait until the server answers. The configuration has already been checked against the TLS and password
    /// policy by [`RedisConfig`].
    pub async fn connect(cfg: &RedisConfig) -> KvResult<RedisKv> {
        let client = Client::open(cfg.url.as_str())
            .map_err(|_| KvError::InvalidArgument("the redis url could not be parsed"))?;
        let conn = ConnectionManager::new(client)
            .await
            .map_err(|e| KvError::Backend(short(&e.to_string())))?;
        Ok(RedisKv {
            conn,
            scripts: SCRIPTS.iter().map(|s| Script::new(s)).collect(),
            clock: None,
            breaker: Breaker::new(5, Duration::from_secs(1), Arc::new(SystemClock::new())),
        })
    }

    /// Drive the time of rate decisions and offence decay from `clock` instead of the server (tests).
    #[must_use]
    pub fn with_clock(mut self, clock: Arc<dyn Clock>) -> RedisKv {
        self.clock = Some(clock);
        self
    }

    /// The circuit breaker (metrics, health).
    pub fn breaker(&self) -> &Breaker {
        &self.breaker
    }

    fn now_arg(&self) -> Arg {
        match &self.clock {
            Some(c) => int_arg(i64::try_from(c.now_us()).unwrap_or(i64::MAX)),
            None => Vec::new(),
        }
    }

    /// Run a script (`EVALSHA`, loaded and reloaded on `NOSCRIPT` by the client library).
    async fn call(&self, sc: Sc, keys: Vec<String>, args: Vec<Arg>) -> KvResult<Value> {
        let probe = keys.first().cloned().unwrap_or_default();
        if !self.breaker.allow() {
            return Err(KvError::Backend("circuit breaker is open".into()));
        }
        let script = self
            .scripts
            .get(sc as usize)
            .ok_or_else(|| KvError::Backend("unknown script".into()))?;
        let mut inv = script.prepare_invoke();
        for k in &keys {
            inv.key(k.as_str());
        }
        for a in &args {
            inv.arg(a.as_slice());
        }
        let mut conn = self.conn.clone();
        match inv.invoke_async::<Value>(&mut conn).await {
            Ok(v) => {
                self.breaker.success();
                Ok(v)
            }
            Err(e) => {
                if is_connection_error(&e) {
                    self.breaker.failure();
                } else {
                    self.breaker.success();
                }
                Err(map_error(&probe, &e))
            }
        }
    }
}

impl KvStore for RedisKv {
    fn backend(&self) -> &'static str {
        "redis"
    }

    async fn get(&self, key: &str) -> KvResult<Option<Vec<u8>>> {
        check_key(key)?;
        let v = self.call(Sc::Get, vec![key.to_owned()], vec![]).await?;
        Ok(reply_bytes(&v))
    }

    async fn set(&self, key: &str, value: &[u8], ttl: Option<Duration>) -> KvResult<()> {
        check_key(key)?;
        check_value(value)?;
        self.call(
            Sc::Set,
            vec![key.to_owned()],
            vec![value.to_vec(), int_arg(ms(ttl))],
        )
        .await
        .map(|_| ())
    }

    async fn del(&self, key: &str) -> KvResult<bool> {
        check_key(key)?;
        let v = self.call(Sc::Del, vec![key.to_owned()], vec![]).await?;
        Ok(reply_i64(&v)? > 0)
    }

    async fn exists(&self, key: &str) -> KvResult<bool> {
        check_key(key)?;
        let v = self.call(Sc::Exists, vec![key.to_owned()], vec![]).await?;
        Ok(reply_i64(&v)? > 0)
    }

    async fn expire(&self, key: &str, ttl: Duration) -> KvResult<bool> {
        check_key(key)?;
        let v = self
            .call(
                Sc::Expire,
                vec![key.to_owned()],
                vec![int_arg(ms(Some(ttl)))],
            )
            .await?;
        Ok(reply_i64(&v)? > 0)
    }

    async fn ttl(&self, key: &str) -> KvResult<Option<Duration>> {
        check_key(key)?;
        let v = self.call(Sc::Ttl, vec![key.to_owned()], vec![]).await?;
        let n = reply_i64(&v)?;
        Ok(u64::try_from(n).ok().map(Duration::from_millis))
    }

    async fn incr(&self, key: &str, by: i64, ttl: Option<Duration>) -> KvResult<i64> {
        check_key(key)?;
        let v = self
            .call(
                Sc::Incr,
                vec![key.to_owned()],
                vec![int_arg(by), int_arg(ms(ttl))],
            )
            .await?;
        reply_i64(&v)
    }

    async fn hset(
        &self,
        key: &str,
        field: &str,
        value: &[u8],
        ttl: Option<Duration>,
    ) -> KvResult<()> {
        check_key(key)?;
        check_key(field)?;
        check_value(value)?;
        self.call(
            Sc::Hset,
            vec![key.to_owned()],
            vec![
                field.as_bytes().to_vec(),
                value.to_vec(),
                int_arg(ms(ttl)),
                int_arg(MAX_MEMBERS as i64),
            ],
        )
        .await
        .map(|_| ())
    }

    async fn hget(&self, key: &str, field: &str) -> KvResult<Option<Vec<u8>>> {
        check_key(key)?;
        let v = self
            .call(
                Sc::Hget,
                vec![key.to_owned()],
                vec![field.as_bytes().to_vec()],
            )
            .await?;
        Ok(reply_bytes(&v))
    }

    async fn hgetall(&self, key: &str) -> KvResult<BTreeMap<String, Vec<u8>>> {
        check_key(key)?;
        let v = self.call(Sc::Hgetall, vec![key.to_owned()], vec![]).await?;
        Ok(reply_pairs(v)?.into_iter().collect())
    }

    async fn zadd(
        &self,
        key: &str,
        score: f64,
        member: &str,
        ttl: Option<Duration>,
    ) -> KvResult<bool> {
        check_key(key)?;
        check_key(member)?;
        if score.is_nan() {
            return Err(KvError::InvalidArgument("score is not a number"));
        }
        let v = self
            .call(
                Sc::Zadd,
                vec![key.to_owned()],
                vec![
                    format!("{score}").into_bytes(),
                    member.as_bytes().to_vec(),
                    int_arg(ms(ttl)),
                    int_arg(MAX_MEMBERS as i64),
                ],
            )
            .await?;
        Ok(reply_i64(&v)? > 0)
    }

    async fn zrange_by_score(
        &self,
        key: &str,
        min: f64,
        max: f64,
        limit: usize,
    ) -> KvResult<Vec<(String, f64)>> {
        check_key(key)?;
        if min.is_nan() || max.is_nan() {
            return Err(KvError::InvalidArgument("a score bound is not a number"));
        }
        let v = self
            .call(
                Sc::Zrange,
                vec![key.to_owned()],
                vec![
                    format!("{min}").into_bytes(),
                    format!("{max}").into_bytes(),
                    int_arg(i64::try_from(limit).unwrap_or(i64::MAX)),
                ],
            )
            .await?;
        reply_pairs(v)?
            .into_iter()
            .map(|(m, s)| {
                String::from_utf8_lossy(&s)
                    .parse::<f64>()
                    .map(|score| (m, score))
                    .map_err(|_| KvError::Backend("unexpected score in reply".into()))
            })
            .collect()
    }

    async fn zrem(&self, key: &str, member: &str) -> KvResult<bool> {
        check_key(key)?;
        let v = self
            .call(
                Sc::Zrem,
                vec![key.to_owned()],
                vec![member.as_bytes().to_vec()],
            )
            .await?;
        Ok(reply_i64(&v)? > 0)
    }

    async fn zcard(&self, key: &str) -> KvResult<usize> {
        check_key(key)?;
        let v = self.call(Sc::Zcard, vec![key.to_owned()], vec![]).await?;
        Ok(usize::try_from(reply_i64(&v)?).unwrap_or(0))
    }

    async fn sadd(&self, key: &str, member: &str, ttl: Option<Duration>) -> KvResult<bool> {
        check_key(key)?;
        check_key(member)?;
        let v = self
            .call(
                Sc::Sadd,
                vec![key.to_owned()],
                vec![
                    member.as_bytes().to_vec(),
                    int_arg(ms(ttl)),
                    int_arg(MAX_MEMBERS as i64),
                ],
            )
            .await?;
        Ok(reply_i64(&v)? > 0)
    }

    async fn smembers(&self, key: &str) -> KvResult<BTreeSet<String>> {
        check_key(key)?;
        let v = self
            .call(Sc::Smembers, vec![key.to_owned()], vec![])
            .await?;
        Ok(reply_array(v).iter().filter_map(reply_string).collect())
    }

    async fn compare_and_set(
        &self,
        key: &str,
        expected: Option<&[u8]>,
        new: &[u8],
        ttl: Option<Duration>,
    ) -> KvResult<bool> {
        check_key(key)?;
        check_value(new)?;
        let (flag, exp) = match expected {
            None => (b"0".to_vec(), Vec::new()),
            Some(e) => (b"1".to_vec(), e.to_vec()),
        };
        let v = self
            .call(
                Sc::Cas,
                vec![key.to_owned()],
                vec![flag, exp, new.to_vec(), int_arg(ms(ttl))],
            )
            .await?;
        Ok(reply_i64(&v)? == 1)
    }

    async fn rate_window_check(&self, key: &str, req: &RateRequest) -> KvResult<RateDecision> {
        check_key(key)?;
        req.validate()?;
        let log_key = format!("{key}:l");
        check_key(&log_key)?;
        let v = self
            .call(
                Sc::Rate,
                vec![key.to_owned(), log_key],
                vec![
                    req.algorithm.name().as_bytes().to_vec(),
                    int_arg(i64::from(req.limit)),
                    int_arg(i64::try_from(req.window_us()).unwrap_or(i64::MAX)),
                    int_arg(i64::from(req.cost)),
                    self.now_arg(),
                ],
            )
            .await?;
        let r = reply_array(v);
        let n = |i: usize| -> KvResult<i64> {
            r.get(i)
                .ok_or_else(|| KvError::Backend("short reply from the rate script".into()))
                .and_then(reply_i64)
        };
        Ok(RateDecision {
            allowed: n(0)? == 1,
            remaining: u32::try_from(n(1)?).unwrap_or(0),
            reset_ms: u64::try_from(n(2)?).unwrap_or(0),
            violations: u32::try_from(n(3)?).unwrap_or(0),
        })
    }

    async fn challenge_nonce_consume(&self, key: &str) -> KvResult<Option<Vec<u8>>> {
        check_key(key)?;
        let v = self.call(Sc::Nonce, vec![key.to_owned()], vec![]).await?;
        Ok(reply_bytes(&v))
    }

    async fn offence_incr_with_decay(
        &self,
        key: &str,
        decay: Duration,
        ttl: Duration,
    ) -> KvResult<u32> {
        check_key(key)?;
        let decay_us = i64::try_from(decay.as_micros().max(1)).unwrap_or(i64::MAX);
        let v = self
            .call(
                Sc::Offence,
                vec![key.to_owned()],
                vec![self.now_arg(), int_arg(decay_us), int_arg(ms(Some(ttl)))],
            )
            .await?;
        Ok(u32::try_from(reply_i64(&v)?).unwrap_or(u32::MAX))
    }

    async fn flow_signal_update(
        &self,
        key: &str,
        signal: &str,
        ttl: Duration,
    ) -> KvResult<BTreeMap<String, u64>> {
        check_key(key)?;
        check_key(signal)?;
        let v = self
            .call(
                Sc::Flow,
                vec![key.to_owned()],
                vec![
                    signal.as_bytes().to_vec(),
                    int_arg(ms(Some(ttl))),
                    int_arg(MAX_FLOW_SIGNALS as i64),
                ],
            )
            .await?;
        Ok(reply_pairs(v)?
            .into_iter()
            .filter_map(|(k, val)| {
                String::from_utf8_lossy(&val)
                    .parse::<u64>()
                    .ok()
                    .map(|n| (k, n))
            })
            .collect())
    }
}

// ---------------------------------------------------------------------------------------------------------------------
// RedisBus

/// A message from the pub/sub connection, before revision checking.
pub enum RawBusMessage {
    /// A message with its revision.
    Message {
        /// Revision.
        revision: u64,
        /// Payload.
        payload: Vec<u8>,
    },
    /// The connection was re-established; messages may have been lost.
    Reconnected,
}

/// Split `"<revision>:<payload>"`.
pub fn parse_wire(raw: &[u8]) -> Option<(u64, Vec<u8>)> {
    let sep = raw.iter().position(|b| *b == b':')?;
    let (rev, rest) = raw.split_at(sep);
    let revision = std::str::from_utf8(rev).ok()?.parse::<u64>().ok()?;
    Some((revision, rest.get(1..)?.to_vec()))
}

type Subscribers = Arc<Mutex<BTreeMap<String, Vec<mpsc::Sender<RawBusMessage>>>>>;

/// The hosted bus: one publisher script (revision counter and `PUBLISH` in one step) and one RESP3 subscriber connection whose
/// push messages are fanned out to bounded queues. A full queue drops the message; the subscriber then sees the revision gap.
/// The connection manager resubscribes by itself after a reconnect, and every subscriber is told to resync.
pub struct RedisBus {
    kv: Arc<RedisKv>,
    subscriber: tokio::sync::Mutex<ConnectionManager>,
    subscribers: Subscribers,
    queue: usize,
}

impl RedisBus {
    /// Connect the subscriber connection and start the pump.
    pub async fn connect(cfg: &RedisConfig, kv: Arc<RedisKv>, queue: usize) -> KvResult<RedisBus> {
        let client = Client::open(resp3_url(&cfg.url))
            .map_err(|_| KvError::InvalidArgument("the redis url could not be parsed"))?;
        let (tx, mut rx) = mpsc::unbounded_channel();
        let manager_cfg = ConnectionManagerConfig::new()
            .set_push_sender(tx)
            .set_automatic_resubscription();
        let subscriber = ConnectionManager::new_with_config(client, manager_cfg)
            .await
            .map_err(|e| KvError::Backend(short(&e.to_string())))?;
        let subscribers: Subscribers = Arc::new(Mutex::new(BTreeMap::new()));
        let fan = Arc::clone(&subscribers);
        tokio::spawn(async move {
            while let Some(push) = rx.recv().await {
                match push.kind {
                    PushKind::Message => {
                        let (Some(ch), Some(body)) = (push.data.first(), push.data.get(1)) else {
                            continue;
                        };
                        let (Some(channel), Some(raw)) = (reply_string(ch), reply_bytes(body))
                        else {
                            continue;
                        };
                        let Some((revision, payload)) = parse_wire(&raw) else {
                            continue;
                        };
                        let senders = fan
                            .lock()
                            .unwrap_or_else(PoisonError::into_inner)
                            .get(&channel)
                            .cloned()
                            .unwrap_or_default();
                        for s in senders {
                            let _ = s.try_send(RawBusMessage::Message {
                                revision,
                                payload: payload.clone(),
                            });
                        }
                    }
                    PushKind::Disconnection => {
                        let all: Vec<_> = fan
                            .lock()
                            .unwrap_or_else(PoisonError::into_inner)
                            .values()
                            .flatten()
                            .cloned()
                            .collect();
                        for s in all {
                            let _ = s.try_send(RawBusMessage::Reconnected);
                        }
                    }
                    _ => {}
                }
            }
        });
        Ok(RedisBus {
            kv,
            subscriber: tokio::sync::Mutex::new(subscriber),
            subscribers,
            queue: queue.max(1),
        })
    }

    /// Publish a raw wire message with a chosen revision, to force a gap (conformance run only).
    #[cfg(any(test, feature = "conformance"))]
    pub async fn publish_raw(&self, channel: &str, revision: u64, payload: &[u8]) -> KvResult<()> {
        let mut wire = format!("{revision}:").into_bytes();
        wire.extend_from_slice(payload);
        let mut conn = self.kv.conn.clone();
        ::redis::cmd("PUBLISH")
            .arg(channel)
            .arg(wire)
            .query_async::<i64>(&mut conn)
            .await
            .map(|_| ())
            .map_err(|e| map_error(channel, &e))
    }
}

impl Bus for RedisBus {
    async fn publish(&self, channel: &str, payload: &[u8]) -> KvResult<u64> {
        check_key(channel)?;
        check_value(payload)?;
        let rev_key = format!("hdd:rev:{channel}");
        check_key(&rev_key)?;
        let v = self
            .kv
            .call(
                Sc::Publish,
                vec![rev_key],
                vec![channel.as_bytes().to_vec(), payload.to_vec()],
            )
            .await?;
        u64::try_from(reply_i64(&v)?).map_err(|_| KvError::Backend("negative revision".into()))
    }

    async fn subscribe(&self, channel: &str) -> KvResult<Subscription> {
        check_key(channel)?;
        let (tx, rx) = mpsc::channel(self.queue);
        let first = {
            let mut map = self
                .subscribers
                .lock()
                .unwrap_or_else(PoisonError::into_inner);
            let entry = map.entry(channel.to_owned()).or_default();
            entry.retain(|s| !s.is_closed());
            let first = entry.is_empty();
            entry.push(tx);
            first
        };
        if first {
            self.subscriber
                .lock()
                .await
                .subscribe(channel)
                .await
                .map_err(|e| map_error(channel, &e))?;
        }
        Ok(Subscription::new(Source::Redis(rx)))
    }
}

#[cfg(test)]
mod tests;
#[cfg(test)]
mod tests_review;
