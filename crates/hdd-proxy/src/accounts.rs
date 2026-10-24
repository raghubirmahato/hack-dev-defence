//! Accounts, sessions, script API tokens and the first-run onboarding store (COLLAB.md Addendum 2).
//!
//! One owner/viewer account model over a single local JSON file in an owner-only data directory. Passwords are hashed
//! with argon2id (PHC string), verified in constant time by the `argon2`/`password-hash` crates, and never written or
//! logged in clear. Session cookies and API tokens are random 256-bit values; only their SHA-256 hash is persisted, so
//! stealing the file does not hand over a working credential. Every write goes through an atomic temp-file + rename.
//!
//! The store is also the account-numbering boundary for the admin API: [`AccountStore::authenticate`] is the only
//! place a request becomes a [`Principal`], and it enforces the 8-hour idle expiry and slides the last-seen time.

use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

use argon2::{Argon2, PasswordHasher, PasswordVerifier};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::api::{
    self, AccountView, ApiRequest, Principal, Role, SessionView, SessionViewBody,
    TokenCreateResponse, TokenView, UserView,
};

/// The idle timeout of a session: eight hours without a request and the cookie stops working.
pub const SESSION_IDLE_SECONDS: u64 = 8 * 60 * 60;
/// The absolute lifetime of a session: a session older than this is rejected even if it was just used.
pub const SESSION_ABSOLUTE_SECONDS: u64 = 24 * 60 * 60;
/// Failed logins allowed inside the window before a client is locked out.
pub const MAX_LOGIN_FAILURES: u32 = 5;
/// The window for counting failed logins, in seconds.
pub const LOGIN_WINDOW_SECONDS: u64 = 60;
/// How long a client is locked out after too many failed logins.
pub const LOGIN_LOCKOUT_SECONDS: u64 = 60;
/// The maximum number of client addresses kept in the login-failure map; older entries are pruned.
pub const MAX_LOCKOUT_ENTRIES: usize = 4096;
/// The minimum length of a username.
pub const MIN_USERNAME_LEN: usize = 3;
/// The maximum length of a username.
pub const MAX_USERNAME_LEN: usize = 32;
/// The maximum length of an email address.
pub const MAX_EMAIL_LEN: usize = 254;
/// The maximum length of an API-token label.
pub const MAX_TOKEN_NAME_LEN: usize = 80;

const STORE_FILE: &str = "accounts.json";
const STORE_VERSION: u32 = 1;

/// The outcome of a login attempt. The caller turns this into the public response; the password is never returned.
#[derive(Debug)]
pub(crate) enum LoginOutcome {
    /// The password matched and a session was created; the value is the cookie handle.
    Success {
        /// The random cookie handle to put in `Set-Cookie` (only its hash is stored).
        session_handle: String,
        /// The authenticated principal.
        principal: Principal,
        /// The account email (part of the login response body).
        email: String,
    },
    /// The username does not exist or the password is wrong; deliberately indistinguishable.
    InvalidCredentials,
    /// Too many recent failures from this client address.
    LockedOut {
        /// Seconds until the lockout expires.
        retry_after_seconds: u64,
    },
    /// A storage or randomness failure (HTTP 500, never an authentication success).
    Internal(String),
}

/// An error from a store operation, mapped to the public API by `accounts_api`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum StoreError {
    /// The input is invalid (HTTP 400).
    BadRequest(String),
    /// The caller is not authenticated or the current password is wrong (HTTP 401).
    Unauthorized,
    /// The caller's role is read-only (HTTP 403).
    Forbidden(String),
    /// The target does not exist (HTTP 404).
    NotFound,
    /// The operation conflicts with the current state (HTTP 409).
    Conflict(String),
    /// A storage, hashing or randomness failure (HTTP 500).
    Internal(String),
}

impl StoreError {
    fn internal(message: impl Into<String>) -> Self {
        Self::Internal(message.into())
    }
}

impl std::fmt::Display for StoreError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::BadRequest(message)
            | Self::Forbidden(message)
            | Self::Conflict(message)
            | Self::Internal(message) => formatter.write_str(message),
            Self::Unauthorized => formatter.write_str("authentication required"),
            Self::NotFound => formatter.write_str("not found"),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct StoredUser {
    id: String,
    username: String,
    email: String,
    password_hash: String,
    role: Role,
    created_unix: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct StoredSession {
    id: String,
    token_hash: String,
    user_id: String,
    created_unix: u64,
    last_seen_unix: u64,
    ip: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct StoredToken {
    id: String,
    user_id: String,
    name: String,
    token_hash: String,
    created_unix: u64,
    last_used_unix: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct StoreFile {
    version: u32,
    users: Vec<StoredUser>,
    sessions: Vec<StoredSession>,
    tokens: Vec<StoredToken>,
}

impl Default for StoreFile {
    fn default() -> Self {
        Self {
            version: STORE_VERSION,
            users: Vec::new(),
            sessions: Vec::new(),
            tokens: Vec::new(),
        }
    }
}

#[derive(Debug, Clone, Default)]
struct FailureState {
    window_start: u64,
    count: u32,
    locked_until: u64,
}

/// The account store: the only writer of the local account file.
///
/// Construct it once per process with [`AccountStore::load`] and share the `Arc` with the admin server. All methods are
/// synchronous and short; password hashing is the longest operation and happens outside any caller-visible lock.
pub struct AccountStore {
    store_path: PathBuf,
    inner: Mutex<StoreFile>,
    failures: Mutex<HashMap<String, FailureState>>,
    dummy_hash: String,
}

impl AccountStore {
    /// Open (or create) the account store in `data_dir`.
    ///
    /// The directory is created with owner-only permissions where the platform supports it, and the JSON file is
    /// created with `0600`. A corrupt file is reported as an error instead of being silently reset (that would be a
    /// silent loss of the owner account, R-19).
    ///
    /// # Errors
    /// Returns a human message when the directory cannot be created, an existing store cannot be read or parsed, or the
    /// random source or password hasher fails.
    pub fn load(data_dir: &Path) -> Result<Arc<AccountStore>, String> {
        ensure_owner_only_dir(data_dir)?;
        let store_path = data_dir.join(STORE_FILE);
        let store = if store_path.exists() {
            let bytes = fs::read(&store_path)
                .map_err(|error| format!("cannot read {}: {error}", store_path.display()))?;
            let parsed: StoreFile = serde_json::from_slice(&bytes).map_err(|error| {
                format!(
                    "{} is not a valid account store: {error}",
                    store_path.display()
                )
            })?;
            parsed
        } else {
            let empty = StoreFile::default();
            let bytes = serde_json::to_vec_pretty(&empty)
                .map_err(|error| format!("cannot serialise the empty account store: {error}"))?;
            write_store_file(&store_path, &bytes)?;
            empty
        };
        // A dummy hash makes "unknown username" take the same time as "wrong password" (R-20, enumeration-safe).
        let dummy_password = random_hex::<16>().map_err(|error| error.to_string())?;
        let dummy_hash = hash_password(&dummy_password).map_err(|error| error.to_string())?;
        Ok(Arc::new(Self {
            store_path,
            inner: Mutex::new(store),
            failures: Mutex::new(HashMap::new()),
            dummy_hash,
        }))
    }

    /// Whether the first-run setup wizard is open (no account exists yet).
    #[must_use]
    pub fn setup_required(&self) -> bool {
        self.inner
            .lock()
            .map(|store| store.users.is_empty())
            .unwrap_or(false)
    }

    /// Authenticate a request by its `hdd_session` cookie or its `Authorization: Bearer hdd_...` API token.
    ///
    /// A session is removed and does not authenticate when it has been idle for [`SESSION_IDLE_SECONDS`] (8 h) or when
    /// it is older than [`SESSION_ABSOLUTE_SECONDS`] (24 h) even if it was used a moment ago. A valid session or token
    /// slides its last-seen / last-used timestamp. `None` always means "not authenticated"; the reason is never revealed.
    #[must_use]
    pub fn authenticate(&self, req: &ApiRequest) -> Option<Principal> {
        if let Some(handle) = cookie_value(req, api::SESSION_COOKIE) {
            return self.authenticate_session(handle);
        }
        if let Some(token) = bearer_token(req) {
            return self.authenticate_token(&token);
        }
        None
    }

    /// Convenience alias for the module-level [`reset_password`] (the CLI wiring may call either form).
    ///
    /// # Errors
    /// See [`reset_password`].
    pub fn reset_password(data_dir: &Path, username: &str) -> Result<String, String> {
        crate::accounts::reset_password(data_dir, username)
    }

    // ------------------------------------------------------------------ authentication helpers

    fn authenticate_session(&self, handle: &str) -> Option<Principal> {
        let token_hash = sha256_hex(handle.as_bytes());
        let now = now_unix();
        let mut store = self.inner.lock().ok()?;
        let index = store
            .sessions
            .iter()
            .position(|session| session.token_hash == token_hash)?;
        let session = store.sessions.get(index)?.clone();
        let idle_expired = now.saturating_sub(session.last_seen_unix) >= SESSION_IDLE_SECONDS;
        let absolutely_expired =
            now.saturating_sub(session.created_unix) >= SESSION_ABSOLUTE_SECONDS;
        if idle_expired || absolutely_expired {
            store.sessions.remove(index);
            let _ = self.save(&store);
            return None;
        }
        let user = store
            .users
            .iter()
            .find(|user| user.id == session.user_id)?
            .clone();
        if let Some(stored) = store.sessions.get_mut(index) {
            stored.last_seen_unix = now;
        }
        let _ = self.save(&store);
        Some(Principal {
            user_id: user.id,
            username: user.username,
            role: user.role,
        })
    }

    fn authenticate_token(&self, token: &str) -> Option<Principal> {
        if !token.starts_with(api::API_TOKEN_PREFIX) {
            return None;
        }
        let token_hash = sha256_hex(token.as_bytes());
        let now = now_unix();
        let mut store = self.inner.lock().ok()?;
        let index = store
            .tokens
            .iter()
            .position(|stored| stored.token_hash == token_hash)?;
        let user_id = store.tokens.get(index)?.user_id.clone();
        let user = store
            .users
            .iter()
            .find(|candidate| candidate.id == user_id)?
            .clone();
        if let Some(stored) = store.tokens.get_mut(index) {
            stored.last_used_unix = Some(now);
        }
        let _ = self.save(&store);
        Some(Principal {
            user_id: user.id,
            username: user.username,
            role: user.role,
        })
    }

    // ------------------------------------------------------------------ login / logout

    pub(crate) fn login(&self, username: &str, password: &str, client_ip: &str) -> LoginOutcome {
        let now = now_unix();
        if let Some(retry_after_seconds) = self.locked_out_seconds(client_ip, now) {
            return LoginOutcome::LockedOut {
                retry_after_seconds,
            };
        }
        let user = match self.find_user_by_name(username) {
            Ok(user) => user,
            Err(error) => return LoginOutcome::Internal(error.to_string()),
        };
        let password_matches = match &user {
            Some(found) => verify_password(password, &found.password_hash),
            None => {
                // Equalise the timing for an unknown username: verify against a throwaway hash.
                let _ = verify_password(password, &self.dummy_hash);
                false
            }
        };
        if !password_matches {
            if let Err(error) = self.record_failure(client_ip, now) {
                return LoginOutcome::Internal(error.to_string());
            }
            return LoginOutcome::InvalidCredentials;
        }
        let Some(found) = user else {
            return LoginOutcome::InvalidCredentials;
        };
        if let Err(error) = self.record_success(client_ip) {
            return LoginOutcome::Internal(error.to_string());
        }
        match self.create_session(&found, client_ip, now) {
            Ok(session_handle) => LoginOutcome::Success {
                session_handle,
                principal: Principal {
                    user_id: found.id,
                    username: found.username,
                    role: found.role,
                },
                email: found.email,
            },
            Err(error) => LoginOutcome::Internal(error.to_string()),
        }
    }

    pub(crate) fn logout(&self, req: &ApiRequest) -> Result<(), StoreError> {
        let Some(handle) = cookie_value(req, api::SESSION_COOKIE) else {
            return Ok(());
        };
        let token_hash = sha256_hex(handle.as_bytes());
        let mut store = self.data()?;
        store
            .sessions
            .retain(|session| session.token_hash != token_hash);
        self.save(&store)
    }

    fn create_session(
        &self,
        user: &StoredUser,
        client_ip: &str,
        now: u64,
    ) -> Result<String, StoreError> {
        let handle = random_hex::<32>()?;
        let id = random_hex::<8>()?;
        let token_hash = sha256_hex(handle.as_bytes());
        let mut store = self.data()?;
        store.sessions.push(StoredSession {
            id,
            token_hash,
            user_id: user.id.clone(),
            created_unix: now,
            last_seen_unix: now,
            ip: client_ip.to_owned(),
        });
        self.save(&store)?;
        Ok(handle)
    }

    fn find_user_by_name(&self, username: &str) -> Result<Option<StoredUser>, StoreError> {
        let store = self.data()?;
        Ok(store
            .users
            .iter()
            .find(|user| user.username.eq_ignore_ascii_case(username.trim()))
            .cloned())
    }

    fn locked_out_seconds(&self, client_ip: &str, now: u64) -> Option<u64> {
        let failures = self.failures.lock().ok()?;
        let state = failures.get(client_ip)?;
        if state.locked_until > now {
            Some(state.locked_until.saturating_sub(now))
        } else {
            None
        }
    }

    fn record_failure(&self, client_ip: &str, now: u64) -> Result<(), StoreError> {
        let mut failures = self
            .failures
            .lock()
            .map_err(|_| StoreError::internal("the login rate-limit lock was poisoned"))?;
        let state = failures.entry(client_ip.to_owned()).or_default();
        if now.saturating_sub(state.window_start) > LOGIN_WINDOW_SECONDS {
            *state = FailureState {
                window_start: now,
                count: 0,
                locked_until: 0,
            };
        }
        state.count = state.count.saturating_add(1);
        if state.count >= MAX_LOGIN_FAILURES {
            state.locked_until = now.saturating_add(LOGIN_LOCKOUT_SECONDS);
            state.count = 0;
            state.window_start = now;
        }
        // The map is bounded (HK1 review round 1 LOW): prune entries that can no longer affect a decision, then
        // evict the oldest non-locked entries if unrelated spoofed addresses filled it. An active lockout is kept.
        if failures.len() > MAX_LOCKOUT_ENTRIES {
            failures.retain(|_, entry| {
                entry.locked_until > now
                    || now.saturating_sub(entry.window_start) <= LOGIN_WINDOW_SECONDS
            });
            while failures.len() > MAX_LOCKOUT_ENTRIES {
                let candidate = failures
                    .iter()
                    .filter(|(_, entry)| entry.locked_until <= now)
                    .min_by_key(|(_, entry)| entry.window_start)
                    .map(|(client_ip, _)| client_ip.clone())
                    .or_else(|| {
                        failures
                            .iter()
                            .min_by_key(|(_, entry)| entry.locked_until)
                            .map(|(client_ip, _)| client_ip.clone())
                    });
                let Some(candidate) = candidate else {
                    break;
                };
                failures.remove(&candidate);
            }
        }
        Ok(())
    }

    fn record_success(&self, client_ip: &str) -> Result<(), StoreError> {
        let mut failures = self
            .failures
            .lock()
            .map_err(|_| StoreError::internal("the login rate-limit lock was poisoned"))?;
        failures.remove(client_ip);
        Ok(())
    }

    // ------------------------------------------------------------------ first-run setup

    pub(crate) fn create_owner(
        &self,
        username: &str,
        email: &str,
        password: &str,
    ) -> Result<(), StoreError> {
        let username = username.trim();
        validate_username(username)?;
        validate_email(email)?;
        validate_password(username, password)?;
        let password_hash = hash_password(password)?;
        let mut store = self.data()?;
        if !store.users.is_empty() {
            return Err(StoreError::Conflict(
                "the owner account already exists".to_owned(),
            ));
        }
        store.users.push(StoredUser {
            id: random_hex::<8>()?,
            username: username.to_owned(),
            email: email.trim().to_owned(),
            password_hash,
            role: Role::Owner,
            created_unix: now_unix(),
        });
        self.save(&store)
    }

    // ------------------------------------------------------------------ account page

    pub(crate) fn session_view_body(&self, principal: &Principal) -> Option<SessionViewBody> {
        let store = self.inner.lock().ok()?;
        let user = store
            .users
            .iter()
            .find(|user| user.id == principal.user_id)?;
        Some(SessionViewBody {
            username: user.username.clone(),
            role: user.role,
            email: user.email.clone(),
        })
    }

    pub(crate) fn account_view(
        &self,
        principal: &Principal,
        req: &ApiRequest,
    ) -> Option<AccountView> {
        let store = self.inner.lock().ok()?;
        let user = store
            .users
            .iter()
            .find(|user| user.id == principal.user_id)?;
        let current_hash =
            cookie_value(req, api::SESSION_COOKIE).map(|handle| sha256_hex(handle.as_bytes()));
        Some(AccountView {
            username: user.username.clone(),
            email: user.email.clone(),
            role: user.role,
            created_at: rfc3339(user.created_unix),
            sessions: sessions_for(&store, &principal.user_id, current_hash.as_deref()),
            tokens: tokens_for(&store, &principal.user_id),
        })
    }

    pub(crate) fn sessions(
        &self,
        principal: &Principal,
        req: &ApiRequest,
    ) -> Result<Vec<SessionView>, StoreError> {
        let store = self.data()?;
        let current_hash =
            cookie_value(req, api::SESSION_COOKIE).map(|handle| sha256_hex(handle.as_bytes()));
        Ok(sessions_for(
            &store,
            &principal.user_id,
            current_hash.as_deref(),
        ))
    }

    pub(crate) fn tokens(&self, principal: &Principal) -> Result<Vec<TokenView>, StoreError> {
        let store = self.data()?;
        Ok(tokens_for(&store, &principal.user_id))
    }

    pub(crate) fn change_password(
        &self,
        principal: &Principal,
        current_password: &str,
        new_password: &str,
        req: &ApiRequest,
    ) -> Result<(), StoreError> {
        validate_password(&principal.username, new_password)?;
        let new_hash = hash_password(new_password)?;
        let mut store = self.data()?;
        let index = store
            .users
            .iter()
            .position(|user| user.id == principal.user_id)
            .ok_or(StoreError::Unauthorized)?;
        let stored_hash = store
            .users
            .get(index)
            .map(|user| user.password_hash.clone())
            .ok_or(StoreError::Unauthorized)?;
        if !verify_password(current_password, &stored_hash) {
            return Err(StoreError::Unauthorized);
        }
        if let Some(user) = store.users.get_mut(index) {
            user.password_hash = new_hash;
        }
        // Other sessions must not survive a password change; the session that made the change stays usable.
        let current_hash =
            cookie_value(req, api::SESSION_COOKIE).map(|handle| sha256_hex(handle.as_bytes()));
        store.sessions.retain(|session| {
            session.user_id != principal.user_id
                || Some(&session.token_hash) == current_hash.as_ref()
        });
        self.save(&store)
    }

    pub(crate) fn change_email(
        &self,
        principal: &Principal,
        password: &str,
        email: &str,
    ) -> Result<(), StoreError> {
        validate_email(email)?;
        let mut store = self.data()?;
        let index = store
            .users
            .iter()
            .position(|user| user.id == principal.user_id)
            .ok_or(StoreError::Unauthorized)?;
        let stored_hash = store
            .users
            .get(index)
            .map(|user| user.password_hash.clone())
            .ok_or(StoreError::Unauthorized)?;
        if !verify_password(password, &stored_hash) {
            return Err(StoreError::Unauthorized);
        }
        if let Some(user) = store.users.get_mut(index) {
            user.email = email.trim().to_owned();
        }
        self.save(&store)
    }

    pub(crate) fn revoke_session(&self, principal: &Principal, id: &str) -> Result<(), StoreError> {
        let mut store = self.data()?;
        let before = store.sessions.len();
        store
            .sessions
            .retain(|session| !(session.id == id && session.user_id == principal.user_id));
        if store.sessions.len() == before {
            return Err(StoreError::NotFound);
        }
        self.save(&store)
    }

    pub(crate) fn create_token(
        &self,
        principal: &Principal,
        name: &str,
    ) -> Result<TokenCreateResponse, StoreError> {
        let name = name.trim();
        if name.is_empty() {
            return Err(StoreError::BadRequest(
                "the token label must not be empty".to_owned(),
            ));
        }
        if name.len() > MAX_TOKEN_NAME_LEN {
            return Err(StoreError::BadRequest(format!(
                "the token label must be at most {MAX_TOKEN_NAME_LEN} characters"
            )));
        }
        let token = format!("{}{}", api::API_TOKEN_PREFIX, random_hex::<32>()?);
        let token_hash = sha256_hex(token.as_bytes());
        let id = random_hex::<8>()?;
        let created_unix = now_unix();
        let mut store = self.data()?;
        store.tokens.push(StoredToken {
            id: id.clone(),
            user_id: principal.user_id.clone(),
            name: name.to_owned(),
            token_hash,
            created_unix,
            last_used_unix: None,
        });
        self.save(&store)?;
        Ok(TokenCreateResponse {
            token,
            view: TokenView {
                id,
                name: name.to_owned(),
                created_at: rfc3339(created_unix),
                last_used_at: None,
            },
        })
    }

    pub(crate) fn revoke_token(&self, principal: &Principal, id: &str) -> Result<(), StoreError> {
        let mut store = self.data()?;
        let before = store.tokens.len();
        store
            .tokens
            .retain(|token| !(token.id == id && token.user_id == principal.user_id));
        if store.tokens.len() == before {
            return Err(StoreError::NotFound);
        }
        self.save(&store)
    }

    // ------------------------------------------------------------------ users (owner only)

    pub(crate) fn users(&self, principal: &Principal) -> Result<Vec<UserView>, StoreError> {
        require_owner(principal)?;
        let store = self.data()?;
        Ok(store
            .users
            .iter()
            .map(|user| UserView {
                id: user.id.clone(),
                username: user.username.clone(),
                email: user.email.clone(),
                role: user.role,
                created_at: rfc3339(user.created_unix),
            })
            .collect())
    }

    pub(crate) fn create_user(
        &self,
        principal: &Principal,
        username: &str,
        email: &str,
        password: &str,
        role: Role,
    ) -> Result<UserView, StoreError> {
        require_owner(principal)?;
        let username = username.trim();
        validate_username(username)?;
        validate_email(email)?;
        validate_password(username, password)?;
        let password_hash = hash_password(password)?;
        let mut store = self.data()?;
        if store
            .users
            .iter()
            .any(|user| user.username.eq_ignore_ascii_case(username))
        {
            return Err(StoreError::Conflict(
                "that username already exists".to_owned(),
            ));
        }
        let id = random_hex::<8>()?;
        let created_unix = now_unix();
        store.users.push(StoredUser {
            id: id.clone(),
            username: username.to_owned(),
            email: email.trim().to_owned(),
            password_hash,
            role,
            created_unix,
        });
        self.save(&store)?;
        Ok(UserView {
            id,
            username: username.to_owned(),
            email: email.trim().to_owned(),
            role,
            created_at: rfc3339(created_unix),
        })
    }

    pub(crate) fn set_role(
        &self,
        principal: &Principal,
        id: &str,
        role: Role,
    ) -> Result<(), StoreError> {
        require_owner(principal)?;
        let mut store = self.data()?;
        let index = store
            .users
            .iter()
            .position(|user| user.id == id)
            .ok_or(StoreError::NotFound)?;
        let current = store
            .users
            .get(index)
            .map(|user| user.role)
            .ok_or(StoreError::NotFound)?;
        if current == Role::Owner && role == Role::Viewer && owner_count(&store) <= 1 {
            return Err(StoreError::Conflict(
                "the last owner cannot be demoted: promote another owner first".to_owned(),
            ));
        }
        if let Some(user) = store.users.get_mut(index) {
            user.role = role;
        }
        self.save(&store)
    }

    pub(crate) fn delete_user(
        &self,
        principal: &Principal,
        id: &str,
        confirmation: &str,
    ) -> Result<(), StoreError> {
        require_owner(principal)?;
        let mut store = self.data()?;
        let index = store
            .users
            .iter()
            .position(|user| user.id == id)
            .ok_or(StoreError::NotFound)?;
        let target = store
            .users
            .get(index)
            .cloned()
            .ok_or(StoreError::NotFound)?;
        if target.username != confirmation.trim() {
            return Err(StoreError::BadRequest(
                "type the exact username to confirm deleting the account".to_owned(),
            ));
        }
        if target.role == Role::Owner && owner_count(&store) <= 1 {
            return Err(StoreError::Conflict(
                "the last owner cannot be removed: promote another owner first".to_owned(),
            ));
        }
        store.users.remove(index);
        store
            .sessions
            .retain(|session| session.user_id != target.id);
        store.tokens.retain(|token| token.user_id != target.id);
        self.save(&store)
    }

    // ------------------------------------------------------------------ reset password

    fn generate_and_store_password(&self, username: &str) -> Result<String, StoreError> {
        let password = generate_password(username)?;
        let password_hash = hash_password(&password)?;
        let mut store = self.data()?;
        let index = store
            .users
            .iter()
            .position(|user| user.username.eq_ignore_ascii_case(username.trim()))
            .ok_or(StoreError::NotFound)?;
        let user_id = store
            .users
            .get(index)
            .map(|user| user.id.clone())
            .ok_or(StoreError::NotFound)?;
        if let Some(user) = store.users.get_mut(index) {
            user.password_hash = password_hash;
        }
        store.sessions.retain(|session| session.user_id != user_id);
        store.tokens.retain(|token| token.user_id != user_id);
        self.save(&store)?;
        Ok(password)
    }

    // ------------------------------------------------------------------ persistence helpers

    fn data(&self) -> Result<std::sync::MutexGuard<'_, StoreFile>, StoreError> {
        self.inner
            .lock()
            .map_err(|_| StoreError::internal("the account store lock was poisoned"))
    }

    fn save(&self, store: &StoreFile) -> Result<(), StoreError> {
        let bytes = serde_json::to_vec_pretty(store).map_err(|error| {
            StoreError::internal(format!("cannot serialise the account store: {error}"))
        })?;
        write_store_file(&self.store_path, &bytes).map_err(StoreError::Internal)
    }
}

/// Reset a user's password offline (the `hdd-proxy admin reset-password <user>` command).
///
/// Returns a freshly generated one-time password for the terminal. Every session and API token of that user is revoked,
/// so a forgotten or leaked credential cannot stay valid. This is a free function on purpose: the CLI opens the same
/// owner-only data directory as the server, without an admin session.
///
/// # Errors
/// Returns a human message when the store cannot be loaded, the user does not exist or the write fails.
pub fn reset_password(data_dir: &Path, username: &str) -> Result<String, String> {
    let store = AccountStore::load(data_dir)?;
    store
        .generate_and_store_password(username)
        .map_err(|error| error.to_string())
}

fn sessions_for(store: &StoreFile, user_id: &str, current_hash: Option<&str>) -> Vec<SessionView> {
    store
        .sessions
        .iter()
        .filter(|session| session.user_id == user_id)
        .map(|session| SessionView {
            id: session.id.clone(),
            created_at: rfc3339(session.created_unix),
            last_seen_at: rfc3339(session.last_seen_unix),
            ip: session.ip.clone(),
            current: current_hash.is_some_and(|hash| hash == session.token_hash),
        })
        .collect()
}

fn tokens_for(store: &StoreFile, user_id: &str) -> Vec<TokenView> {
    store
        .tokens
        .iter()
        .filter(|token| token.user_id == user_id)
        .map(|token| TokenView {
            id: token.id.clone(),
            name: token.name.clone(),
            created_at: rfc3339(token.created_unix),
            last_used_at: token.last_used_unix.map(rfc3339),
        })
        .collect()
}

fn owner_count(store: &StoreFile) -> usize {
    store
        .users
        .iter()
        .filter(|user| user.role == Role::Owner)
        .count()
}

fn require_owner(principal: &Principal) -> Result<(), StoreError> {
    if principal.role.can_mutate() {
        Ok(())
    } else {
        Err(StoreError::Forbidden(
            "the viewer role is read-only".to_owned(),
        ))
    }
}

fn validate_username(username: &str) -> Result<(), StoreError> {
    if username.len() < MIN_USERNAME_LEN {
        return Err(StoreError::BadRequest(format!(
            "the username must be at least {MIN_USERNAME_LEN} characters"
        )));
    }
    if username.len() > MAX_USERNAME_LEN {
        return Err(StoreError::BadRequest(format!(
            "the username must be at most {MAX_USERNAME_LEN} characters"
        )));
    }
    let first = username
        .chars()
        .next()
        .ok_or_else(|| StoreError::BadRequest("the username is empty".to_owned()))?;
    if !first.is_ascii_alphanumeric() {
        return Err(StoreError::BadRequest(
            "the username must start with a letter or digit".to_owned(),
        ));
    }
    if !username
        .chars()
        .all(|character| character.is_ascii_alphanumeric() || matches!(character, '.' | '_' | '-'))
    {
        return Err(StoreError::BadRequest(
            "the username may only contain letters, digits, '.', '_' and '-'".to_owned(),
        ));
    }
    Ok(())
}

fn validate_email(email: &str) -> Result<(), StoreError> {
    let email = email.trim();
    if email.is_empty() || email.len() > MAX_EMAIL_LEN {
        return Err(StoreError::BadRequest(
            "enter a valid email address".to_owned(),
        ));
    }
    if email
        .chars()
        .any(|character| character.is_whitespace() || character.is_control())
    {
        return Err(StoreError::BadRequest(
            "enter a valid email address".to_owned(),
        ));
    }
    let Some((local, domain)) = email.split_once('@') else {
        return Err(StoreError::BadRequest(
            "enter a valid email address".to_owned(),
        ));
    };
    if local.is_empty() || domain.is_empty() || !domain.contains('.') {
        return Err(StoreError::BadRequest(
            "enter a valid email address".to_owned(),
        ));
    }
    if domain.starts_with('.') || domain.ends_with('.') || local.contains('@') {
        return Err(StoreError::BadRequest(
            "enter a valid email address".to_owned(),
        ));
    }
    Ok(())
}

fn validate_password(username: &str, password: &str) -> Result<(), StoreError> {
    if password.len() < api::MIN_PASSWORD_LEN {
        return Err(StoreError::BadRequest(format!(
            "the password must be at least {} characters",
            api::MIN_PASSWORD_LEN
        )));
    }
    if password.len() > 1024 {
        return Err(StoreError::BadRequest(
            "the password is too long".to_owned(),
        ));
    }
    let classes = [
        password
            .chars()
            .any(|character| character.is_ascii_lowercase()),
        password
            .chars()
            .any(|character| character.is_ascii_uppercase()),
        password.chars().any(|character| character.is_ascii_digit()),
        password
            .chars()
            .any(|character| !character.is_ascii_alphanumeric() && !character.is_whitespace()),
    ]
    .iter()
    .filter(|present| **present)
    .count();
    if classes < 3 {
        return Err(StoreError::BadRequest(
            "the password must mix at least three of: lower case, upper case, digits and symbols"
                .to_owned(),
        ));
    }
    if !username.trim().is_empty() {
        let lowered = password.to_lowercase();
        if lowered.contains(&username.trim().to_lowercase()) {
            return Err(StoreError::BadRequest(
                "the password must not contain the username".to_owned(),
            ));
        }
    }
    let lowered = password.to_lowercase();
    for weak in [
        "password",
        "letmein12345",
        "123456789012",
        "qwertyuiop12",
        "adminadmin12",
    ] {
        if lowered == weak {
            return Err(StoreError::BadRequest(
                "the password is too common; choose something unique".to_owned(),
            ));
        }
    }
    Ok(())
}

fn generate_password(username: &str) -> Result<String, StoreError> {
    const UPPER: &str = "ABCDEFGHJKLMNPQRSTUVWXYZ";
    const LOWER: &str = "abcdefghijkmnopqrstuvwxyz";
    const DIGITS: &str = "23456789";
    const SYMBOLS: &str = "!@#$%^&*-_=+";
    const ALPHABETS: [&str; 4] = [UPPER, LOWER, DIGITS, SYMBOLS];
    for _attempt in 0..32 {
        let mut characters: Vec<char> = Vec::with_capacity(24);
        for alphabet in ALPHABETS {
            let index = random_index(alphabet.chars().count())?;
            let character = alphabet
                .chars()
                .nth(index)
                .ok_or_else(|| StoreError::internal("password alphabet indexing failed"))?;
            characters.push(character);
        }
        let target_len = 24;
        while characters.len() < target_len {
            let alphabet = ALPHABETS
                .get(random_index(ALPHABETS.len())?)
                .ok_or_else(|| StoreError::internal("password alphabet indexing failed"))?;
            let index = random_index(alphabet.chars().count())?;
            let character = alphabet
                .chars()
                .nth(index)
                .ok_or_else(|| StoreError::internal("password alphabet indexing failed"))?;
            characters.push(character);
        }
        let shuffle_len = characters.len();
        for left in 0..shuffle_len.saturating_sub(1) {
            let right = random_index(shuffle_len)?;
            characters.swap(left, right);
        }
        let candidate: String = characters.into_iter().collect();
        if validate_password(username, &candidate).is_ok() {
            return Ok(candidate);
        }
    }
    Err(StoreError::internal(
        "could not generate a strong one-time password from the system random source",
    ))
}

fn random_index(bound: usize) -> Result<usize, StoreError> {
    if bound == 0 {
        return Err(StoreError::internal("random index with an empty range"));
    }
    let value = getrandom::u32().map_err(|error| {
        StoreError::internal(format!("the system random source failed: {error}"))
    })?;
    Ok((value as usize) % bound)
}

fn random_bytes<const N: usize>() -> Result<[u8; N], StoreError> {
    let mut bytes = [0u8; N];
    getrandom::fill(&mut bytes).map_err(|error| {
        StoreError::internal(format!("the system random source failed: {error}"))
    })?;
    Ok(bytes)
}

fn random_hex<const N: usize>() -> Result<String, StoreError> {
    let bytes = random_bytes::<N>()?;
    Ok(hex_encode(&bytes))
}

fn hex_encode(bytes: &[u8]) -> String {
    let mut encoded = String::with_capacity(bytes.len().saturating_mul(2));
    for byte in bytes {
        encoded.push_str(&format!("{byte:02x}"));
    }
    encoded
}

fn sha256_hex(value: &[u8]) -> String {
    let digest = Sha256::digest(value);
    hex_encode(digest.as_ref())
}

fn hash_password(password: &str) -> Result<String, StoreError> {
    Argon2::default()
        .hash_password(password.as_bytes())
        .map(|hash| hash.to_string())
        .map_err(|error| StoreError::internal(format!("argon2id hashing failed: {error}")))
}

fn verify_password(password: &str, password_hash: &str) -> bool {
    Argon2::default()
        .verify_password(password.as_bytes(), password_hash)
        .is_ok()
}

fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or(0)
}

/// Format a Unix timestamp as RFC 3339 UTC (`YYYY-MM-DDTHH:MM:SSZ`).
fn rfc3339(unix_seconds: u64) -> String {
    let days = (unix_seconds / 86_400) as i64;
    let seconds_of_day = (unix_seconds % 86_400) as u32;
    let (year, month, day) = civil_from_days(days);
    format!(
        "{year:04}-{month:02}-{day:02}T{:02}:{:02}:{:02}Z",
        seconds_of_day / 3600,
        (seconds_of_day % 3600) / 60,
        seconds_of_day % 60
    )
}

/// Convert days since 1970-01-01 to a civil date (Howard Hinnant's algorithm, proleptic Gregorian).
fn civil_from_days(days_since_epoch: i64) -> (i64, u32, u32) {
    let shifted = days_since_epoch + 719_468;
    let era = if shifted >= 0 {
        shifted
    } else {
        shifted - 146_096
    } / 146_097;
    let day_of_era = shifted - era * 146_097;
    let year_of_era =
        (day_of_era - day_of_era / 1_460 + day_of_era / 36_524 - day_of_era / 146_096) / 365;
    let year = year_of_era + era * 400;
    let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    let month_prime = (5 * day_of_year + 2) / 153;
    let day = day_of_year - (153 * month_prime + 2) / 5 + 1;
    let month = if month_prime < 10 {
        month_prime + 3
    } else {
        month_prime - 9
    };
    let civil_year = if month <= 2 { year + 1 } else { year };
    (civil_year, month as u32, day as u32)
}

fn cookie_value<'a>(req: &'a ApiRequest, cookie_name: &str) -> Option<&'a str> {
    for (name, value) in &req.headers {
        if !name.eq_ignore_ascii_case("cookie") {
            continue;
        }
        for part in value.split(';') {
            let part = part.trim();
            if let Some((candidate_name, candidate_value)) = part.split_once('=')
                && candidate_name.trim() == cookie_name
            {
                let candidate_value = candidate_value.trim();
                if !candidate_value.is_empty() {
                    return Some(candidate_value);
                }
            }
        }
    }
    None
}

fn bearer_token(req: &ApiRequest) -> Option<String> {
    let header = req.header("authorization")?;
    let (scheme, token) = header.split_once(' ')?;
    if !scheme.eq_ignore_ascii_case("bearer") {
        return None;
    }
    let token = token.trim();
    if token.is_empty() {
        None
    } else {
        Some(token.to_owned())
    }
}

fn ensure_owner_only_dir(path: &Path) -> Result<(), String> {
    fs::create_dir_all(path).map_err(|error| {
        format!(
            "cannot create the data directory {}: {error}",
            path.display()
        )
    })?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o700)).map_err(|error| {
            format!(
                "cannot restrict the data directory {}: {error}",
                path.display()
            )
        })?;
    }
    Ok(())
}

fn write_store_file(path: &Path, bytes: &[u8]) -> Result<(), String> {
    let temporary = path.with_extension("json.tmp");
    {
        let mut file = open_owner_only(&temporary)?;
        std::io::Write::write_all(&mut file, bytes)
            .map_err(|error| format!("cannot write {}: {error}", temporary.display()))?;
        file.sync_all()
            .map_err(|error| format!("cannot flush {}: {error}", temporary.display()))?;
    }
    fs::rename(&temporary, path).map_err(|error| {
        format!(
            "cannot replace {} with the updated account store: {error}",
            path.display()
        )
    })
}

#[cfg(unix)]
fn open_owner_only(path: &Path) -> Result<fs::File, String> {
    use std::os::unix::fs::OpenOptionsExt;
    fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(path)
        .map_err(|error| format!("cannot open {}: {error}", path.display()))
}

#[cfg(not(unix))]
fn open_owner_only(path: &Path) -> Result<fs::File, String> {
    fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .open(path)
        .map_err(|error| format!("cannot open {}: {error}", path.display()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rfc3339_formats_known_instants() {
        assert_eq!(rfc3339(0), "1970-01-01T00:00:00Z");
        assert_eq!(rfc3339(1_700_000_000), "2023-11-14T22:13:20Z");
    }

    #[test]
    fn password_validation_rejects_weak_secrets() {
        assert!(validate_password("owner", "short").is_err());
        assert!(validate_password("owner", "onlylettersnolonger").is_err());
        assert!(validate_password("owner", "Owner-Passw0rd!").is_err());
        assert!(validate_password("owner", "Correct-Horse-9!").is_ok());
    }

    #[test]
    fn emails_and_usernames_are_validated() {
        assert!(validate_email("owner@example.com").is_ok());
        assert!(validate_email("not-an-email").is_err());
        assert!(validate_email("a@b").is_err());
        assert!(validate_username("owner").is_ok());
        assert!(validate_username("owner name").is_err());
        assert!(validate_username("o").is_err());
    }

    #[test]
    fn a_generated_one_time_password_passes_the_strength_check() {
        let password = generate_password("owner");
        assert!(password.is_ok());
        if let Ok(value) = password {
            assert!(validate_password("owner", &value).is_ok());
            assert!(value.len() >= api::MIN_PASSWORD_LEN);
        }
    }

    #[test]
    fn hashes_are_argon2id_phc_strings_that_verify() {
        let hash = hash_password("Correct-Horse-9!");
        assert!(hash.is_ok());
        if let Ok(value) = hash {
            assert!(value.starts_with("$argon2id$"));
            assert!(verify_password("Correct-Horse-9!", &value));
            assert!(!verify_password("wrong", &value));
        }
    }

    #[test]
    fn the_login_failure_map_is_bounded_while_lockouts_still_work() {
        // HK1 review round 1 LOW: the per-IP failure map was unbounded. The cap is asserted through the real
        // `record_failure` path (not a direct field write) so pruning and lockout retention are both exercised.
        const EXPECTED_LOCKOUT_CAP: usize = 4096;
        let dir = std::env::temp_dir().join(format!(
            "hdd-accounts-throttle-{}-{}",
            std::process::id(),
            now_unix()
        ));
        let store = AccountStore::load(&dir).expect("the account store loads in a temp directory");
        let now = now_unix();

        for _ in 0..MAX_LOGIN_FAILURES {
            store
                .record_failure("10.0.0.1", now)
                .expect("a failed login is recorded");
        }
        assert!(
            store.locked_out_seconds("10.0.0.1", now).is_some(),
            "five failures lock the client out before pruning is involved"
        );

        for index in 0..(EXPECTED_LOCKOUT_CAP * 2) {
            let client_ip = format!("198.18.{}.{}", index / 256, index % 256);
            store
                .record_failure(&client_ip, now)
                .expect("a failed login is recorded");
        }
        let tracked = store
            .failures
            .lock()
            .map(|failures| failures.len())
            .unwrap_or(0);
        assert!(
            tracked <= EXPECTED_LOCKOUT_CAP,
            "the per-IP failure map must stay bounded, tracked {tracked} entries"
        );
        assert!(
            store.locked_out_seconds("10.0.0.1", now).is_some(),
            "an active lockout must survive pruning of unrelated addresses"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }
}
