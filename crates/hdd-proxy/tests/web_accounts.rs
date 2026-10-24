//! Account, session and onboarding tests for the HK1 admin surface (COLLAB.md Addendum 2).
//!
//! These are integration tests against the public `accounts` and `accounts_api` APIs: the accounts layer is exercised
//! exactly as the admin server drives it (a request in, an optional response out), so no listener is needed. Every
//! stored-file assertion reads the bytes on disk, because "no plaintext password in any file" is a requirement, not a
//! behaviour we can trust from memory.

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use serde_json::{Value, json};

use hdd_proxy::accounts::{AccountStore, reset_password};
use hdd_proxy::accounts_api;
use hdd_proxy::api::{ApiRequest, ApiResponse, Principal, Role};

static UNIQUE: AtomicU64 = AtomicU64::new(0);

const OWNER_PASSWORD: &str = "Correct-Horse-9!";
const VIEWER_PASSWORD: &str = "Teammate-Pass-9!";

fn temp_dir(tag: &str) -> PathBuf {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let n = UNIQUE.fetch_add(1, Ordering::SeqCst);
    std::env::temp_dir().join(format!("hdd-proxy-accounts-{tag}-{nanos}-{n}"))
}

fn open_store(tag: &str) -> Result<(PathBuf, Arc<AccountStore>), String> {
    let dir = temp_dir(tag);
    let store = AccountStore::load(&dir)?;
    Ok((dir, store))
}

fn request(method: &str, path: &str) -> ApiRequest {
    ApiRequest {
        method: method.to_owned(),
        path: path.to_owned(),
        query: Vec::new(),
        headers: Vec::new(),
        body: Vec::new(),
    }
}

fn json_request(method: &str, path: &str, body: &Value) -> ApiRequest {
    let mut req = request(method, path);
    req.body = serde_json::to_vec(body).unwrap_or_default();
    req
}

fn cookie_request(method: &str, path: &str, session_handle: &str) -> ApiRequest {
    let mut req = request(method, path);
    req.headers.push((
        "cookie".to_owned(),
        format!("{}={}", hdd_proxy::api::SESSION_COOKIE, session_handle),
    ));
    req
}

fn bearer_request(method: &str, path: &str, token: &str) -> ApiRequest {
    let mut req = request(method, path);
    req.headers
        .push(("authorization".to_owned(), format!("Bearer {token}")));
    req
}

fn body_value(response: &ApiResponse) -> Value {
    serde_json::from_slice(&response.body).unwrap_or(Value::Null)
}

fn set_cookie_handle(response: &ApiResponse) -> Option<String> {
    let value = response
        .headers
        .iter()
        .find(|(name, _)| name.eq_ignore_ascii_case("set-cookie"))
        .map(|(_, value)| value.as_str())?;
    let first = value.split(';').next()?;
    let (name, handle) = first.split_once('=')?;
    if name != hdd_proxy::api::SESSION_COOKIE || handle.is_empty() {
        return None;
    }
    Some(handle.to_owned())
}

fn call(
    store: &AccountStore,
    req: &ApiRequest,
    principal: Option<&Principal>,
    client_ip: &str,
    loopback: bool,
) -> Option<ApiResponse> {
    accounts_api::handle(store, req, principal, client_ip, loopback)
}

/// Create the owner account through the public setup endpoint and return the session handle.
fn do_setup(store: &AccountStore) -> Option<String> {
    let setup = json!({
        "username": "owner",
        "email": "owner@example.com",
        "password": OWNER_PASSWORD,
    });
    let req = json_request("POST", "/api/setup", &setup);
    let response = call(store, &req, None, "127.0.0.1", true)?;
    if response.status != 200 {
        return None;
    }
    set_cookie_handle(&response)
}

/// Log in and return `(status, session handle, body)`.
fn do_login(
    store: &AccountStore,
    username: &str,
    password: &str,
    client_ip: &str,
) -> (u16, Option<String>, Value) {
    let req = json_request(
        "POST",
        "/api/login",
        &json!({ "username": username, "password": password }),
    );
    match call(store, &req, None, client_ip, true) {
        Some(response) => (
            response.status,
            set_cookie_handle(&response),
            body_value(&response),
        ),
        None => (0, None, Value::Null),
    }
}

fn principal_of(store: &AccountStore, session_handle: &str) -> Option<Principal> {
    let req = cookie_request("GET", "/api/me", session_handle);
    store.authenticate(&req)
}

fn read_store_file(dir: &Path) -> Result<Vec<u8>, String> {
    std::fs::read(dir.join("accounts.json")).map_err(|error| error.to_string())
}

fn write_store_file(dir: &Path, bytes: &[u8]) -> Result<(), String> {
    std::fs::write(dir.join("accounts.json"), bytes).map_err(|error| error.to_string())
}

fn unix_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or(0)
}

/// Rewrite both session timestamps on disk, exactly as an old persisted store would look after a restart.
fn rewrite_session_times(dir: &Path, created_unix: u64, last_seen_unix: u64) -> Result<(), String> {
    let bytes = read_store_file(dir)?;
    let mut document: Value = serde_json::from_slice(&bytes).map_err(|error| error.to_string())?;
    let Some(sessions) = document.get_mut("sessions").and_then(Value::as_array_mut) else {
        return Err("the store has no sessions array".to_owned());
    };
    for session in sessions.iter_mut() {
        session["created_unix"] = json!(created_unix);
        session["last_seen_unix"] = json!(last_seen_unix);
    }
    write_store_file(
        dir,
        &serde_json::to_vec(&document).map_err(|error| error.to_string())?,
    )
}

#[test]
fn setup_is_open_once_then_returns_404() {
    let (_dir, store) = open_store("setup-once").unwrap();
    assert!(store.setup_required());

    let status_req = request("GET", "/api/setup-status");
    let status_response = call(&store, &status_req, None, "127.0.0.1", true).unwrap();
    assert_eq!(status_response.status, 200);
    assert_eq!(
        body_value(&status_response).get("setup_required"),
        Some(&json!(true))
    );

    let handle = do_setup(&store).expect("first-run setup creates the owner and a session");
    assert!(!store.setup_required());
    assert!(principal_of(&store, &handle).is_some());

    let after = call(&store, &status_req, None, "127.0.0.1", true).unwrap();
    assert_eq!(
        body_value(&after).get("setup_required"),
        Some(&json!(false))
    );

    // The wizard is gone for good: a second setup is a 404, not a silent overwrite.
    let setup = json!({
        "username": "attacker",
        "email": "attacker@example.com",
        "password": "Attacker-Passw0rd!",
    });
    let second = call(
        &store,
        &json_request("POST", "/api/setup", &setup),
        None,
        "127.0.0.1",
        true,
    )
    .unwrap();
    assert_eq!(second.status, 404);
    assert!(!store.setup_required());
}

#[test]
fn setup_is_loopback_only() {
    let (_dir, store) = open_store("setup-loopback").unwrap();
    let setup = json!({
        "username": "owner",
        "email": "owner@example.com",
        "password": OWNER_PASSWORD,
    });
    let response = call(
        &store,
        &json_request("POST", "/api/setup", &setup),
        None,
        "203.0.113.7",
        false,
    )
    .unwrap();
    assert_eq!(response.status, 403);
    assert!(
        store.setup_required(),
        "a remote setup attempt must not create an account"
    );
}

#[test]
fn setup_validates_username_email_and_password_strength() {
    let (_dir, store) = open_store("setup-validation").unwrap();
    let bad = [
        json!({ "username": "owner", "email": "owner@example.com", "password": "short" }),
        json!({ "username": "owner", "email": "owner@example.com", "password": "onlylettersonlyletters" }),
        json!({ "username": "o", "email": "owner@example.com", "password": OWNER_PASSWORD }),
        json!({ "username": "owner name", "email": "owner@example.com", "password": OWNER_PASSWORD }),
        json!({ "username": "owner", "email": "not-an-email", "password": OWNER_PASSWORD }),
        json!({ "username": "owner", "email": "owner@example.com", "password": "ownerownerownerowner" }),
    ];
    for body in &bad {
        let response = call(
            &store,
            &json_request("POST", "/api/setup", body),
            None,
            "127.0.0.1",
            true,
        )
        .unwrap();
        assert_eq!(response.status, 400, "expected 400 for {body}");
    }
    assert!(store.setup_required());
}

#[test]
fn wrong_password_locks_out_after_five_failures() {
    let (_dir, store) = open_store("lockout").unwrap();
    let _handle = do_setup(&store).expect("setup");

    for attempt in 0..5 {
        let (status, handle, _body) = do_login(&store, "owner", "wrong-password-1", "198.51.100.9");
        assert_eq!(
            status, 401,
            "failure {attempt} must be 401, not an information leak"
        );
        assert!(handle.is_none());
    }
    // The sixth attempt is refused before the password is even checked, even with the correct password.
    let (status, handle, body) = do_login(&store, "owner", OWNER_PASSWORD, "198.51.100.9");
    assert_eq!(status, 429);
    assert!(handle.is_none());
    let message = body
        .get("error")
        .and_then(|error| error.get("message"))
        .and_then(Value::as_str)
        .unwrap_or_default();
    assert!(message.to_lowercase().contains("too many"));
    // A different client is not locked out by somebody else's failures.
    let (other_status, other_handle, _) =
        do_login(&store, "owner", OWNER_PASSWORD, "198.51.100.10");
    assert_eq!(other_status, 200);
    assert!(other_handle.is_some());
}

#[test]
fn login_errors_are_enumeration_safe() {
    let (_dir, store) = open_store("enumeration").unwrap();
    let _handle = do_setup(&store).expect("setup");
    let (_unknown_status, _, unknown_body) =
        do_login(&store, "nobody", "Wrong-Password-1!", "192.0.2.5");
    let (_wrong_status, _, wrong_body) =
        do_login(&store, "owner", "Wrong-Password-1!", "192.0.2.5");
    assert_eq!(
        unknown_body, wrong_body,
        "unknown user and wrong password must be indistinguishable"
    );
    let message = unknown_body
        .get("error")
        .and_then(|error| error.get("message"))
        .and_then(Value::as_str)
        .unwrap_or_default();
    assert!(!message.to_lowercase().contains("nobody"));
    assert!(!message.to_lowercase().contains("owner"));
}

#[test]
fn logout_revokes_the_session_server_side() {
    let (_dir, store) = open_store("logout").unwrap();
    let handle = do_setup(&store).expect("setup");
    assert!(principal_of(&store, &handle).is_some());

    let logout = call(
        &store,
        &cookie_request("POST", "/api/logout", &handle),
        principal_of(&store, &handle).as_ref(),
        "127.0.0.1",
        true,
    )
    .unwrap();
    assert_eq!(logout.status, 204);
    assert!(
        principal_of(&store, &handle).is_none(),
        "the cookie must not work after logout"
    );

    // Logging out again stays harmless and idempotent.
    let again = call(
        &store,
        &cookie_request("POST", "/api/logout", &handle),
        None,
        "127.0.0.1",
        true,
    )
    .unwrap();
    assert_eq!(again.status, 204);
}

#[test]
fn session_idle_expiry_after_eight_hours() {
    let (dir, store) = open_store("session-expiry").unwrap();
    let handle = do_setup(&store).expect("setup");
    assert!(principal_of(&store, &handle).is_some());

    // Rewrite the persisted last-seen instant to nine hours ago, then reload exactly as a restart would.
    let bytes = read_store_file(&dir).unwrap();
    let mut document: Value = serde_json::from_slice(&bytes).unwrap();
    let nine_hours_ago = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
        .saturating_sub(9 * 3600);
    let sessions = document
        .get_mut("sessions")
        .and_then(Value::as_array_mut)
        .expect("the store persists sessions");
    assert!(!sessions.is_empty());
    for session in sessions.iter_mut() {
        session["last_seen_unix"] = json!(nine_hours_ago);
    }
    write_store_file(&dir, &serde_json::to_vec(&document).unwrap()).unwrap();

    let reloaded = AccountStore::load(&dir).unwrap();
    assert!(
        principal_of(&reloaded, &handle).is_none(),
        "an 8h-idle session must not authenticate after a restart"
    );
}

#[test]
fn session_absolute_expiry_after_twenty_four_hours() {
    let (dir, store) = open_store("session-absolute-expiry").unwrap();
    let handle = do_setup(&store).expect("setup");
    assert!(principal_of(&store, &handle).is_some());
    let now = unix_now();

    // 23 hours old but used a minute ago: the absolute cap has not been reached, so the session still works.
    rewrite_session_times(&dir, now.saturating_sub(23 * 3600), now.saturating_sub(60)).unwrap();
    let reloaded = AccountStore::load(&dir).unwrap();
    assert!(
        principal_of(&reloaded, &handle).is_some(),
        "a 23h-old session that was used recently must still authenticate"
    );

    // 25 hours old with a fresh last-seen instant: the idle check passes, the absolute check must not.
    rewrite_session_times(&dir, now.saturating_sub(25 * 3600), now).unwrap();
    let reloaded = AccountStore::load(&dir).unwrap();
    assert!(
        principal_of(&reloaded, &handle).is_none(),
        "a session older than 24 hours must not authenticate even when it was used a moment ago"
    );

    // The rejected session is deleted from the store, not merely ignored in memory.
    let bytes = read_store_file(&dir).unwrap();
    let document: Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(
        document
            .get("sessions")
            .and_then(Value::as_array)
            .map(Vec::len),
        Some(0),
        "an absolutely expired session row must be deleted"
    );
}

#[test]
fn authenticate_slides_the_last_seen_time() {
    let (dir, store) = open_store("session-slide").unwrap();
    let handle = do_setup(&store).expect("setup");
    let before = read_store_file(&dir).unwrap();
    let old = serde_json::from_slice::<Value>(&before)
        .unwrap()
        .get("sessions")
        .and_then(Value::as_array)
        .and_then(|sessions| sessions.first())
        .and_then(|session| session.get("last_seen_unix"))
        .and_then(Value::as_u64)
        .unwrap();
    assert!(principal_of(&store, &handle).is_some());
    let after = read_store_file(&dir).unwrap();
    let updated = serde_json::from_slice::<Value>(&after)
        .unwrap()
        .get("sessions")
        .and_then(Value::as_array)
        .and_then(|sessions| sessions.first())
        .and_then(|session| session.get("last_seen_unix"))
        .and_then(Value::as_u64)
        .unwrap();
    assert!(updated >= old);
}

#[test]
fn sessions_can_be_listed_and_revoked_from_the_account_page() {
    let (_dir, store) = open_store("session-revoke").unwrap();
    let first = do_setup(&store).expect("setup");
    let (_status, second, _body) = do_login(&store, "owner", OWNER_PASSWORD, "198.51.100.20");
    let second = second.expect("second login");
    assert!(principal_of(&store, &second).is_some());

    let principal = principal_of(&store, &first).unwrap();
    let list = call(
        &store,
        &cookie_request("GET", "/api/account/sessions", &first),
        Some(&principal),
        "127.0.0.1",
        true,
    )
    .unwrap();
    assert_eq!(list.status, 200);
    let sessions = body_value(&list);
    let array = sessions.as_array().expect("sessions list is a JSON array");
    assert_eq!(array.len(), 2);
    assert_eq!(
        array
            .iter()
            .filter(|s| s.get("current") == Some(&json!(true)))
            .count(),
        1
    );
    let other_id = array
        .iter()
        .find(|session| session.get("current") == Some(&json!(false)))
        .and_then(|session| session.get("id"))
        .and_then(Value::as_str)
        .expect("the other session row");

    let revoke = call(
        &store,
        &cookie_request(
            "POST",
            &format!("/api/account/sessions/{other_id}/delete"),
            &first,
        ),
        Some(&principal),
        "127.0.0.1",
        true,
    )
    .unwrap();
    assert_eq!(revoke.status, 200);
    assert!(
        principal_of(&store, &second).is_none(),
        "a revoked session must stop working"
    );
    assert!(
        principal_of(&store, &first).is_some(),
        "the current session must survive"
    );
}

#[test]
fn change_password_requires_the_current_password_and_rehashes() {
    let (dir, store) = open_store("change-password").unwrap();
    let handle = do_setup(&store).expect("setup");
    let principal = principal_of(&store, &handle).unwrap();

    let wrong =
        json!({ "current_password": "not-the-password", "new_password": "New-Password-77!" });
    let response = call(
        &store,
        &json_request_with_cookie("POST", "/api/account/password", &wrong, &handle),
        Some(&principal),
        "127.0.0.1",
        true,
    )
    .unwrap();
    assert_eq!(response.status, 401);

    let good = json!({ "current_password": OWNER_PASSWORD, "new_password": "New-Password-77!" });
    let response = call(
        &store,
        &json_request_with_cookie("POST", "/api/account/password", &good, &handle),
        Some(&principal),
        "127.0.0.1",
        true,
    )
    .unwrap();
    assert_eq!(response.status, 200);

    let (old_status, _, _) = do_login(&store, "owner", OWNER_PASSWORD, "198.51.100.30");
    assert_eq!(old_status, 401, "the old password must stop working");
    let (new_status, _, _) = do_login(&store, "owner", "New-Password-77!", "198.51.100.30");
    assert_eq!(new_status, 200);

    let stored = String::from_utf8(read_store_file(&dir).unwrap()).unwrap_or_default();
    assert!(!stored.contains(OWNER_PASSWORD));
    assert!(!stored.contains("New-Password-77!"));
}

#[test]
fn change_email_requires_the_password_and_is_reflected_in_me() {
    let (_dir, store) = open_store("change-email").unwrap();
    let handle = do_setup(&store).expect("setup");
    let principal = principal_of(&store, &handle).unwrap();

    let wrong = json!({ "password": "not-the-password", "email": "new@example.com" });
    let response = call(
        &store,
        &json_request_with_cookie("POST", "/api/account/email", &wrong, &handle),
        Some(&principal),
        "127.0.0.1",
        true,
    )
    .unwrap();
    assert_eq!(response.status, 401);

    let good = json!({ "password": OWNER_PASSWORD, "email": "new@example.com" });
    let response = call(
        &store,
        &json_request_with_cookie("POST", "/api/account/email", &good, &handle),
        Some(&principal),
        "127.0.0.1",
        true,
    )
    .unwrap();
    assert_eq!(response.status, 200);

    let me = call(
        &store,
        &cookie_request("GET", "/api/me", &handle),
        Some(&principal),
        "127.0.0.1",
        true,
    )
    .unwrap();
    assert_eq!(
        body_value(&me).get("email"),
        Some(&json!("new@example.com"))
    );
}

#[test]
fn viewer_is_read_only_and_cannot_touch_users() {
    let (_dir, store) = open_store("viewer-rbac").unwrap();
    let owner_handle = do_setup(&store).expect("setup");
    let owner = principal_of(&store, &owner_handle).unwrap();

    let create = json!({
        "username": "viewer",
        "email": "viewer@example.com",
        "password": VIEWER_PASSWORD,
        "role": "viewer",
    });
    let created = call(
        &store,
        &json_request_with_cookie("POST", "/api/users", &create, &owner_handle),
        Some(&owner),
        "127.0.0.1",
        true,
    )
    .unwrap();
    assert_eq!(
        created.status,
        200,
        "owner can create users: {:?}",
        body_value(&created)
    );

    let (status, viewer_handle, _) = do_login(&store, "viewer", VIEWER_PASSWORD, "198.51.100.40");
    assert_eq!(status, 200);
    let viewer_handle = viewer_handle.expect("viewer session");
    let viewer = principal_of(&store, &viewer_handle).unwrap();
    assert_eq!(viewer.role, Role::Viewer);

    // A viewer can read the dashboard but cannot mutate the account list.
    let list = call(
        &store,
        &cookie_request("GET", "/api/users", &viewer_handle),
        Some(&viewer),
        "127.0.0.1",
        true,
    )
    .unwrap();
    assert_eq!(list.status, 403);

    let create_attempt = json!({
        "username": "escalated",
        "email": "escalated@example.com",
        "password": "Escalated-Passw0rd!",
        "role": "owner",
    });
    let attempt = call(
        &store,
        &json_request_with_cookie("POST", "/api/users", &create_attempt, &viewer_handle),
        Some(&viewer),
        "127.0.0.1",
        true,
    )
    .unwrap();
    assert_eq!(attempt.status, 403);

    let role_attempt = call(
        &store,
        &json_request_with_cookie(
            "POST",
            &format!("/api/users/{}/role", owner.user_id),
            &json!({ "role": "viewer" }),
            &viewer_handle,
        ),
        Some(&viewer),
        "127.0.0.1",
        true,
    )
    .unwrap();
    assert_eq!(role_attempt.status, 403);

    let delete_attempt = call(
        &store,
        &json_request_with_cookie(
            "POST",
            &format!("/api/users/{}/delete", owner.user_id),
            &json!({ "confirmation": "owner" }),
            &viewer_handle,
        ),
        Some(&viewer),
        "127.0.0.1",
        true,
    )
    .unwrap();
    assert_eq!(delete_attempt.status, 403);
}

#[test]
fn the_last_owner_cannot_be_removed_or_demoted() {
    let (_dir, store) = open_store("last-owner").unwrap();
    let handle = do_setup(&store).expect("setup");
    let owner = principal_of(&store, &handle).unwrap();

    let demote = call(
        &store,
        &json_request_with_cookie(
            "POST",
            &format!("/api/users/{}/role", owner.user_id),
            &json!({ "role": "viewer" }),
            &handle,
        ),
        Some(&owner),
        "127.0.0.1",
        true,
    )
    .unwrap();
    assert_eq!(demote.status, 409);

    let delete = call(
        &store,
        &json_request_with_cookie(
            "POST",
            &format!("/api/users/{}/delete", owner.user_id),
            &json!({ "confirmation": "owner" }),
            &handle,
        ),
        Some(&owner),
        "127.0.0.1",
        true,
    )
    .unwrap();
    assert_eq!(delete.status, 409);

    let users = call(
        &store,
        &cookie_request("GET", "/api/users", &handle),
        Some(&owner),
        "127.0.0.1",
        true,
    )
    .unwrap();
    let users = body_value(&users);
    let list = users
        .get("users")
        .and_then(Value::as_array)
        .expect("users array");
    assert_eq!(list.len(), 1);
    assert_eq!(
        list.first().and_then(|u| u.get("role")),
        Some(&json!("owner"))
    );
}

#[test]
fn users_crud_and_role_changes() {
    let (_dir, store) = open_store("users-crud").unwrap();
    let handle = do_setup(&store).expect("setup");
    let owner = principal_of(&store, &handle).unwrap();

    let create = json!({
        "username": "alice",
        "email": "alice@example.com",
        "password": "Colleague-Pass-9!",
        "role": "viewer",
    });
    let created = call(
        &store,
        &json_request_with_cookie("POST", "/api/users", &create, &handle),
        Some(&owner),
        "127.0.0.1",
        true,
    )
    .unwrap();
    assert_eq!(created.status, 200);
    let alice_id = body_value(&created)
        .get("id")
        .and_then(Value::as_str)
        .expect("created user id")
        .to_owned();

    // Duplicate user names are rejected, and initial passwords are strength-checked too.
    let duplicate = call(
        &store,
        &json_request_with_cookie("POST", "/api/users", &create, &handle),
        Some(&owner),
        "127.0.0.1",
        true,
    )
    .unwrap();
    assert_eq!(duplicate.status, 409);
    let mut weak = create.clone();
    weak["username"] = json!("bob");
    weak["password"] = json!("short");
    let weak_response = call(
        &store,
        &json_request_with_cookie("POST", "/api/users", &weak, &handle),
        Some(&owner),
        "127.0.0.1",
        true,
    )
    .unwrap();
    assert_eq!(weak_response.status, 400);

    let promote = call(
        &store,
        &json_request_with_cookie(
            "POST",
            &format!("/api/users/{alice_id}/role"),
            &json!({ "role": "owner" }),
            &handle,
        ),
        Some(&owner),
        "127.0.0.1",
        true,
    )
    .unwrap();
    assert_eq!(promote.status, 200);

    let users = call(
        &store,
        &cookie_request("GET", "/api/users", &handle),
        Some(&owner),
        "127.0.0.1",
        true,
    )
    .unwrap();
    let users = body_value(&users);
    let list = users
        .get("users")
        .and_then(Value::as_array)
        .expect("users array");
    assert_eq!(list.len(), 2);
    assert_eq!(
        list.iter()
            .find(|u| u.get("id") == Some(&json!(alice_id)))
            .and_then(|u| u.get("role")),
        Some(&json!("owner"))
    );

    let delete = call(
        &store,
        &json_request_with_cookie(
            "POST",
            &format!("/api/users/{alice_id}/delete"),
            &json!({ "confirmation": "alice" }),
            &handle,
        ),
        Some(&owner),
        "127.0.0.1",
        true,
    )
    .unwrap();
    assert_eq!(delete.status, 200);

    let users = call(
        &store,
        &cookie_request("GET", "/api/users", &handle),
        Some(&owner),
        "127.0.0.1",
        true,
    )
    .unwrap();
    let users = body_value(&users);
    assert_eq!(
        users.get("users").and_then(Value::as_array).map(Vec::len),
        Some(1)
    );
}

#[test]
fn api_tokens_are_shown_once_stored_hashed_and_authenticate() {
    let (dir, store) = open_store("tokens").unwrap();
    let handle = do_setup(&store).expect("setup");
    let owner = principal_of(&store, &handle).unwrap();

    let create = json!({ "name": "demo script" });
    let response = call(
        &store,
        &json_request_with_cookie("POST", "/api/account/tokens", &create, &handle),
        Some(&owner),
        "127.0.0.1",
        true,
    )
    .unwrap();
    assert_eq!(response.status, 200);
    let created = body_value(&response);
    let token = created
        .get("token")
        .and_then(Value::as_str)
        .expect("the one-time token value")
        .to_owned();
    assert!(token.starts_with(hdd_proxy::api::API_TOKEN_PREFIX));
    assert_eq!(
        token.len(),
        hdd_proxy::api::API_TOKEN_PREFIX.len() + 64,
        "256-bit random hex token"
    );
    let token_id = created
        .get("view")
        .and_then(|view| view.get("id"))
        .and_then(Value::as_str)
        .expect("token view id")
        .to_owned();

    // The list never repeats the value, and the disk never holds it in clear.
    let list = call(
        &store,
        &cookie_request("GET", "/api/account/tokens", &handle),
        Some(&owner),
        "127.0.0.1",
        true,
    )
    .unwrap();
    assert_eq!(list.status, 200);
    let serialized = String::from_utf8(list.body.clone()).unwrap_or_default();
    assert!(!serialized.contains(&token));
    assert_eq!(body_value(&list).as_array().map(Vec::len), Some(1));
    let stored = String::from_utf8(read_store_file(&dir).unwrap()).unwrap_or_default();
    assert!(
        !stored.contains(&token),
        "the token value must never be stored in clear"
    );
    assert!(stored.contains("token_hash"));

    // The token authenticates as its owner and records last use.
    assert_eq!(
        store
            .authenticate(&bearer_request("GET", "/api/me", &token))
            .map(|p| p.role),
        Some(Role::Owner)
    );
    assert!(
        store
            .authenticate(&bearer_request("GET", "/api/me", "hdd_deadbeef"))
            .is_none()
    );
    let list = call(
        &store,
        &cookie_request("GET", "/api/account/tokens", &handle),
        Some(&owner),
        "127.0.0.1",
        true,
    )
    .unwrap();
    let used = body_value(&list);
    let used = used
        .as_array()
        .and_then(|tokens| tokens.first())
        .and_then(|view| view.get("last_used_at"));
    assert!(
        used.and_then(Value::as_str).is_some(),
        "token use is recorded"
    );

    // Revoking the token stops it immediately.
    let revoke = call(
        &store,
        &json_request_with_cookie(
            "POST",
            &format!("/api/account/tokens/{token_id}/delete"),
            &json!({}),
            &handle,
        ),
        Some(&owner),
        "127.0.0.1",
        true,
    )
    .unwrap();
    assert_eq!(revoke.status, 200);
    assert!(
        store
            .authenticate(&bearer_request("GET", "/api/me", &token))
            .is_none()
    );
}

#[test]
fn no_plaintext_password_or_session_handle_is_stored() {
    let (dir, store) = open_store("no-plaintext").unwrap();
    let handle = do_setup(&store).expect("setup");
    let bytes = read_store_file(&dir).unwrap();
    let stored = String::from_utf8(bytes).unwrap_or_default();
    assert!(
        !stored.contains(OWNER_PASSWORD),
        "the password must never reach the disk"
    );
    assert!(
        !stored.contains(&handle),
        "the session cookie handle must only be stored hashed"
    );
    assert!(
        stored.contains("$argon2id$"),
        "passwords are stored as argon2id PHC strings"
    );
    // The JSON is the only local state file and it is readable JSON, not a binary blob.
    let document: Value = serde_json::from_str(&stored).unwrap();
    assert!(document.get("users").and_then(Value::as_array).is_some());
}

#[test]
fn unauthenticated_account_endpoints_are_rejected() {
    let (_dir, store) = open_store("unauthenticated").unwrap();
    let _handle = do_setup(&store).expect("setup");
    for (method, path) in [
        ("GET", "/api/account"),
        ("GET", "/api/me"),
        ("GET", "/api/account/sessions"),
        ("GET", "/api/account/tokens"),
        ("POST", "/api/account/password"),
        ("POST", "/api/account/email"),
        ("GET", "/api/users"),
    ] {
        let response = call(&store, &request(method, path), None, "127.0.0.1", true).unwrap();
        assert_eq!(
            response.status, 401,
            "{method} {path} must require a session"
        );
    }
}

#[test]
fn offline_reset_password_returns_a_one_time_password_and_revokes_sessions() {
    let (dir, store) = open_store("reset-password").unwrap();
    let handle = do_setup(&store).expect("setup");
    assert!(principal_of(&store, &handle).is_some());

    let one_time =
        reset_password(&dir, "owner").expect("the reset command accepts an existing user");
    assert!(one_time.len() >= hdd_proxy::api::MIN_PASSWORD_LEN);
    assert!(reset_password(&dir, "nobody").is_err());

    // The CLI rewrites the store offline; a (re)started server reads the new file, so reopen it here.
    let store = AccountStore::load(&dir).unwrap();

    let (old_status, _, _) = do_login(&store, "owner", OWNER_PASSWORD, "198.51.100.60");
    assert_eq!(old_status, 401);
    let (new_status, new_handle, _) = do_login(&store, "owner", &one_time, "198.51.100.60");
    assert_eq!(new_status, 200);
    assert!(new_handle.is_some());
    assert!(
        principal_of(&store, &handle).is_none(),
        "an offline reset must invalidate existing sessions"
    );
}

// The API accepts a JSON body on a cookie-authenticated request just like the browser sends it.
fn json_request_with_cookie(
    method: &str,
    path: &str,
    body: &Value,
    session_handle: &str,
) -> ApiRequest {
    let mut req = json_request(method, path, body);
    req.headers.push((
        "cookie".to_owned(),
        format!("{}={}", hdd_proxy::api::SESSION_COOKIE, session_handle),
    ));
    req
}
