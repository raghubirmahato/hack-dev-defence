//! The account, onboarding and user-management endpoints of the admin API (COLLAB.md Addendum 2).
//!
//! The admin server calls [`handle`] first for every admin request and forwards whatever it returns; `None` means "this
//! is not an accounts route" and the server keeps routing. The server owns the wire concerns that need the listener
//! (auth for non-public paths, the cookie CSRF `Origin` check and the viewer read-only guard); this module owns the
//! business rules and still refuses a viewer on every `/api/users*` mutation itself (defence in depth).
//!
//! Passwords and token values never appear in a response except the one-time value of a freshly created API token.

use crate::accounts::{AccountStore, LoginOutcome, StoreError};
use crate::api::{
    self, AccountView, ApiError, ApiRequest, ApiResponse, ChangeEmailRequest,
    ChangePasswordRequest, ErrorBody, LoginRequest, OkResponse, Principal, SessionView,
    SessionViewBody, SetupRequest, SetupStatusView, TokenCreateRequest, TokenCreateResponse,
    TokenView, UserCreateRequest, UserRoleRequest, UserView, UsersResponse, paths,
};

const ACCOUNT_PASSWORD: &str = "/api/account/password";
const ACCOUNT_EMAIL: &str = "/api/account/email";
const ACCOUNT_SESSIONS: &str = "/api/account/sessions";
const ACCOUNT_TOKENS: &str = "/api/account/tokens";
const SESSIONS_PREFIX: &str = "/api/account/sessions/";
const TOKENS_PREFIX: &str = "/api/account/tokens/";
const USERS_PREFIX: &str = "/api/users/";
const DELETE_SUFFIX: &str = "/delete";
const ROLE_SUFFIX: &str = "/role";

/// A destructive action must be confirmed by typing the target (R-28); reuse for user deletion.
#[derive(Debug, Clone, serde::Deserialize)]
struct DeleteConfirmation {
    #[serde(default)]
    confirmation: Option<String>,
}

/// Handle one accounts/admin-account request, or return `None` when the path is not ours.
#[must_use]
pub fn handle(
    store: &AccountStore,
    req: &ApiRequest,
    principal: Option<&Principal>,
    client_ip: &str,
    loopback: bool,
) -> Option<ApiResponse> {
    let method = req.method.as_str();
    let path = req.path.as_str();

    let response = match (method, path) {
        ("GET", p) if p == paths::API_SETUP_STATUS => setup_status(store, loopback),
        ("POST", p) if p == paths::API_SETUP => setup(store, req, client_ip, loopback),
        ("POST", p) if p == paths::API_LOGIN => login(store, req, client_ip),
        ("POST", p) if p == paths::API_LOGOUT => logout(store, req),
        ("GET", p) if p == paths::API_ME => me(store, principal),
        ("GET", p) if p == paths::API_ACCOUNT => account(store, req, principal),
        ("POST", p) if p == ACCOUNT_PASSWORD => change_password(store, req, principal),
        ("POST", p) if p == ACCOUNT_EMAIL => change_email(store, req, principal),
        ("GET", p) if p == ACCOUNT_SESSIONS => sessions(store, req, principal),
        ("GET", p) if p == ACCOUNT_TOKENS => tokens(store, principal),
        ("POST", p) if p == ACCOUNT_TOKENS => create_token(store, req, principal),
        ("GET", p) if p == paths::API_USERS => users(store, principal),
        ("POST", p) if p == paths::API_USERS => create_user(store, req, principal),
        _ => return dynamic(store, req, principal),
    };
    Some(response)
}

fn dynamic(
    store: &AccountStore,
    req: &ApiRequest,
    principal: Option<&Principal>,
) -> Option<ApiResponse> {
    let method = req.method.as_str();
    let path = req.path.as_str();
    if method == "POST" {
        if let Some(id) = path_segment(path, SESSIONS_PREFIX, DELETE_SUFFIX) {
            return Some(with_principal(principal, |principal| {
                revoke_session(store, principal, id)
            }));
        }
        if let Some(id) = path_segment(path, TOKENS_PREFIX, DELETE_SUFFIX) {
            return Some(with_principal(principal, |principal| {
                revoke_token(store, principal, id)
            }));
        }
        if let Some(id) = path_segment(path, USERS_PREFIX, ROLE_SUFFIX) {
            return Some(with_principal(principal, |principal| {
                set_role(store, req, principal, id)
            }));
        }
        if let Some(id) = path_segment(path, USERS_PREFIX, DELETE_SUFFIX) {
            return Some(with_principal(principal, |principal| {
                delete_user(store, req, principal, id)
            }));
        }
    }
    None
}

/// Extract a non-empty, single-segment id between a prefix and a suffix.
fn path_segment<'a>(path: &'a str, prefix: &str, suffix: &str) -> Option<&'a str> {
    let rest = path.strip_prefix(prefix)?;
    let id = rest.strip_suffix(suffix)?;
    if id.is_empty() || id.contains('/') {
        None
    } else {
        Some(id)
    }
}

fn with_principal(
    principal: Option<&Principal>,
    handler: impl FnOnce(&Principal) -> ApiResponse,
) -> ApiResponse {
    match principal {
        Some(principal) => handler(principal),
        None => ApiError::unauthorized("sign in to use this endpoint").into_response(),
    }
}

fn internal_error(message: String) -> ApiResponse {
    ApiResponse::error(
        500,
        "internal",
        format!("the account store could not complete the request: {message}"),
    )
}

fn store_error(error: StoreError) -> ApiResponse {
    match error {
        StoreError::BadRequest(message) => ApiError::bad_request(message).into_response(),
        StoreError::Unauthorized => {
            ApiError::unauthorized("the current password is incorrect").into_response()
        }
        StoreError::Forbidden(message) => ApiError::forbidden(message).into_response(),
        StoreError::NotFound => {
            ApiError::not_found("the requested item does not exist").into_response()
        }
        StoreError::Conflict(message) => ApiError::conflict(message).into_response(),
        StoreError::Internal(message) => internal_error(message),
    }
}

fn session_cookie(handle: &str) -> String {
    format!(
        "{}={handle}; Path=/; HttpOnly; SameSite=Strict; Max-Age={}",
        api::SESSION_COOKIE,
        crate::accounts::SESSION_IDLE_SECONDS
    )
}

fn cleared_session_cookie() -> String {
    format!(
        "{}=; Path=/; HttpOnly; SameSite=Strict; Max-Age=0",
        api::SESSION_COOKIE
    )
}

fn json_body<T: serde::de::DeserializeOwned>(req: &ApiRequest) -> Result<T, ApiResponse> {
    req.json::<T>()
        .map_err(|error| ApiResponse::error(error.status, error.code, error.message))
}

fn setup_status(store: &AccountStore, loopback: bool) -> ApiResponse {
    ApiResponse::json(&SetupStatusView {
        setup_required: store.setup_required(),
        loopback,
    })
}

fn setup(store: &AccountStore, req: &ApiRequest, client_ip: &str, loopback: bool) -> ApiResponse {
    if !store.setup_required() {
        return ApiError::not_found("the first-run setup is closed: an account already exists")
            .into_response();
    }
    if !loopback {
        return ApiError::forbidden(
            "first-run setup is only available from the machine running HDD",
        )
        .into_response();
    }
    let body: SetupRequest = match json_body(req) {
        Ok(body) => body,
        Err(response) => return response,
    };
    if let Err(error) = store.create_owner(&body.username, &body.email, &body.password) {
        return store_error(error);
    }
    match store.login(&body.username, &body.password, client_ip) {
        LoginOutcome::Success {
            session_handle,
            principal,
            email,
        } => ApiResponse::json(&SessionViewBody {
            username: principal.username,
            role: principal.role,
            email,
        })
        .with_header("Set-Cookie", session_cookie(&session_handle)),
        LoginOutcome::InvalidCredentials => {
            internal_error("the owner account was created but the automatic sign-in failed".to_owned())
        }
        LoginOutcome::LockedOut { retry_after_seconds } => ApiResponse::error(
            429,
            "too_many_requests",
            "the owner account was created but sign-in is rate-limited; sign in from the login page"
                .to_owned(),
        )
        .with_header("Retry-After", retry_after_seconds.to_string()),
        LoginOutcome::Internal(message) => internal_error(message),
    }
}

fn login(store: &AccountStore, req: &ApiRequest, client_ip: &str) -> ApiResponse {
    let body: LoginRequest = match json_body(req) {
        Ok(body) => body,
        Err(response) => return response,
    };
    match store.login(&body.username, &body.password, client_ip) {
        LoginOutcome::Success {
            session_handle,
            principal,
            email,
        } => ApiResponse::json(&SessionViewBody {
            username: principal.username,
            role: principal.role,
            email,
        })
        .with_header("Set-Cookie", session_cookie(&session_handle)),
        // The same message for an unknown user and a wrong password (R-20).
        LoginOutcome::InvalidCredentials => {
            ApiError::unauthorized("invalid username or password").into_response()
        }
        LoginOutcome::LockedOut {
            retry_after_seconds,
        } => ApiResponse::error(
            429,
            "too_many_requests",
            "too many failed sign-in attempts; try again in a minute".to_owned(),
        )
        .with_header("Retry-After", retry_after_seconds.to_string()),
        LoginOutcome::Internal(message) => internal_error(message),
    }
}

fn logout(store: &AccountStore, req: &ApiRequest) -> ApiResponse {
    if let Err(error) = store.logout(req) {
        return store_error(error);
    }
    ApiResponse::no_content().with_header("Set-Cookie", cleared_session_cookie())
}

fn me(store: &AccountStore, principal: Option<&Principal>) -> ApiResponse {
    with_principal(principal, |principal| {
        match store.session_view_body(principal) {
            Some(view) => ApiResponse::json(&view),
            None => {
                ApiError::unauthorized("the signed-in account no longer exists").into_response()
            }
        }
    })
}

fn account(store: &AccountStore, req: &ApiRequest, principal: Option<&Principal>) -> ApiResponse {
    with_principal(principal, |principal| {
        match store.account_view(principal, req) {
            Some(view) => ApiResponse::json(&view),
            None => {
                ApiError::unauthorized("the signed-in account no longer exists").into_response()
            }
        }
    })
}

fn change_password(
    store: &AccountStore,
    req: &ApiRequest,
    principal: Option<&Principal>,
) -> ApiResponse {
    with_principal(principal, |principal| {
        let body: ChangePasswordRequest = match json_body(req) {
            Ok(body) => body,
            Err(response) => return response,
        };
        match store.change_password(principal, &body.current_password, &body.new_password, req) {
            Ok(()) => ApiResponse::json(&OkResponse { ok: true }),
            Err(error) => store_error(error),
        }
    })
}

fn change_email(
    store: &AccountStore,
    req: &ApiRequest,
    principal: Option<&Principal>,
) -> ApiResponse {
    with_principal(principal, |principal| {
        let body: ChangeEmailRequest = match json_body(req) {
            Ok(body) => body,
            Err(response) => return response,
        };
        match store.change_email(principal, &body.password, &body.email) {
            Ok(()) => ApiResponse::json(&OkResponse { ok: true }),
            Err(error) => store_error(error),
        }
    })
}

fn sessions(store: &AccountStore, req: &ApiRequest, principal: Option<&Principal>) -> ApiResponse {
    with_principal(principal, |principal| {
        match store.sessions(principal, req) {
            Ok(sessions) => ApiResponse::json(&sessions),
            Err(error) => store_error(error),
        }
    })
}

fn tokens(store: &AccountStore, principal: Option<&Principal>) -> ApiResponse {
    with_principal(principal, |principal| match store.tokens(principal) {
        Ok(tokens) => ApiResponse::json(&tokens),
        Err(error) => store_error(error),
    })
}

fn create_token(
    store: &AccountStore,
    req: &ApiRequest,
    principal: Option<&Principal>,
) -> ApiResponse {
    with_principal(principal, |principal| {
        let body: TokenCreateRequest = match json_body(req) {
            Ok(body) => body,
            Err(response) => return response,
        };
        match store.create_token(principal, &body.name) {
            Ok(created) => ApiResponse::json(&created),
            Err(error) => store_error(error),
        }
    })
}

fn revoke_session(store: &AccountStore, principal: &Principal, id: &str) -> ApiResponse {
    match store.revoke_session(principal, id) {
        Ok(()) => ApiResponse::json(&OkResponse { ok: true }),
        Err(error) => store_error(error),
    }
}

fn revoke_token(store: &AccountStore, principal: &Principal, id: &str) -> ApiResponse {
    match store.revoke_token(principal, id) {
        Ok(()) => ApiResponse::json(&OkResponse { ok: true }),
        Err(error) => store_error(error),
    }
}

fn users(store: &AccountStore, principal: Option<&Principal>) -> ApiResponse {
    with_principal(principal, |principal| match store.users(principal) {
        Ok(users) => ApiResponse::json(&UsersResponse { users }),
        Err(error) => store_error(error),
    })
}

fn create_user(
    store: &AccountStore,
    req: &ApiRequest,
    principal: Option<&Principal>,
) -> ApiResponse {
    with_principal(principal, |principal| {
        let body: UserCreateRequest = match json_body(req) {
            Ok(body) => body,
            Err(response) => return response,
        };
        match store.create_user(
            principal,
            &body.username,
            &body.email,
            &body.password,
            body.role,
        ) {
            Ok(user) => ApiResponse::json(&user),
            Err(error) => store_error(error),
        }
    })
}

fn set_role(
    store: &AccountStore,
    req: &ApiRequest,
    principal: &Principal,
    id: &str,
) -> ApiResponse {
    let body: UserRoleRequest = match json_body(req) {
        Ok(body) => body,
        Err(response) => return response,
    };
    match store.set_role(principal, id, body.role) {
        Ok(()) => ApiResponse::json(&OkResponse { ok: true }),
        Err(error) => store_error(error),
    }
}

fn delete_user(
    store: &AccountStore,
    req: &ApiRequest,
    principal: &Principal,
    id: &str,
) -> ApiResponse {
    let body: DeleteConfirmation = match json_body(req) {
        Ok(body) => body,
        Err(response) => return response,
    };
    let Some(confirmation) = body.confirmation else {
        return ApiError::bad_request("type the username to confirm deleting the account")
            .into_response();
    };
    match store.delete_user(principal, id, &confirmation) {
        Ok(()) => ApiResponse::json(&OkResponse { ok: true }),
        Err(error) => store_error(error),
    }
}

// Anchor the DTOs used here to the frozen contract: if a type or field disappears from `api.rs`, this function stops
// compiling even though no handler names it directly.
#[allow(dead_code)]
fn assert_dto_contract() {
    fn assert_serialize<T: serde::Serialize>() {}
    fn assert_deserialize<T: serde::de::DeserializeOwned>() {}
    assert_serialize::<AccountView>();
    assert_serialize::<SessionView>();
    assert_serialize::<TokenCreateResponse>();
    assert_serialize::<TokenView>();
    assert_serialize::<UsersResponse>();
    assert_serialize::<UserView>();
    assert_serialize::<ErrorBody>();
    assert_deserialize::<LoginRequest>();
    assert_deserialize::<SetupRequest>();
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dynamic_ids_are_single_non_empty_segments() {
        assert_eq!(
            path_segment("/api/users/abc/role", USERS_PREFIX, ROLE_SUFFIX),
            Some("abc")
        );
        assert_eq!(
            path_segment("/api/users//role", USERS_PREFIX, ROLE_SUFFIX),
            None
        );
        assert_eq!(
            path_segment("/api/users/a/b/role", USERS_PREFIX, ROLE_SUFFIX),
            None
        );
        assert_eq!(
            path_segment("/api/users/abc", USERS_PREFIX, ROLE_SUFFIX),
            None
        );
    }

    #[test]
    fn the_session_cookie_is_http_only_and_same_site_strict() {
        let cookie = session_cookie("abc123");
        assert!(cookie.starts_with("hdd_session=abc123;"));
        assert!(cookie.contains("HttpOnly"));
        assert!(cookie.contains("SameSite=Strict"));
        assert!(cookie.contains("Path=/"));
    }
}
