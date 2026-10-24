//! The production authenticator: teammate D's [`crate::accounts::AccountStore`] (session cookie or `hdd_` API token)
//! plus the R-03 bootstrap/break-glass token from the configured environment variable, which is accepted only as a
//! bearer token and compared in constant time. The admin token is never stored in a file and never printed.
//!
//! This is the only module that names the accounts implementation, so the admin integration tests can implement the
//! [`AdminAuth`] seam directly while the production binary always uses the real store.

use std::sync::Arc;

use crate::accounts::AccountStore;
use crate::api::{ApiRequest, ApiResponse, Principal, Role};
use crate::config::{ConfigError, Validated};
use crate::state::AdminAuth;
use crate::util;

/// The production authenticator.
pub struct AccountAuth {
    /// The account store (sessions, API tokens, users) loaded from the data directory.
    store: Arc<AccountStore>,
    /// The bootstrap/break-glass admin token from the environment (never a default, never printed).
    bootstrap_token: String,
}

impl AccountAuth {
    /// Load the account store from the data directory and keep the bootstrap token.
    ///
    /// # Errors
    /// Returns a [`ConfigError`] when the account store cannot be loaded.
    pub fn load(validated: &Validated, bootstrap_token: &str) -> Result<Self, ConfigError> {
        let store = AccountStore::load(&validated.data_dir).map_err(|message| ConfigError {
            message: format!(
                "cannot load the account store from `{}`: {message}",
                validated.data_dir.display()
            ),
        })?;
        Ok(Self {
            store,
            bootstrap_token: bootstrap_token.to_owned(),
        })
    }

    /// The wrapped account store (used by the CLI password reset).
    #[must_use]
    pub fn store(&self) -> &Arc<AccountStore> {
        &self.store
    }

    /// Accept the bootstrap token as an owner bearer token (R-19 break-glass; no default value exists).
    fn bootstrap_principal(&self, request: &ApiRequest) -> Option<Principal> {
        let header = util::header(&request.headers, "authorization")?;
        let token = header
            .strip_prefix("Bearer ")
            .or_else(|| header.strip_prefix("bearer "))?
            .trim();
        if token.is_empty() || !util::constant_time_eq(token, &self.bootstrap_token) {
            return None;
        }
        Some(Principal {
            user_id: "bootstrap".to_owned(),
            username: "bootstrap".to_owned(),
            role: Role::Owner,
        })
    }
}

impl AdminAuth for AccountAuth {
    fn authenticate(&self, request: &ApiRequest) -> Option<Principal> {
        self.store
            .authenticate(request)
            .or_else(|| self.bootstrap_principal(request))
    }

    fn setup_required(&self) -> bool {
        self.store.setup_required()
    }

    fn handle_accounts(
        &self,
        request: &ApiRequest,
        principal: Option<&Principal>,
        client_ip: &str,
        loopback: bool,
    ) -> Option<ApiResponse> {
        crate::accounts_api::handle(&self.store, request, principal, client_ip, loopback)
    }
}
