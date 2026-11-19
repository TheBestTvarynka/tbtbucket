use std::sync::Arc;

use tracing::warn;

use crate::Result;
use crate::bitbucket::client::BitbucketClient;
use crate::config::Config;
use crate::crypto::{Cipher, TokenMac};
use crate::db::Db;
use crate::services::{AccessTokenService, AdminService, BitbucketTokenService, ProxyService, SessionService};

/// Everything request handlers need, built once at start-up.
pub(crate) struct State<D> {
    pub(crate) db: Arc<D>,
    pub(crate) admin_service: AdminService<D>,
    pub(crate) session_service: SessionService<D>,
    pub(crate) bitbucket_token_service: BitbucketTokenService<D>,
    pub(crate) access_token_service: AccessTokenService<D>,
    pub(crate) proxy_service: ProxyService<D>,
}

pub(crate) type ServerState = State<Db>;

/// Shared handle to the server state, as stored in the router.
pub(crate) type AppState = Arc<ServerState>;

impl ServerState {
    /// Opens the database and builds the services.
    ///
    /// The master key in `config` is dropped, and zeroized, once every key is derived from it.
    pub(crate) async fn new(config: Config) -> Result<Self> {
        let Config {
            database_url,
            encryption_key,
            bitbucket_url,
            bitbucket_ca_certs,
            ..
        } = config;

        let db_cipher = Cipher::for_database(&encryption_key);
        let session_cipher = Cipher::for_sessions(&encryption_key);
        let token_mac = TokenMac::for_access_tokens(&encryption_key);
        drop(encryption_key);

        let db = Arc::new(Db::connect(&database_url, db_cipher).await?);
        let client = BitbucketClient::new(&bitbucket_url, bitbucket_ca_certs).map_err(crate::Error::HttpClient)?;

        let state = Self {
            admin_service: AdminService::new(Arc::clone(&db)),
            session_service: SessionService::new(Arc::clone(&db), session_cipher),
            bitbucket_token_service: BitbucketTokenService::new(Arc::clone(&db)),
            access_token_service: AccessTokenService::new(Arc::clone(&db), token_mac),
            proxy_service: ProxyService::new(Arc::clone(&db), client),
            db,
        };

        if state.admin_service.admin_id().await?.is_none() {
            // Until then, whoever reaches the sign-up page first sets the admin password.
            warn!("Admin is not initialized, sign up in the admin panel to set the password");
        }

        Ok(state)
    }
}

#[cfg(test)]
impl ServerState {
    /// Builds a state backed by an in-memory database, with no admin, forwarding to an unreachable Bitbucket.
    pub(crate) async fn for_tests() -> Self {
        Self::for_tests_with_bitbucket("http://127.0.0.1:1").await
    }

    /// Like [`ServerState::for_tests`], forwarding to the Bitbucket server at `bitbucket_url`.
    pub(crate) async fn for_tests_with_bitbucket(bitbucket_url: &str) -> Self {
        use secret::Secret;

        use crate::crypto::KEY_LEN;

        let master_key = Secret::new([1; KEY_LEN]);
        let db = Arc::new(Db::in_memory(Cipher::for_database(&master_key)).await);
        let client = BitbucketClient::new(&bitbucket_url.parse().unwrap(), None).unwrap();

        Self {
            admin_service: AdminService::new(Arc::clone(&db)),
            session_service: SessionService::new(Arc::clone(&db), Cipher::for_sessions(&master_key)),
            bitbucket_token_service: BitbucketTokenService::new(Arc::clone(&db)),
            access_token_service: AccessTokenService::new(Arc::clone(&db), TokenMac::for_access_tokens(&master_key)),
            proxy_service: ProxyService::new(Arc::clone(&db), client),
            db,
        }
    }
}
