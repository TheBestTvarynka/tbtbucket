use std::sync::Arc;

use tracing::warn;

use crate::Result;
use crate::config::Config;
use crate::crypto::Cipher;
use crate::db::Db;
use crate::services::{AdminService, SessionService};

/// Everything request handlers need, built once at start-up.
pub(crate) struct State<D> {
    pub(crate) db: Arc<D>,
    pub(crate) admin_service: AdminService<D>,
    pub(crate) session_service: SessionService<D>,
}

pub(crate) type ServerState = State<Db>;

/// Shared handle to the server state, as stored in the router.
pub(crate) type AppState = Arc<ServerState>;

impl ServerState {
    /// Opens the database and builds the services.
    ///
    /// The master key in `config` is dropped, and zeroized, once both ciphers are derived from it.
    pub(crate) async fn new(config: Config) -> Result<Self> {
        let Config {
            database_url,
            encryption_key,
            ..
        } = config;

        let db_cipher = Cipher::for_database(&encryption_key);
        let session_cipher = Cipher::for_sessions(&encryption_key);
        drop(encryption_key);

        let db = Arc::new(Db::connect(&database_url, db_cipher).await?);

        let state = Self {
            admin_service: AdminService::new(Arc::clone(&db)),
            session_service: SessionService::new(Arc::clone(&db), session_cipher),
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
    /// Builds a state backed by an in-memory database, with no admin.
    pub(crate) async fn for_tests() -> Self {
        use secret::Secret;

        use crate::crypto::KEY_LEN;

        let master_key = Secret::new([1; KEY_LEN]);
        let db = Arc::new(Db::in_memory(Cipher::for_database(&master_key)).await);

        Self {
            admin_service: AdminService::new(Arc::clone(&db)),
            session_service: SessionService::new(Arc::clone(&db), Cipher::for_sessions(&master_key)),
            db,
        }
    }
}
