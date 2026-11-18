//! Persistent storage.
//!
//! Each domain has its own trait, and [`Db`] implements all of them on top of SQLite.
//! Identifiers and the admin password hash are stored as is.
//! Every other value is encrypted with the database cipher before it reaches SQLite.

mod model;
mod sqlite;

pub(crate) use model::*;
pub(crate) use sqlite::Db;
use uuid::Uuid;

use crate::crypto::{DecryptError, EncryptError};

#[derive(Debug, thiserror::Error)]
pub(crate) enum DbError {
    #[error("database query failed")]
    Sqlx(#[from] sqlx::Error),

    #[error("failed to run database migrations")]
    Migrate(#[from] sqlx::migrate::MigrateError),

    #[error("admin already exists")]
    AdminAlreadyExists,

    #[error("invalid {0} ID")]
    InvalidId(&'static str, #[source] uuid::Error),

    #[error("failed to serialize {0}")]
    Serialize(&'static str, #[source] serde_json::Error),

    #[error("failed to deserialize {0}")]
    Deserialize(&'static str, #[source] serde_json::Error),

    #[error("failed to encrypt {0}")]
    Encrypt(&'static str, #[source] EncryptError),

    #[error("failed to decrypt {0}")]
    Decrypt(&'static str, #[source] DecryptError),
}

/// Storage of the single admin account.
pub(crate) trait AdminDb: Send + Sync {
    /// Stores the admin.
    ///
    /// Fails with [`DbError::AdminAlreadyExists`] if an admin is already stored.
    async fn init_admin(&self, admin: &Admin) -> Result<(), DbError>;

    /// Returns the admin, if initialized.
    async fn admin(&self) -> Result<Option<Admin>, DbError>;
}

/// Storage of admin sessions.
pub(crate) trait SessionDb: Send + Sync {
    async fn add_session(&self, id: Uuid, session: &Session) -> Result<(), DbError>;

    /// Returns the session with the given ID, if any.
    ///
    /// Fails if the stored session cannot be decrypted, which means it was tampered with.
    async fn session(&self, id: Uuid) -> Result<Option<Session>, DbError>;

    async fn remove_session(&self, id: Uuid) -> Result<(), DbError>;

    /// Removes every session that is expired at `now` (Unix seconds) or cannot be decrypted.
    async fn remove_expired_sessions(&self, now: u64) -> Result<(), DbError>;
}
