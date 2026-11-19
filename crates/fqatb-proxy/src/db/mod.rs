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

    #[error("Bitbucket token name is already taken")]
    BitbucketTokenNameTaken,

    #[error("access token name is already taken")]
    AccessTokenNameTaken,

    #[error("access token refers to a Bitbucket token that does not exist")]
    UnknownBitbucketToken,

    #[error("invalid {0} ID")]
    InvalidId(&'static str, #[source] uuid::Error),

    #[error("{0} is not valid UTF-8")]
    InvalidText(&'static str),

    #[error("{0} hash has an unexpected length")]
    InvalidHash(&'static str),

    #[error("invalid {0} timestamp")]
    InvalidTimestamp(&'static str, #[source] time::error::Parse),

    #[error("failed to format {0} timestamp")]
    FormatTimestamp(&'static str, #[source] time::error::Format),

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

/// Storage of Bitbucket access tokens.
pub(crate) trait BitbucketTokenDb: Send + Sync {
    /// Stores the token.
    ///
    /// Fails with [`DbError::BitbucketTokenNameTaken`] if a token with the same name exists.
    async fn add_bitbucket_token(&self, token: &BitbucketToken) -> Result<(), DbError>;

    /// Returns the token with its value, if it exists.
    async fn bitbucket_token(&self, id: Uuid) -> Result<Option<BitbucketToken>, DbError>;

    /// Returns all tokens ordered by name, without their values.
    async fn bitbucket_tokens(&self) -> Result<Vec<BitbucketTokenSummary>, DbError>;

    /// Removes the token, together with every access token whose policy uses it, and returns whether it existed.
    async fn remove_bitbucket_token(&self, id: Uuid) -> Result<bool, DbError>;
}

/// Storage of access tokens issued by the proxy.
pub(crate) trait AccessTokenDb: Send + Sync {
    /// Stores the token and records which Bitbucket tokens its policy uses.
    ///
    /// Fails with [`DbError::AccessTokenNameTaken`] if the name is taken,
    /// and with [`DbError::UnknownBitbucketToken`] if the policy uses a Bitbucket token that does not exist.
    async fn add_access_token(&self, token: &AccessToken) -> Result<(), DbError>;

    /// Returns the token with its policy, if it exists.
    async fn access_token(&self, id: Uuid) -> Result<Option<AccessToken>, DbError>;

    /// Returns all tokens ordered by name, without their secrets and policies.
    async fn access_tokens(&self) -> Result<Vec<AccessTokenSummary>, DbError>;

    /// Removes the token and returns whether it existed.
    async fn remove_access_token(&self, id: Uuid) -> Result<bool, DbError>;

    /// Returns the names of the access tokens whose policy uses the Bitbucket token, ordered by name.
    async fn access_tokens_using_bitbucket_token(&self, bitbucket_token_id: Uuid) -> Result<Vec<String>, DbError>;
}
