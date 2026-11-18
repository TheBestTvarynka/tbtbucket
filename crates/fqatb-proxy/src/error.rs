use std::error::Error as StdError;
use std::fmt::Write as _;

use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use tracing::error;

use crate::crypto::EncryptError;
use crate::db::DbError;
use crate::services::MIN_PASSWORD_LEN;

#[derive(Debug, thiserror::Error)]
pub(crate) enum Error {
    #[error("database operation failed")]
    Db(#[from] DbError),

    #[error("invalid credentials")]
    InvalidCredentials,

    #[error("admin is not initialized")]
    AdminNotInitialized,

    #[error("FQATB_ADMIN_PASSWORD must be set on first start-up to initialize the admin")]
    AdminPasswordMissing,

    #[error("admin password must be at least {MIN_PASSWORD_LEN} characters long")]
    PasswordTooShort,

    #[error("password hashing failed")]
    PasswordHash(#[source] argon2::password_hash::Error),

    #[error("failed to encrypt session token")]
    SessionToken(#[source] EncryptError),

    #[error("background task failed")]
    Join(#[from] tokio::task::JoinError),
}

pub(crate) type Result<T> = std::result::Result<T, Error>;

impl IntoResponse for Error {
    fn into_response(self) -> Response {
        match self {
            Self::InvalidCredentials => (StatusCode::UNAUTHORIZED, "invalid credentials").into_response(),
            error => {
                error!(error = report(&error), "Request failed");
                (StatusCode::INTERNAL_SERVER_ERROR, "internal server error").into_response()
            }
        }
    }
}

/// Formats an error with all of its sources, separated by `: `.
pub(crate) fn report(error: &dyn StdError) -> String {
    let mut report = error.to_string();
    let mut source = error.source();

    while let Some(error) = source {
        let _ = write!(report, ": {error}");
        source = error.source();
    }

    report
}
