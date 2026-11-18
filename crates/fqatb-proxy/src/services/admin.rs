use std::sync::Arc;

use argon2::Argon2;
use argon2::password_hash::{self, PasswordHasher as _, PasswordVerifier as _};
use secret::Secret;
use uuid::Uuid;

use crate::db::{Admin, AdminDb, DbError};
use crate::{Error, Result};

/// Shortest password accepted when the admin is initialized, in characters.
pub(crate) const MIN_PASSWORD_LEN: usize = 6;

/// A requirement that a new admin password does not meet.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub(crate) enum PasswordRequirement {
    #[error("password must be at least {MIN_PASSWORD_LEN} characters long")]
    MinLength,

    #[error("password must contain a digit")]
    Digit,

    /// Any character that is neither a letter, a digit nor whitespace.
    #[error("password must contain a special character")]
    SpecialCharacter,
}

impl PasswordRequirement {
    /// Returns the first requirement that `password` does not meet, if any.
    pub(crate) fn first_unmet(password: &str) -> Option<Self> {
        if !(MIN_PASSWORD_LEN <= password.chars().count()) {
            return Some(Self::MinLength);
        }

        if !password.chars().any(|c| c.is_ascii_digit()) {
            return Some(Self::Digit);
        }

        if !password.chars().any(|c| !c.is_alphanumeric() && !c.is_whitespace()) {
            return Some(Self::SpecialCharacter);
        }

        None
    }
}

/// Initializes and authenticates the single admin.
///
/// Argon2 is deliberately slow, so hashing runs on the blocking thread pool.
pub(crate) struct AdminService<D> {
    db: Arc<D>,
}

impl<D> AdminService<D> {
    pub(crate) fn new(db: Arc<D>) -> Self {
        Self { db }
    }
}

impl<D: AdminDb> AdminService<D> {
    /// Returns the admin ID, if the admin is initialized.
    pub(crate) async fn admin_id(&self) -> Result<Option<Uuid>> {
        Ok(self.db.admin().await?.map(|admin| admin.id))
    }

    /// Creates the admin with a fresh random ID and the Argon2id hash of `password`.
    ///
    /// Fails with [`Error::WeakPassword`] if `password` does not meet a [`PasswordRequirement`],
    /// and with [`Error::AdminAlreadyInitialized`] if the admin already exists.
    pub(crate) async fn init(&self, password: Secret<String>) -> Result<Uuid> {
        if let Some(requirement) = PasswordRequirement::first_unmet(password.as_ref()) {
            return Err(Error::WeakPassword(requirement));
        }

        let password_hash = tokio::task::spawn_blocking(move || {
            Argon2::default()
                .hash_password(password.as_ref().as_bytes())
                .map(|hash| hash.to_string())
        })
        .await?
        .map_err(Error::PasswordHash)?;

        let admin = Admin {
            id: Uuid::new_v4(),
            password_hash,
        };
        self.db.init_admin(&admin).await.map_err(|error| match error {
            DbError::AdminAlreadyExists => Error::AdminAlreadyInitialized,
            error => Error::Db(error),
        })?;

        Ok(admin.id)
    }

    /// Checks `password` and returns the admin ID.
    ///
    /// Fails with [`Error::InvalidCredentials`] if the password is wrong.
    pub(crate) async fn authenticate(&self, password: Secret<String>) -> Result<Uuid> {
        let Admin { id, password_hash } = self.db.admin().await?.ok_or(Error::AdminNotInitialized)?;

        let verified = tokio::task::spawn_blocking(move || {
            Argon2::default().verify_password(password.as_ref().as_bytes(), password_hash.as_str())
        })
        .await?;

        match verified {
            Ok(()) => Ok(id),
            Err(password_hash::Error::PasswordInvalid) => Err(Error::InvalidCredentials),
            Err(error) => Err(Error::PasswordHash(error)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::{Cipher, KEY_LEN};
    use crate::db::Db;

    async fn service() -> AdminService<Db> {
        let db = Db::in_memory(Cipher::for_database(&Secret::new([0; KEY_LEN]))).await;
        AdminService::new(Arc::new(db))
    }

    fn password(password: &str) -> Secret<String> {
        Secret::new(password.to_owned())
    }

    #[test]
    fn password_requirements() {
        for (password, expected) in [
            ("ab1!", Some(PasswordRequirement::MinLength)),
            ("abcde!", Some(PasswordRequirement::Digit)),
            ("abcde1", Some(PasswordRequirement::SpecialCharacter)),
            ("abcd 1", Some(PasswordRequirement::SpecialCharacter)),
            ("abcd1!", None),
            ("пароль1!", None),
            ("abcd1€", None),
            ("a b c 1_", None),
        ] {
            assert_eq!(PasswordRequirement::first_unmet(password), expected, "{password}");
        }
    }

    #[tokio::test]
    async fn init_then_authenticate() {
        let service = service().await;
        assert!(service.admin_id().await.unwrap().is_none());

        let id = service.init(password("pass1!")).await.unwrap();

        assert_eq!(service.admin_id().await.unwrap(), Some(id));
        assert_eq!(service.authenticate(password("pass1!")).await.unwrap(), id);
        assert!(matches!(
            service.authenticate(password("wrong1!")).await,
            Err(Error::InvalidCredentials)
        ));
    }

    #[tokio::test]
    async fn init_only_once() {
        let service = service().await;
        let id = service.init(password("pass1!")).await.unwrap();

        assert!(matches!(
            service.init(password("other2!")).await,
            Err(Error::AdminAlreadyInitialized)
        ));
        assert_eq!(service.authenticate(password("pass1!")).await.unwrap(), id);
    }

    #[tokio::test]
    async fn rejects_weak_password() {
        let service = service().await;

        assert!(matches!(
            service.init(password("password")).await,
            Err(Error::WeakPassword(PasswordRequirement::Digit))
        ));
        assert!(service.admin_id().await.unwrap().is_none());
    }

    #[tokio::test]
    async fn authenticate_requires_admin() {
        let service = service().await;

        assert!(matches!(
            service.authenticate(password("pass1!")).await,
            Err(Error::AdminNotInitialized)
        ));
    }
}
