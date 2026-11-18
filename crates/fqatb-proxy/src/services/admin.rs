use std::sync::Arc;

use argon2::Argon2;
use argon2::password_hash::{self, PasswordHasher as _, PasswordVerifier as _};
use secret::Secret;
use uuid::Uuid;

use crate::db::{Admin, AdminDb};
use crate::{Error, Result};

/// Shortest passphrase accepted when the admin is initialized.
pub(crate) const MIN_PASSWORD_LEN: usize = 12;

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
    pub(crate) async fn init(&self, password: Secret<String>) -> Result<Uuid> {
        if !(MIN_PASSWORD_LEN <= password.as_ref().chars().count()) {
            return Err(Error::PasswordTooShort);
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
        self.db.init_admin(&admin).await?;

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

    #[tokio::test]
    async fn init_then_authenticate() {
        let service = service().await;
        assert!(service.admin_id().await.unwrap().is_none());

        let id = service.init(password("a long passphrase")).await.unwrap();

        assert_eq!(service.admin_id().await.unwrap(), Some(id));
        assert_eq!(service.authenticate(password("a long passphrase")).await.unwrap(), id);
        assert!(matches!(
            service.authenticate(password("a wrong passphrase")).await,
            Err(Error::InvalidCredentials)
        ));
    }

    #[tokio::test]
    async fn rejects_short_password() {
        let service = service().await;

        assert!(matches!(
            service.init(password("short")).await,
            Err(Error::PasswordTooShort)
        ));
    }

    #[tokio::test]
    async fn authenticate_requires_admin() {
        let service = service().await;

        assert!(matches!(
            service.authenticate(password("a long passphrase")).await,
            Err(Error::AdminNotInitialized)
        ));
    }
}
