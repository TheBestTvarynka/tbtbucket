use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use tracing::debug;
use uuid::Uuid;

use crate::crypto::Cipher;
use crate::db::{Session, SessionDb};
use crate::{Error, Result};

/// How long a session stays valid after login.
pub(crate) const SESSION_TTL: Duration = Duration::from_secs(12 * 60 * 60);

const TOKEN_CONTEXT: &[u8] = b"session token";

/// A session that was just created.
pub(crate) struct NewSession {
    pub(crate) id: Uuid,
    /// Opaque value for the client to present on later requests.
    pub(crate) token: String,
}

/// Creates and resolves admin sessions.
///
/// The session itself lives in the database.
/// The client only receives the session ID encrypted with the session cipher, so a leaked database row cannot be turned into a token without the key.
pub(crate) struct SessionService<D> {
    db: Arc<D>,
    cipher: Cipher,
}

impl<D> SessionService<D> {
    pub(crate) fn new(db: Arc<D>, cipher: Cipher) -> Self {
        Self { db, cipher }
    }

    fn token(&self, id: Uuid) -> Result<String> {
        let encrypted_id = self
            .cipher
            .encrypt(TOKEN_CONTEXT, id.as_bytes())
            .map_err(Error::SessionToken)?;

        Ok(URL_SAFE_NO_PAD.encode(encrypted_id))
    }

    fn session_id(&self, token: &str) -> Option<Uuid> {
        let encrypted_id = URL_SAFE_NO_PAD.decode(token).ok()?;
        let id = self.cipher.decrypt(TOKEN_CONTEXT, &encrypted_id).ok()?;
        Uuid::from_slice(&id).ok()
    }
}

impl<D: SessionDb> SessionService<D> {
    /// Starts a session for the admin, removing expired sessions on the way.
    pub(crate) async fn create(&self, admin_id: Uuid) -> Result<NewSession> {
        let now = unix_now();

        self.db.remove_expired_sessions(now).await?;

        let id = Uuid::new_v4();
        let session = Session {
            admin_id,
            created_at: now,
            expires_at: now + SESSION_TTL.as_secs(),
        };
        self.db.add_session(id, &session).await?;

        Ok(NewSession {
            id,
            token: self.token(id)?,
        })
    }

    /// Resolves a token to a live session.
    ///
    /// Returns `None` for malformed, forged, unknown or expired tokens.
    /// An expired session is removed on the way.
    pub(crate) async fn resolve(&self, token: &str) -> Result<Option<(Uuid, Session)>> {
        let Some(id) = self.session_id(token) else {
            debug!("Rejected invalid session token");
            return Ok(None);
        };

        let Some(session) = self.db.session(id).await? else {
            return Ok(None);
        };

        if session.is_expired(unix_now()) {
            self.db.remove_session(id).await?;
            return Ok(None);
        }

        Ok(Some((id, session)))
    }

    pub(crate) async fn end(&self, id: Uuid) -> Result<()> {
        self.db.remove_session(id).await?;
        Ok(())
    }
}

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock is after the Unix epoch")
        .as_secs()
}

#[cfg(test)]
mod tests {
    use secret::Secret;

    use super::*;
    use crate::crypto::KEY_LEN;
    use crate::db::Db;

    async fn service() -> SessionService<Db> {
        let master_key = Secret::new([0; KEY_LEN]);
        let db = Db::in_memory(Cipher::for_database(&master_key)).await;
        SessionService::new(Arc::new(db), Cipher::for_sessions(&master_key))
    }

    #[tokio::test]
    async fn create_resolve_end() {
        let service = service().await;
        let admin_id = Uuid::new_v4();

        let new_session = service.create(admin_id).await.unwrap();
        let (id, session) = service.resolve(&new_session.token).await.unwrap().unwrap();
        assert_eq!(id, new_session.id);
        assert_eq!(session.admin_id, admin_id);

        service.end(id).await.unwrap();
        assert!(service.resolve(&new_session.token).await.unwrap().is_none());
    }

    #[tokio::test]
    async fn rejects_forged_token() {
        let service = service().await;

        for token in ["", "AAAA", "not base64!"] {
            assert!(service.resolve(token).await.unwrap().is_none());
        }
    }

    #[tokio::test]
    async fn token_is_not_the_session_id() {
        let service = service().await;

        let new_session = service.create(Uuid::new_v4()).await.unwrap();

        assert!(!new_session.token.contains(&new_session.id.to_string()));
        assert!(service.resolve(&new_session.id.to_string()).await.unwrap().is_none());
    }

    #[tokio::test]
    async fn expired_session_is_removed() {
        let service = service().await;
        let id = Uuid::new_v4();
        let expired = Session {
            admin_id: Uuid::new_v4(),
            created_at: 0,
            expires_at: 1,
        };
        service.db.add_session(id, &expired).await.unwrap();

        let token = service.token(id).unwrap();

        assert!(service.resolve(&token).await.unwrap().is_none());
        assert_eq!(service.db.session_count().await, 0);
    }
}
