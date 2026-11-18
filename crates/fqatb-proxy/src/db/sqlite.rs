use sqlx::SqlitePool;
use sqlx::sqlite::{SqliteConnectOptions, SqlitePoolOptions};
use tracing::warn;
use uuid::Uuid;

use super::model::*;
use super::{AdminDb, DbError, SessionDb};
use crate::crypto::Cipher;
use crate::error::report;

/// SQLite storage with encryption of stored values.
pub(crate) struct Db {
    pool: SqlitePool,
    cipher: Cipher,
}

impl Db {
    /// Opens the database, creating the file if needed, and applies pending migrations.
    ///
    /// `cipher` encrypts every stored value except identifiers and password hashes.
    pub(crate) async fn connect(url: &str, cipher: Cipher) -> Result<Self, DbError> {
        let options = url.parse::<SqliteConnectOptions>()?.create_if_missing(true);

        let pool = SqlitePoolOptions::new().connect_with(options).await?;

        Self::with_pool(pool, cipher).await
    }

    async fn with_pool(pool: SqlitePool, cipher: Cipher) -> Result<Self, DbError> {
        sqlx::migrate!().run(&pool).await?;

        Ok(Self { pool, cipher })
    }

    /// Checks that the database answers queries.
    pub(crate) async fn ping(&self) -> Result<(), DbError> {
        sqlx::query("SELECT 1").execute(&self.pool).await?;
        Ok(())
    }

    /// Closes all connections, waiting for in-flight queries to finish.
    pub(crate) async fn close(&self) {
        self.pool.close().await;
    }

    fn decrypt_session(&self, id: Uuid, ciphertext: &[u8]) -> Result<Session, DbError> {
        let json = self
            .cipher
            .decrypt(session_context(id).as_bytes(), ciphertext)
            .map_err(|error| DbError::Decrypt("session", error))?;

        serde_json::from_slice(&json).map_err(|error| DbError::Deserialize("session", error))
    }
}

impl AdminDb for Db {
    async fn init_admin(&self, admin: &Admin) -> Result<(), DbError> {
        sqlx::query("INSERT INTO admin (id, password_hash) VALUES (?, ?)")
            .bind(admin.id.to_string())
            .bind(&admin.password_hash)
            .execute(&self.pool)
            .await
            .map_err(|error| {
                // The `admin_singleton` index allows a single row.
                if error
                    .as_database_error()
                    .is_some_and(|db_error| db_error.is_unique_violation())
                {
                    DbError::AdminAlreadyExists
                } else {
                    DbError::Sqlx(error)
                }
            })?;

        Ok(())
    }

    async fn admin(&self) -> Result<Option<Admin>, DbError> {
        let row: Option<(String, String)> = sqlx::query_as("SELECT id, password_hash FROM admin")
            .fetch_optional(&self.pool)
            .await?;

        row.map(|(id, password_hash)| {
            let id = Uuid::parse_str(&id).map_err(|error| DbError::InvalidId("admin", error))?;
            Ok(Admin { id, password_hash })
        })
        .transpose()
    }
}

impl SessionDb for Db {
    async fn add_session(&self, id: Uuid, session: &Session) -> Result<(), DbError> {
        let ciphertext = {
            let json = serde_json::to_vec(session).map_err(|error| DbError::Serialize("session", error))?;
            self.cipher
                .encrypt(session_context(id).as_bytes(), &json)
                .map_err(|error| DbError::Encrypt("session", error))?
        };

        sqlx::query("INSERT INTO sessions (id, ciphertext) VALUES (?, ?)")
            .bind(id.to_string())
            .bind(ciphertext)
            .execute(&self.pool)
            .await?;

        Ok(())
    }

    async fn session(&self, id: Uuid) -> Result<Option<Session>, DbError> {
        let ciphertext: Option<Vec<u8>> = sqlx::query_scalar("SELECT ciphertext FROM sessions WHERE id = ?")
            .bind(id.to_string())
            .fetch_optional(&self.pool)
            .await?;

        ciphertext
            .map(|ciphertext| self.decrypt_session(id, &ciphertext))
            .transpose()
    }

    async fn remove_session(&self, id: Uuid) -> Result<(), DbError> {
        sqlx::query("DELETE FROM sessions WHERE id = ?")
            .bind(id.to_string())
            .execute(&self.pool)
            .await?;

        Ok(())
    }

    async fn remove_expired_sessions(&self, now: u64) -> Result<(), DbError> {
        // Expiry lives inside the encrypted payload, so every row has to be decrypted.
        // With a single admin the table stays small.
        let rows: Vec<(String, Vec<u8>)> = sqlx::query_as("SELECT id, ciphertext FROM sessions")
            .fetch_all(&self.pool)
            .await?;

        for (id, ciphertext) in rows {
            let session = Uuid::parse_str(&id)
                .map_err(|error| DbError::InvalidId("session", error))
                .and_then(|uuid| self.decrypt_session(uuid, &ciphertext));

            let live = match session {
                Ok(session) => !session.is_expired(now),
                Err(error) => {
                    warn!(%id, error = report(&error), "Removing unreadable session");
                    false
                }
            };

            if !live {
                sqlx::query("DELETE FROM sessions WHERE id = ?")
                    .bind(id)
                    .execute(&self.pool)
                    .await?;
            }
        }

        Ok(())
    }
}

/// Binds a session ciphertext to its row, so that it does not decrypt under another ID.
fn session_context(id: Uuid) -> String {
    format!("sessions.ciphertext:{id}")
}

#[cfg(test)]
impl Db {
    /// Opens a migrated in-memory database.
    pub(crate) async fn in_memory(cipher: Cipher) -> Self {
        // An in-memory database exists per connection, so the pool must not open a second one.
        let pool = SqlitePoolOptions::new()
            .max_connections(1)
            .connect("sqlite::memory:")
            .await
            .unwrap();

        Self::with_pool(pool, cipher).await.unwrap()
    }

    pub(crate) async fn session_count(&self) -> i64 {
        sqlx::query_scalar("SELECT COUNT(*) FROM sessions")
            .fetch_one(&self.pool)
            .await
            .unwrap()
    }
}

#[cfg(test)]
mod tests {
    use secret::Secret;

    use super::*;
    use crate::crypto::KEY_LEN;

    async fn db() -> Db {
        Db::in_memory(Cipher::for_database(&Secret::new([3; KEY_LEN]))).await
    }

    fn admin() -> Admin {
        Admin {
            id: Uuid::new_v4(),
            password_hash: "$argon2id$v=19$m=19456,t=2,p=1$c2FsdA$aGFzaA".to_owned(),
        }
    }

    fn session(expires_at: u64) -> Session {
        Session {
            admin_id: Uuid::new_v4(),
            created_at: 0,
            expires_at,
        }
    }

    #[tokio::test]
    async fn admin_round_trip() {
        let db = db().await;
        assert!(db.admin().await.unwrap().is_none());

        let admin = admin();
        db.init_admin(&admin).await.unwrap();

        let found = db.admin().await.unwrap().unwrap();
        assert_eq!(found.id, admin.id);
        assert_eq!(found.password_hash, admin.password_hash);
    }

    #[tokio::test]
    async fn only_one_admin_allowed() {
        let db = db().await;

        db.init_admin(&admin()).await.unwrap();

        assert!(matches!(
            db.init_admin(&admin()).await,
            Err(DbError::AdminAlreadyExists)
        ));
    }

    #[tokio::test]
    async fn session_round_trip() {
        let db = db().await;
        let (id, session) = (Uuid::new_v4(), session(100));

        db.add_session(id, &session).await.unwrap();
        let found = db.session(id).await.unwrap().unwrap();

        assert_eq!(found.admin_id, session.admin_id);
        assert_eq!(found.expires_at, session.expires_at);
        assert!(db.session(Uuid::new_v4()).await.unwrap().is_none());

        db.remove_session(id).await.unwrap();
        assert!(db.session(id).await.unwrap().is_none());
    }

    #[tokio::test]
    async fn session_stored_encrypted() {
        let db = db().await;
        let session = session(100);

        db.add_session(Uuid::new_v4(), &session).await.unwrap();

        let ciphertext: Vec<u8> = sqlx::query_scalar("SELECT ciphertext FROM sessions")
            .fetch_one(&db.pool)
            .await
            .unwrap();
        let admin_id = session.admin_id.to_string();
        assert!(
            !ciphertext
                .windows(admin_id.len())
                .any(|window| window == admin_id.as_bytes())
        );
    }

    #[tokio::test]
    async fn session_ciphertext_bound_to_row() {
        let db = db().await;
        let other_id = Uuid::new_v4();

        db.add_session(Uuid::new_v4(), &session(100)).await.unwrap();
        sqlx::query("UPDATE sessions SET id = ?")
            .bind(other_id.to_string())
            .execute(&db.pool)
            .await
            .unwrap();

        assert!(matches!(db.session(other_id).await, Err(DbError::Decrypt(..))));
    }

    #[tokio::test]
    async fn remove_expired_sessions_keeps_live_ones() {
        let db = db().await;
        let live = Uuid::new_v4();

        db.add_session(live, &session(100)).await.unwrap();
        db.add_session(Uuid::new_v4(), &session(50)).await.unwrap();
        sqlx::query("INSERT INTO sessions (id, ciphertext) VALUES (?, x'00')")
            .bind(Uuid::new_v4().to_string())
            .execute(&db.pool)
            .await
            .unwrap();

        db.remove_expired_sessions(50).await.unwrap();

        assert_eq!(db.session_count().await, 1);
        assert!(db.session(live).await.unwrap().is_some());
    }
}
