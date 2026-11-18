use sqlx::SqlitePool;
use sqlx::sqlite::{SqliteConnectOptions, SqlitePoolOptions};
use time::format_description::well_known::Rfc3339;
use time::{OffsetDateTime, UtcOffset};
use tracing::warn;
use uuid::Uuid;

use super::model::*;
use super::{AdminDb, BitbucketTokenDb, DbError, SessionDb};
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
                if is_unique_violation(&error) {
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
impl BitbucketTokenDb for Db {
    async fn add_bitbucket_token(&self, token: &BitbucketToken) -> Result<(), DbError> {
        let ciphertext = self
            .cipher
            .encrypt(
                bitbucket_token_context(token.id).as_bytes(),
                token.token.as_ref().as_bytes(),
            )
            .map_err(|error| DbError::Encrypt("Bitbucket token", error))?;

        let created_at = format_utc_timestamp(token.created_at)
            .map_err(|error| DbError::FormatTimestamp("Bitbucket token creation", error))?;

        sqlx::query("INSERT INTO bitbucket_tokens (id, name, token, created_at) VALUES (?, ?, ?, ?)")
            .bind(token.id.to_string())
            .bind(&token.name)
            .bind(ciphertext)
            .bind(created_at)
            .execute(&self.pool)
            .await
            .map_err(|error| {
                if is_unique_violation(&error) {
                    DbError::BitbucketTokenNameTaken
                } else {
                    DbError::Sqlx(error)
                }
            })?;

        Ok(())
    }

    async fn bitbucket_tokens(&self) -> Result<Vec<BitbucketTokenSummary>, DbError> {
        let rows: Vec<(String, String, String)> =
            sqlx::query_as("SELECT id, name, created_at FROM bitbucket_tokens ORDER BY name")
                .fetch_all(&self.pool)
                .await?;

        rows.into_iter()
            .map(|(id, name, created_at)| {
                let id = Uuid::parse_str(&id).map_err(|error| DbError::InvalidId("Bitbucket token", error))?;
                let created_at = OffsetDateTime::parse(&created_at, &Rfc3339)
                    .map_err(|error| DbError::InvalidTimestamp("Bitbucket token creation", error))?;
                Ok(BitbucketTokenSummary { id, name, created_at })
            })
            .collect()
    }

    async fn remove_bitbucket_token(&self, id: Uuid) -> Result<bool, DbError> {
        let result = sqlx::query("DELETE FROM bitbucket_tokens WHERE id = ?")
            .bind(id.to_string())
            .execute(&self.pool)
            .await?;

        Ok(0 < result.rows_affected())
    }
}

/// Formats a timestamp as RFC 3339 in UTC with whole seconds, e.g. `2026-11-18T20:00:00Z`.
///
/// This is the only shape the `created_at` columns accept.
fn format_utc_timestamp(at: OffsetDateTime) -> Result<String, time::error::Format> {
    at.to_offset(UtcOffset::UTC)
        .replace_nanosecond(0)
        .expect("0 is a valid nanosecond")
        .format(&Rfc3339)
}

fn is_unique_violation(error: &sqlx::Error) -> bool {
    error
        .as_database_error()
        .is_some_and(|db_error| db_error.is_unique_violation())
}

/// Binds a Bitbucket token ciphertext to its row, so that it does not decrypt under another ID.
fn bitbucket_token_context(id: Uuid) -> String {
    format!("bitbucket_tokens.token:{id}")
}

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

    fn bitbucket_token(name: &str, token: &str) -> BitbucketToken {
        BitbucketToken {
            id: Uuid::new_v4(),
            name: name.to_owned(),
            token: Secret::new(token.to_owned()),
            created_at: OffsetDateTime::now_utc(),
        }
    }

    #[tokio::test]
    async fn bitbucket_token_created_at_stored_as_utc_seconds() {
        let db = db().await;
        let mut token = bitbucket_token("ci", "value");
        // 2026-11-18 22:30:15.75 at UTC+02:00, i.e. 20:30:15.75 UTC.
        token.created_at = OffsetDateTime::from_unix_timestamp_nanos(1_795_033_815_750_000_000)
            .unwrap()
            .to_offset(UtcOffset::from_hms(2, 0, 0).unwrap());
        db.add_bitbucket_token(&token).await.unwrap();

        let stored: String = sqlx::query_scalar("SELECT created_at FROM bitbucket_tokens")
            .fetch_one(&db.pool)
            .await
            .unwrap();
        assert_eq!(stored, "2026-11-18T20:30:15Z");

        let listed = db.bitbucket_tokens().await.unwrap().remove(0).created_at;
        assert_eq!(listed.offset(), UtcOffset::UTC);
        assert_eq!(listed.unix_timestamp(), 1_795_033_815);
    }

    #[tokio::test]
    async fn created_at_rejects_other_formats() {
        let db = db().await;

        for created_at in [
            "2026-11-18 20:00:00",
            "2026-11-18T20:00:00+02:00",
            "2026-11-18T20:00:00.5Z",
        ] {
            let result =
                sqlx::query("INSERT INTO bitbucket_tokens (id, name, token, created_at) VALUES (?, ?, x'00', ?)")
                    .bind(Uuid::new_v4().to_string())
                    .bind(created_at)
                    .bind(created_at)
                    .execute(&db.pool)
                    .await;
            assert!(result.is_err(), "{created_at}");
        }
    }

    /// Applies the migrations one by one to check that tokens added before `created_at` existed get the fixed time.
    #[tokio::test]
    async fn created_at_migration_backfills_existing_tokens() {
        let pool = SqlitePoolOptions::new()
            .max_connections(1)
            .connect("sqlite::memory:")
            .await
            .unwrap();

        for sql in [
            include_str!("../../migrations/20261118000000_admin_and_sessions.sql"),
            include_str!("../../migrations/20261118220000_bitbucket_tokens.sql"),
        ] {
            sqlx::raw_sql(sql).execute(&pool).await.unwrap();
        }
        sqlx::query("INSERT INTO bitbucket_tokens (id, name, token) VALUES ('legacy-id', 'legacy', x'01020304')")
            .execute(&pool)
            .await
            .unwrap();

        sqlx::raw_sql(include_str!(
            "../../migrations/20261118230000_bitbucket_tokens_created_at.sql"
        ))
        .execute(&pool)
        .await
        .unwrap();

        let row: (String, String, Vec<u8>, String) =
            sqlx::query_as("SELECT id, name, token, created_at FROM bitbucket_tokens")
                .fetch_one(&pool)
                .await
                .unwrap();
        assert_eq!(
            row,
            (
                "legacy-id".to_owned(),
                "legacy".to_owned(),
                vec![1, 2, 3, 4],
                "2026-11-18T20:00:00Z".to_owned()
            )
        );

        // The column has no default, so an insert that forgets it fails instead of getting the backfill time.
        let without_created_at =
            sqlx::query("INSERT INTO bitbucket_tokens (id, name, token) VALUES ('new-id', 'new', x'00')")
                .execute(&pool)
                .await;
        assert!(without_created_at.is_err());
    }

    #[tokio::test]
    async fn bitbucket_tokens_add_list_remove() {
        let db = db().await;
        assert!(db.bitbucket_tokens().await.unwrap().is_empty());

        let (beta, alpha) = (bitbucket_token("beta", "token-b"), bitbucket_token("alpha", "token-a"));
        db.add_bitbucket_token(&beta).await.unwrap();
        db.add_bitbucket_token(&alpha).await.unwrap();

        let names: Vec<_> = db
            .bitbucket_tokens()
            .await
            .unwrap()
            .into_iter()
            .map(|token| (token.id, token.name))
            .collect();
        assert_eq!(names, [(alpha.id, "alpha".to_owned()), (beta.id, "beta".to_owned())]);

        assert!(db.remove_bitbucket_token(alpha.id).await.unwrap());
        assert!(!db.remove_bitbucket_token(alpha.id).await.unwrap());
        assert_eq!(db.bitbucket_tokens().await.unwrap().len(), 1);
    }

    #[tokio::test]
    async fn bitbucket_token_names_are_unique() {
        let db = db().await;

        db.add_bitbucket_token(&bitbucket_token("ci", "one")).await.unwrap();

        assert!(matches!(
            db.add_bitbucket_token(&bitbucket_token("ci", "two")).await,
            Err(DbError::BitbucketTokenNameTaken)
        ));
    }

    #[tokio::test]
    async fn bitbucket_token_stored_encrypted() {
        let db = db().await;
        let token = bitbucket_token("ci", "ATBB-plaintext-token-value");
        db.add_bitbucket_token(&token).await.unwrap();

        let (name, ciphertext): (String, Vec<u8>) = sqlx::query_as("SELECT name, token FROM bitbucket_tokens")
            .fetch_one(&db.pool)
            .await
            .unwrap();
        assert_eq!(name, "ci");
        assert!(
            !ciphertext
                .windows(token.token.as_ref().len())
                .any(|window| window == token.token.as_ref().as_bytes())
        );

        let decrypted = db
            .cipher
            .decrypt(bitbucket_token_context(token.id).as_bytes(), &ciphertext)
            .unwrap();
        assert_eq!(decrypted, token.token.as_ref().as_bytes());
        assert!(
            db.cipher
                .decrypt(bitbucket_token_context(Uuid::new_v4()).as_bytes(), &ciphertext)
                .is_err()
        );
    }
}
