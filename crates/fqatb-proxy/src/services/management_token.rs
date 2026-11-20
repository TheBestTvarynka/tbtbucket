//! Management tokens, which authenticate the management API.
//!
//! They use the format of [`super::token`] with their own prefix and HMAC key, so a management token never passes for an
//! access token or the other way round.

use std::sync::Arc;

use secret::Secret;
use time::OffsetDateTime;
use tracing::debug;
use uuid::Uuid;

use super::token::{TokenCodec, secret_matches};
use crate::crypto::TokenMac;
use crate::db::{DbError, ManagementToken, ManagementTokenDb, ManagementTokenSummary};
use crate::{Error, Result};

/// Prefix of every management token, which also lets secret scanners recognize them.
pub(crate) const MANAGEMENT_TOKEN_PREFIX: &str = "fgatbm_";

/// Longest accepted management token name, in characters.
pub(crate) const MAX_MANAGEMENT_TOKEN_NAME_LEN: usize = 100;

/// Why a new management token was rejected.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub(crate) enum ManagementTokenRejection {
    #[error("management token name is empty")]
    EmptyName,

    #[error("management token name is longer than {MAX_MANAGEMENT_TOKEN_NAME_LEN} characters")]
    NameTooLong,

    #[error("management token name is already taken")]
    NameTaken,

    #[error("management token expiration is not in the future")]
    AlreadyExpired,
}

/// A newly issued management token.
pub(crate) struct IssuedManagementToken {
    pub(crate) id: Uuid,
    /// The full token, shown once and never stored.
    pub(crate) token: Secret<String>,
}

/// Issues, verifies and removes management tokens.
pub(crate) struct ManagementTokenService<D> {
    db: Arc<D>,
    codec: TokenCodec,
}

impl<D> ManagementTokenService<D> {
    pub(crate) fn new(db: Arc<D>, mac: TokenMac) -> Self {
        Self {
            db,
            codec: TokenCodec::new(MANAGEMENT_TOKEN_PREFIX, mac),
        }
    }
}

impl<D: ManagementTokenDb> ManagementTokenService<D> {
    /// Issues a token and returns it, the only time the full token is available.
    ///
    /// Fails with [`Error::InvalidManagementToken`] if the input is rejected.
    pub(crate) async fn issue(&self, name: &str, expires_at: OffsetDateTime) -> Result<IssuedManagementToken> {
        let name = name.trim();
        let now = OffsetDateTime::now_utc();

        let rejection = if name.is_empty() {
            Some(ManagementTokenRejection::EmptyName)
        } else if !(name.chars().count() <= MAX_MANAGEMENT_TOKEN_NAME_LEN) {
            Some(ManagementTokenRejection::NameTooLong)
        } else if !(now < expires_at) {
            Some(ManagementTokenRejection::AlreadyExpired)
        } else {
            None
        };

        if let Some(rejection) = rejection {
            return Err(Error::InvalidManagementToken(rejection));
        }

        let id = Uuid::new_v4();
        let generated = self.codec.generate(id)?;

        let token = ManagementToken {
            id,
            name: name.to_owned(),
            secret_hash: generated.secret_hash,
            created_at: now,
            expires_at,
        };

        self.db
            .add_management_token(&token)
            .await
            .map_err(|error| match error {
                DbError::ManagementTokenNameTaken => Error::InvalidManagementToken(ManagementTokenRejection::NameTaken),
                error => Error::Db(error),
            })?;

        Ok(IssuedManagementToken {
            id,
            token: generated.token,
        })
    }

    /// Returns the management token a client presented, if it is genuine, known and not expired.
    pub(crate) async fn authenticate(&self, presented: &str) -> Result<Option<ManagementTokenSummary>> {
        let Some((id, secret)) = self.codec.decode(presented) else {
            debug!("Rejected malformed or forged management token");
            return Ok(None);
        };

        let Some(token) = self.db.management_token(id).await? else {
            debug!(management_token_id = %id, "Rejected unknown management token");
            return Ok(None);
        };

        if !secret_matches(secret.as_ref(), &token.secret_hash) {
            debug!(management_token_id = %id, "Rejected management token with a wrong secret");
            return Ok(None);
        }

        if !(OffsetDateTime::now_utc() < token.expires_at) {
            debug!(management_token_id = %id, "Rejected expired management token");
            return Ok(None);
        }

        Ok(Some(ManagementTokenSummary {
            id,
            name: token.name,
            created_at: token.created_at,
            expires_at: token.expires_at,
        }))
    }

    /// Returns all tokens ordered by name.
    pub(crate) async fn list(&self) -> Result<Vec<ManagementTokenSummary>> {
        Ok(self.db.management_tokens().await?)
    }

    /// Removes the token and returns whether it existed.
    pub(crate) async fn remove(&self, id: Uuid) -> Result<bool> {
        Ok(self.db.remove_management_token(id).await?)
    }
}

#[cfg(test)]
mod tests {
    use time::Duration;

    use super::*;
    use crate::crypto::{Cipher, KEY_LEN};
    use crate::db::Db;
    use crate::services::AccessTokenService;
    use crate::services::token::{SECRET_LEN, secret_hash};

    const MASTER_KEY: [u8; KEY_LEN] = [6; KEY_LEN];

    async fn service() -> (ManagementTokenService<Db>, Arc<Db>) {
        let master_key = Secret::new(MASTER_KEY);
        let db = Arc::new(Db::in_memory(Cipher::for_database(&master_key)).await);
        let service = ManagementTokenService::new(Arc::clone(&db), TokenMac::for_management_tokens(&master_key));
        (service, db)
    }

    fn in_days(days: i64) -> OffsetDateTime {
        OffsetDateTime::now_utc() + Duration::days(days)
    }

    fn rejection(result: Result<IssuedManagementToken>) -> ManagementTokenRejection {
        match result {
            Err(Error::InvalidManagementToken(rejection)) => rejection,
            Err(other) => panic!("expected a rejection, got {other:?}"),
            Ok(_) => panic!("expected a rejection, got a token"),
        }
    }

    #[tokio::test]
    async fn issue_then_authenticate() {
        let (service, _db) = service().await;

        let issued = service.issue("  ci  ", in_days(7)).await.unwrap();
        let token = issued.token.as_ref();
        assert!(token.starts_with("fgatbm_"));
        assert_eq!(token.len(), "fgatbm_".len() + 107);

        let authenticated = service.authenticate(token).await.unwrap().unwrap();
        assert_eq!((authenticated.id, authenticated.name.as_str()), (issued.id, "ci"));

        let listed = service.list().await.unwrap();
        assert_eq!((listed.len(), listed[0].id), (1, issued.id));

        assert!(service.remove(issued.id).await.unwrap());
        assert!(service.authenticate(token).await.unwrap().is_none());
        assert!(!service.remove(issued.id).await.unwrap());
    }

    #[tokio::test]
    async fn rejects_malformed_forged_and_expired_tokens() {
        let (service, db) = service().await;
        let issued = service.issue("ci", in_days(1)).await.unwrap();
        let token = issued.token.as_ref();

        let mut tampered = token.as_bytes().to_vec();
        let last = tampered.len() - 2;
        tampered[last] = if tampered[last] == b'A' { b'B' } else { b'A' };
        let tampered = String::from_utf8(tampered).unwrap();

        // Someone holding the MAC key and a token ID still cannot mint a working token without its secret.
        let wrong_secret = service.codec.encode(issued.id, &[0x42; SECRET_LEN]);
        let unknown = service.codec.encode(Uuid::new_v4(), &[0x42; SECRET_LEN]);

        let (expired_id, expired_secret) = (Uuid::new_v4(), [7; SECRET_LEN]);
        db.add_management_token(&ManagementToken {
            id: expired_id,
            name: "old".to_owned(),
            secret_hash: secret_hash(&expired_secret),
            created_at: in_days(-10),
            expires_at: in_days(-1),
        })
        .await
        .unwrap();
        let expired = service.codec.encode(expired_id, &expired_secret);

        for presented in [
            "",
            "fgatbm_",
            &token["fgatbm_".len()..],
            &token[..token.len() - 1],
            &tampered,
            wrong_secret.as_ref(),
            unknown.as_ref(),
            expired.as_ref(),
        ] {
            assert!(service.authenticate(presented).await.unwrap().is_none(), "{presented}");
        }
    }

    /// The two token kinds use different HMAC keys, so neither passes for the other even when the IDs match.
    #[tokio::test]
    async fn access_tokens_are_not_management_tokens() {
        let (service, db) = service().await;
        let master_key = Secret::new(MASTER_KEY);
        let access_tokens = AccessTokenService::new(Arc::clone(&db), TokenMac::for_access_tokens(&master_key));

        let issued = service.issue("ci", in_days(1)).await.unwrap();
        let disguised = issued.token.as_ref().replacen("fgatbm_", "fgatb_", 1);
        assert!(access_tokens.authenticate(&disguised).await.unwrap().is_none());

        let access_token_mac = TokenCodec::new(MANAGEMENT_TOKEN_PREFIX, TokenMac::for_access_tokens(&master_key));
        let (_, secret) = service.codec.decode(issued.token.as_ref()).unwrap();
        let wrong_key = access_token_mac.encode(issued.id, secret.as_ref());
        assert!(service.authenticate(wrong_key.as_ref()).await.unwrap().is_none());
    }

    #[tokio::test]
    async fn rejects_invalid_input() {
        let (service, _db) = service().await;
        let long_name = "n".repeat(MAX_MANAGEMENT_TOKEN_NAME_LEN + 1);

        assert_eq!(
            rejection(service.issue(" ", in_days(1)).await),
            ManagementTokenRejection::EmptyName
        );
        assert_eq!(
            rejection(service.issue(&long_name, in_days(1)).await),
            ManagementTokenRejection::NameTooLong
        );
        assert_eq!(
            rejection(service.issue("ci", in_days(-1)).await),
            ManagementTokenRejection::AlreadyExpired
        );
        assert!(service.list().await.unwrap().is_empty());

        service.issue("ci", in_days(1)).await.unwrap();
        assert_eq!(
            rejection(service.issue("ci", in_days(1)).await),
            ManagementTokenRejection::NameTaken
        );
    }
}
