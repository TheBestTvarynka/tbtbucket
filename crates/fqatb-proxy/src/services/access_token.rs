//! Access tokens issued by the proxy.
//!
//! See [`super::token`] for the format, and the Access tokens section of `docs/access-model.md` for the reasoning behind
//! each part.

use std::sync::Arc;

use secret::Secret;
use time::OffsetDateTime;
use tracing::debug;
use uuid::Uuid;

use super::token::{TokenCodec, secret_matches};
use crate::crypto::TokenMac;
use crate::db::{AccessToken, AccessTokenDb, AccessTokenSummary, DbError};
use crate::policy::Policy;
use crate::{Error, Result};

/// Prefix of every access token, which also lets secret scanners recognize them.
pub(crate) const ACCESS_TOKEN_PREFIX: &str = "fgatb_";

/// Longest accepted access token name, in characters.
pub(crate) const MAX_ACCESS_TOKEN_NAME_LEN: usize = 100;

/// Why a new access token was rejected.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub(crate) enum AccessTokenRejection {
    #[error("access token name is empty")]
    EmptyName,

    #[error("access token name is longer than {MAX_ACCESS_TOKEN_NAME_LEN} characters")]
    NameTooLong,

    #[error("access token name is already taken")]
    NameTaken,

    #[error("access token expiration is not in the future")]
    AlreadyExpired,

    #[error("access token permissions use a Bitbucket token that does not exist")]
    UnknownBitbucketToken,
}

/// A newly issued access token.
pub(crate) struct IssuedAccessToken {
    pub(crate) id: Uuid,
    /// The full token, shown once and never stored.
    pub(crate) token: Secret<String>,
}

/// Issues, verifies and removes access tokens.
pub(crate) struct AccessTokenService<D> {
    db: Arc<D>,
    codec: TokenCodec,
}

impl<D> AccessTokenService<D> {
    pub(crate) fn new(db: Arc<D>, mac: TokenMac) -> Self {
        Self {
            db,
            codec: TokenCodec::new(ACCESS_TOKEN_PREFIX, mac),
        }
    }
}

impl<D: AccessTokenDb> AccessTokenService<D> {
    /// Issues a token with the given policy and returns it, the only time the full token is available.
    ///
    /// Fails with [`Error::InvalidAccessToken`] if the input is rejected.
    pub(crate) async fn issue(
        &self,
        name: &str,
        policy: Policy,
        expires_at: OffsetDateTime,
    ) -> Result<IssuedAccessToken> {
        let name = name.trim();
        let now = OffsetDateTime::now_utc();

        let rejection = if name.is_empty() {
            Some(AccessTokenRejection::EmptyName)
        } else if !(name.chars().count() <= MAX_ACCESS_TOKEN_NAME_LEN) {
            Some(AccessTokenRejection::NameTooLong)
        } else if !(now < expires_at) {
            Some(AccessTokenRejection::AlreadyExpired)
        } else {
            None
        };

        if let Some(rejection) = rejection {
            return Err(Error::InvalidAccessToken(rejection));
        }

        let id = Uuid::new_v4();
        let generated = self.codec.generate(id)?;

        let token = AccessToken {
            id,
            name: name.to_owned(),
            secret_hash: generated.secret_hash,
            policy,
            created_at: now,
            expires_at,
        };

        self.db.add_access_token(&token).await.map_err(|error| match error {
            DbError::AccessTokenNameTaken => Error::InvalidAccessToken(AccessTokenRejection::NameTaken),
            DbError::UnknownBitbucketToken => Error::InvalidAccessToken(AccessTokenRejection::UnknownBitbucketToken),
            error => Error::Db(error),
        })?;

        Ok(IssuedAccessToken {
            id,
            token: generated.token,
        })
    }

    /// Returns the access token a client presented, if it is genuine, known and not expired.
    pub(crate) async fn authenticate(&self, presented: &str) -> Result<Option<AccessToken>> {
        let Some((id, secret)) = self.codec.decode(presented) else {
            debug!("Rejected malformed or forged access token");
            return Ok(None);
        };

        let Some(token) = self.db.access_token(id).await? else {
            debug!(access_token_id = %id, "Rejected unknown access token");
            return Ok(None);
        };

        if !secret_matches(secret.as_ref(), &token.secret_hash) {
            debug!(access_token_id = %id, "Rejected access token with a wrong secret");
            return Ok(None);
        }

        if !(OffsetDateTime::now_utc() < token.expires_at) {
            debug!(access_token_id = %id, "Rejected expired access token");
            return Ok(None);
        }

        Ok(Some(token))
    }

    /// Returns all tokens ordered by name.
    pub(crate) async fn list(&self) -> Result<Vec<AccessTokenSummary>> {
        Ok(self.db.access_tokens().await?)
    }

    /// Removes the token and returns whether it existed.
    pub(crate) async fn remove(&self, id: Uuid) -> Result<bool> {
        Ok(self.db.remove_access_token(id).await?)
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;
    use time::Duration;

    use super::*;
    use crate::crypto::{Cipher, KEY_LEN};
    use crate::db::{BitbucketToken, BitbucketTokenDb, Db};
    use crate::services::token::{SECRET_LEN, secret_hash};

    struct Fixture {
        service: AccessTokenService<Db>,
        db: Arc<Db>,
        bitbucket_token: Uuid,
    }

    async fn fixture() -> Fixture {
        let master_key = Secret::new([5; KEY_LEN]);
        let db = Arc::new(Db::in_memory(Cipher::for_database(&master_key)).await);

        let bitbucket_token = Uuid::new_v4();
        db.add_bitbucket_token(&BitbucketToken {
            id: bitbucket_token,
            name: "pr-token".to_owned(),
            token: Secret::new("ATBB-value".to_owned()),
            created_at: OffsetDateTime::now_utc(),
        })
        .await
        .unwrap();

        Fixture {
            service: AccessTokenService::new(Arc::clone(&db), TokenMac::for_access_tokens(&master_key)),
            db,
            bitbucket_token,
        }
    }

    fn policy(bitbucket_token: Uuid) -> Policy {
        serde_json::from_value(json!({ "version": 1, "rules": [
            { "bitbucket_token": bitbucket_token, "actions": ["repo:read"], "project": "PROJ", "repository": "api" }
        ] }))
        .unwrap()
    }

    fn in_days(days: i64) -> OffsetDateTime {
        OffsetDateTime::now_utc() + Duration::days(days)
    }

    fn rejection(result: Result<IssuedAccessToken>) -> AccessTokenRejection {
        match result {
            Err(Error::InvalidAccessToken(rejection)) => rejection,
            Err(other) => panic!("expected a rejection, got {other:?}"),
            Ok(_) => panic!("expected a rejection, got a token"),
        }
    }

    #[tokio::test]
    async fn issue_then_authenticate() {
        let Fixture {
            service,
            bitbucket_token,
            ..
        } = fixture().await;

        let issued = service
            .issue("  ci  ", policy(bitbucket_token), in_days(30))
            .await
            .unwrap();
        let token = issued.token.as_ref();
        assert!(token.starts_with("fgatb_"));
        assert_eq!(token.len(), "fgatb_".len() + 107);

        let authenticated = service.authenticate(token).await.unwrap().unwrap();
        assert_eq!(authenticated.id, issued.id);
        assert_eq!(authenticated.name, "ci");
        assert_eq!(
            authenticated.policy.bitbucket_tokens().into_iter().collect::<Vec<_>>(),
            [bitbucket_token]
        );

        let listed = service.list().await.unwrap();
        assert_eq!((listed.len(), listed[0].id), (1, issued.id));
    }

    #[tokio::test]
    async fn rejects_malformed_and_forged_tokens() {
        let Fixture {
            service,
            bitbucket_token,
            ..
        } = fixture().await;
        let token = service
            .issue("ci", policy(bitbucket_token), in_days(1))
            .await
            .unwrap()
            .token;
        let token = token.as_ref();

        let mut tampered = token.as_bytes().to_vec();
        let last = tampered.len() - 2;
        tampered[last] = if tampered[last] == b'A' { b'B' } else { b'A' };
        let tampered = String::from_utf8(tampered).unwrap();

        for presented in [
            "",
            "fgatb_",
            &token["fgatb_".len()..],
            &format!("ghp_{}", &token["fgatb_".len()..]),
            &token[..token.len() - 1],
            &format!("{token}A"),
            "fgatb_!!!!",
            &tampered,
        ] {
            assert!(service.authenticate(presented).await.unwrap().is_none(), "{presented}");
        }
    }

    #[tokio::test]
    async fn rejects_removed_tokens() {
        let Fixture {
            service,
            bitbucket_token,
            ..
        } = fixture().await;
        let issued = service.issue("ci", policy(bitbucket_token), in_days(1)).await.unwrap();

        assert!(service.remove(issued.id).await.unwrap());

        assert!(service.authenticate(issued.token.as_ref()).await.unwrap().is_none());
        assert!(!service.remove(issued.id).await.unwrap());
    }

    /// Someone holding the MAC key and a token ID still cannot mint a working token without its secret.
    #[tokio::test]
    async fn rejects_minted_token_with_wrong_secret() {
        let Fixture {
            service,
            bitbucket_token,
            ..
        } = fixture().await;
        let issued = service.issue("ci", policy(bitbucket_token), in_days(1)).await.unwrap();

        let forged = service.codec.encode(issued.id, &[0x42; SECRET_LEN]);

        assert!(service.authenticate(forged.as_ref()).await.unwrap().is_none());
    }

    #[tokio::test]
    async fn rejects_expired_tokens() {
        let Fixture {
            service,
            db,
            bitbucket_token,
        } = fixture().await;
        let (id, secret) = (Uuid::new_v4(), [7; SECRET_LEN]);
        db.add_access_token(&AccessToken {
            id,
            name: "old".to_owned(),
            secret_hash: secret_hash(&secret),
            policy: policy(bitbucket_token),
            created_at: in_days(-10),
            expires_at: in_days(-1),
        })
        .await
        .unwrap();

        assert!(
            service
                .authenticate(service.codec.encode(id, &secret).as_ref())
                .await
                .unwrap()
                .is_none()
        );
    }

    #[tokio::test]
    async fn rejects_invalid_input() {
        let Fixture {
            service,
            bitbucket_token,
            ..
        } = fixture().await;
        let long_name = "n".repeat(MAX_ACCESS_TOKEN_NAME_LEN + 1);

        assert_eq!(
            rejection(service.issue(" ", policy(bitbucket_token), in_days(1)).await),
            AccessTokenRejection::EmptyName
        );
        assert_eq!(
            rejection(service.issue(&long_name, policy(bitbucket_token), in_days(1)).await),
            AccessTokenRejection::NameTooLong
        );
        assert_eq!(
            rejection(service.issue("ci", policy(bitbucket_token), in_days(-1)).await),
            AccessTokenRejection::AlreadyExpired
        );
        assert_eq!(
            rejection(service.issue("ci", policy(Uuid::new_v4()), in_days(1)).await),
            AccessTokenRejection::UnknownBitbucketToken
        );
        assert!(service.list().await.unwrap().is_empty());

        service.issue("ci", policy(bitbucket_token), in_days(1)).await.unwrap();
        assert_eq!(
            rejection(service.issue("ci", policy(bitbucket_token), in_days(1)).await),
            AccessTokenRejection::NameTaken
        );
    }
}
