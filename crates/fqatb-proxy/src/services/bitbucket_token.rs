use std::sync::Arc;

use secret::Secret;
use time::OffsetDateTime;
use uuid::Uuid;

use crate::db::{BitbucketToken, BitbucketTokenDb, BitbucketTokenSummary, DbError};
use crate::{Error, Result};

/// Longest accepted token name, in characters.
pub(crate) const MAX_TOKEN_NAME_LEN: usize = 100;

/// Longest accepted token value, in bytes.
pub(crate) const MAX_TOKEN_LEN: usize = 4096;

/// Why a new Bitbucket token was rejected.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub(crate) enum BitbucketTokenRejection {
    #[error("token name is empty")]
    EmptyName,

    #[error("token name is longer than {MAX_TOKEN_NAME_LEN} characters")]
    NameTooLong,

    #[error("token name is already taken")]
    NameTaken,

    #[error("token value is empty")]
    EmptyToken,

    #[error("token value is longer than {MAX_TOKEN_LEN} bytes")]
    TokenTooLong,
}

/// Manages the Bitbucket access tokens.
pub(crate) struct BitbucketTokenService<D> {
    db: Arc<D>,
}

impl<D> BitbucketTokenService<D> {
    pub(crate) fn new(db: Arc<D>) -> Self {
        Self { db }
    }
}

impl<D: BitbucketTokenDb> BitbucketTokenService<D> {
    /// Returns all tokens ordered by name, without their values.
    pub(crate) async fn list(&self) -> Result<Vec<BitbucketTokenSummary>> {
        Ok(self.db.bitbucket_tokens().await?)
    }

    /// Stores a new token and returns its ID.
    ///
    /// Surrounding whitespace is removed from both the name and the value, since it is never meaningful and easily pasted by accident.
    /// Fails with [`Error::InvalidBitbucketToken`] if the input is rejected.
    pub(crate) async fn add(&self, name: &str, token: Secret<String>) -> Result<Uuid> {
        let name = name.trim();
        let token = Secret::new(token.as_ref().trim().to_owned());

        let rejection = if name.is_empty() {
            Some(BitbucketTokenRejection::EmptyName)
        } else if !(name.chars().count() <= MAX_TOKEN_NAME_LEN) {
            Some(BitbucketTokenRejection::NameTooLong)
        } else if token.as_ref().is_empty() {
            Some(BitbucketTokenRejection::EmptyToken)
        } else if !(token.as_ref().len() <= MAX_TOKEN_LEN) {
            Some(BitbucketTokenRejection::TokenTooLong)
        } else {
            None
        };

        if let Some(rejection) = rejection {
            return Err(Error::InvalidBitbucketToken(rejection));
        }

        let token = BitbucketToken {
            id: Uuid::new_v4(),
            name: name.to_owned(),
            token,
            created_at: OffsetDateTime::now_utc(),
        };

        self.db.add_bitbucket_token(&token).await.map_err(|error| match error {
            DbError::BitbucketTokenNameTaken => Error::InvalidBitbucketToken(BitbucketTokenRejection::NameTaken),
            error => Error::Db(error),
        })?;

        Ok(token.id)
    }

    /// Removes the token and returns whether it existed.
    pub(crate) async fn remove(&self, id: Uuid) -> Result<bool> {
        Ok(self.db.remove_bitbucket_token(id).await?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::{Cipher, KEY_LEN};
    use crate::db::Db;

    async fn service() -> BitbucketTokenService<Db> {
        let db = Db::in_memory(Cipher::for_database(&Secret::new([0; KEY_LEN]))).await;
        BitbucketTokenService::new(Arc::new(db))
    }

    fn token(value: &str) -> Secret<String> {
        Secret::new(value.to_owned())
    }

    fn rejection(result: Result<Uuid>) -> BitbucketTokenRejection {
        match result {
            Err(Error::InvalidBitbucketToken(rejection)) => rejection,
            other => panic!("expected a rejection, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn add_list_remove() {
        let service = service().await;

        let before = OffsetDateTime::now_utc().unix_timestamp();
        let id = service.add("  ci  ", token(" ATBB-value\n")).await.unwrap();
        let after = OffsetDateTime::now_utc().unix_timestamp();

        let tokens = service.list().await.unwrap();
        assert_eq!(tokens.len(), 1);
        assert_eq!((tokens[0].id, tokens[0].name.as_str()), (id, "ci"));
        assert!((before..=after).contains(&tokens[0].created_at.unix_timestamp()));

        assert!(service.remove(id).await.unwrap());
        assert!(service.list().await.unwrap().is_empty());
        assert!(!service.remove(id).await.unwrap());
    }

    #[tokio::test]
    async fn rejects_invalid_input() {
        let service = service().await;
        let long_name = "n".repeat(MAX_TOKEN_NAME_LEN + 1);
        let long_token = "t".repeat(MAX_TOKEN_LEN + 1);

        assert_eq!(
            rejection(service.add(" ", token("value")).await),
            BitbucketTokenRejection::EmptyName
        );
        assert_eq!(
            rejection(service.add(&long_name, token("value")).await),
            BitbucketTokenRejection::NameTooLong
        );
        assert_eq!(
            rejection(service.add("ci", token(" \n")).await),
            BitbucketTokenRejection::EmptyToken
        );
        assert_eq!(
            rejection(service.add("ci", token(&long_token)).await),
            BitbucketTokenRejection::TokenTooLong
        );
        assert!(service.list().await.unwrap().is_empty());

        service.add("ci", token("value")).await.unwrap();
        assert_eq!(
            rejection(service.add("ci", token("other")).await),
            BitbucketTokenRejection::NameTaken
        );
    }
}
