use secret::Secret;
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use uuid::Uuid;

use crate::policy::Policy;

#[derive(Debug)]
pub(crate) struct Admin {
    pub(crate) id: Uuid,
    /// Argon2id hash in the PHC string format.
    pub(crate) password_hash: String,
}

/// An admin session, stored as encrypted JSON.
#[derive(Debug, Serialize, Deserialize)]
pub(crate) struct Session {
    pub(crate) admin_id: Uuid,
    /// Unix timestamp in seconds.
    pub(crate) created_at: u64,
    /// Unix timestamp in seconds.
    pub(crate) expires_at: u64,
}

impl Session {
    pub(crate) fn is_expired(&self, now: u64) -> bool {
        !(now < self.expires_at)
    }
}

/// A Bitbucket access token, with its value decrypted.
#[derive(Debug)]
pub(crate) struct BitbucketToken {
    pub(crate) id: Uuid,
    /// Unique and immutable after creation.
    pub(crate) name: String,
    pub(crate) token: Secret<String>,
    /// When the token was added, stored in UTC with whole-second precision.
    pub(crate) created_at: OffsetDateTime,
}

/// A Bitbucket access token without its value.
#[derive(Debug)]
pub(crate) struct BitbucketTokenSummary {
    pub(crate) id: Uuid,
    pub(crate) name: String,
    /// When the token was added, in UTC.
    pub(crate) created_at: OffsetDateTime,
}

/// An access token issued by the proxy, with its policy decrypted.
#[derive(Debug)]
pub(crate) struct AccessToken {
    pub(crate) id: Uuid,
    /// Unique and immutable after creation.
    pub(crate) name: String,
    /// SHA-256 of the random part of the token.
    pub(crate) secret_hash: [u8; 32],
    pub(crate) policy: Policy,
    /// Stored in UTC with whole-second precision.
    pub(crate) created_at: OffsetDateTime,
    /// Stored in UTC with whole-second precision.
    pub(crate) expires_at: OffsetDateTime,
}

/// An access token without its secret hash and policy.
#[derive(Debug)]
pub(crate) struct AccessTokenSummary {
    pub(crate) id: Uuid,
    pub(crate) name: String,
    pub(crate) created_at: OffsetDateTime,
    pub(crate) expires_at: OffsetDateTime,
}
