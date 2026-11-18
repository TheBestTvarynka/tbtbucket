use serde::{Deserialize, Serialize};
use uuid::Uuid;

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
