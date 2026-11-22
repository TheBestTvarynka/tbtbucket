//! The format shared by the tokens the proxy hands out: access tokens and management tokens.
//!
//! A token is its kind's prefix followed by unpadded URL-safe base64 of
//! `id (16) ‖ secret (32) ‖ HMAC-SHA256(id ‖ secret) (32)`.
//! The tag rejects guessed and forged tokens before any database lookup, and the ID finds the row.
//! Only the SHA-256 of the secret is stored, so the database alone never yields a working token.

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use secret::Secret;
use sha2::{Digest as _, Sha256};
use subtle::ConstantTimeEq as _;
use uuid::Uuid;

use crate::crypto::{TOKEN_TAG_LEN, TokenMac};
use crate::{Error, Result};

const ID_LEN: usize = 16;
pub(crate) const SECRET_LEN: usize = 32;
const PAYLOAD_LEN: usize = ID_LEN + SECRET_LEN + TOKEN_TAG_LEN;

/// A newly generated token, before it is stored.
pub(crate) struct GeneratedToken {
    /// The full token, shown once and never stored.
    pub(crate) token: Secret<String>,
    pub(crate) secret_hash: [u8; 32],
}

/// Encodes and decodes the tokens of one kind.
pub(crate) struct TokenCodec {
    prefix: &'static str,
    mac: TokenMac,
}

impl TokenCodec {
    pub(crate) fn new(prefix: &'static str, mac: TokenMac) -> Self {
        Self { prefix, mac }
    }

    /// Generates a token with a fresh random secret for the row `id`.
    pub(crate) fn generate(&self, id: Uuid) -> Result<GeneratedToken> {
        let mut secret = Secret::new([0; SECRET_LEN]);
        getrandom::fill(secret.as_mut()).map_err(Error::Random)?;

        Ok(GeneratedToken {
            token: self.encode(id, secret.as_ref()),
            secret_hash: secret_hash(secret.as_ref()),
        })
    }

    pub(crate) fn encode(&self, id: Uuid, secret: &[u8; SECRET_LEN]) -> Secret<String> {
        let mut payload = Secret::new(Vec::with_capacity(PAYLOAD_LEN));
        payload.as_mut().extend_from_slice(id.as_bytes());
        payload.as_mut().extend_from_slice(secret);
        let tag = self.mac.tag(payload.as_ref());
        payload.as_mut().extend_from_slice(&tag);

        Secret::new(format!("{}{}", self.prefix, URL_SAFE_NO_PAD.encode(payload.as_ref())))
    }

    /// Returns the ID and secret of a token of this kind minted by this proxy, checking its tag in constant time.
    pub(crate) fn decode(&self, presented: &str) -> Option<(Uuid, Secret<[u8; SECRET_LEN]>)> {
        let encoded = presented.strip_prefix(self.prefix)?;
        let payload = Secret::new(URL_SAFE_NO_PAD.decode(encoded).ok()?);

        if payload.as_ref().len() != PAYLOAD_LEN {
            return None;
        }

        let (message, tag) = payload.as_ref().split_at(ID_LEN + SECRET_LEN);
        if !self.mac.verify(message, tag) {
            return None;
        }

        let (id, secret) = message.split_at(ID_LEN);
        let id = Uuid::from_slice(id).expect("the ID part is 16 bytes long");
        let secret = Secret::new(secret.try_into().expect("the secret part is 32 bytes long"));

        Some((id, secret))
    }
}

pub(crate) fn secret_hash(secret: &[u8; SECRET_LEN]) -> [u8; 32] {
    Sha256::digest(secret).into()
}

/// Compares the secret with a stored hash in constant time.
pub(crate) fn secret_matches(secret: &[u8; SECRET_LEN], stored_hash: &[u8; 32]) -> bool {
    secret_hash(secret).ct_eq(stored_hash).into()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::KEY_LEN;

    fn codec(prefix: &'static str) -> TokenCodec {
        TokenCodec::new(prefix, TokenMac::for_access_tokens(&Secret::new([3; KEY_LEN])))
    }

    #[test]
    fn round_trip() {
        let codec = codec("test_");
        let id = Uuid::new_v4();

        let generated = codec.generate(id).unwrap();
        let token = generated.token.as_ref();
        assert!(token.starts_with("test_"));
        assert_eq!(token.len(), "test_".len() + 107);

        let (decoded_id, secret) = codec.decode(token).unwrap();
        assert_eq!(decoded_id, id);
        assert!(secret_matches(secret.as_ref(), &generated.secret_hash));
        assert!(!secret_matches(&[0; SECRET_LEN], &generated.secret_hash));
    }

    #[test]
    fn rejects_other_prefixes() {
        let token = codec("one_").generate(Uuid::new_v4()).unwrap().token;

        assert!(codec("two_").decode(token.as_ref()).is_none());
        assert!(
            codec("two_")
                .decode(&token.as_ref().replacen("one_", "two_", 1))
                .is_some()
        );
    }
}
