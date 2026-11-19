//! Authenticated encryption for everything the proxy stores or hands out.
//!
//! Messages are encrypted with AES-256-GCM.
//! Keys are derived from the master key with HKDF-SHA256 ([RFC 5869]), using a different hardcoded salt per purpose.
//! The database and session ciphers therefore use independent keys, and neither can open the other's messages.
//!
//! Every message is bound to a caller-chosen context, so that a ciphertext cannot be moved to another column, row or cookie.
//!
//! Access tokens are authenticated with [`TokenMac`], an HMAC-SHA256 key derived the same way with its own salt.
//!
//! [RFC 5869]: https://www.rfc-editor.org/rfc/rfc5869

use aes_gcm::aead::{Aead as _, KeyInit as _, Payload};
use aes_gcm::{Aes256Gcm, Nonce};
use hkdf::Hkdf;
use hmac::{Hmac, Mac as _};
use secret::Secret;
use sha2::Sha256;

/// Length of the master key in bytes.
pub(crate) const KEY_LEN: usize = 32;

const FORMAT_VERSION: u8 = 1;
const NONCE_LEN: usize = 12;
const TAG_LEN: usize = 16;
const HEADER_LEN: usize = 1 /* FormatVersion */ + NONCE_LEN;

const KEY_INFO: &[u8] = b"fqatb-proxy AES-256-GCM key";

const TOKEN_MAC_KEY_INFO: &[u8] = b"fqatb-proxy access token HMAC-SHA256 key";

/// Length of an access token tag in bytes.
pub(crate) const TOKEN_TAG_LEN: usize = 32;

const DATABASE_SALT: [u8; 32] = [
    0xf9, 0xf2, 0xcc, 0x9a, 0xed, 0x97, 0x68, 0x72, 0xfe, 0x58, 0xff, 0x15, 0xed, 0x7e, 0x97, 0x7b, 0xff, 0xce, 0x14,
    0xd1, 0x61, 0xcd, 0x6a, 0x4a, 0x73, 0x94, 0x01, 0x59, 0xe4, 0x44, 0xa4, 0xd0,
];

const SESSION_SALT: [u8; 32] = [
    0x4c, 0x3c, 0x61, 0xfb, 0x0d, 0x34, 0xe4, 0x88, 0xab, 0xb7, 0x91, 0x53, 0xfe, 0xad, 0x6b, 0xc7, 0x92, 0x47, 0x2c,
    0xc4, 0xd2, 0x8e, 0x84, 0x4a, 0x1c, 0xb7, 0x47, 0x1b, 0x4e, 0xab, 0xf1, 0x61,
];

const TOKEN_MAC_SALT: [u8; 32] = [
    0xed, 0xa7, 0xd3, 0x4a, 0x90, 0x4b, 0x23, 0x77, 0x62, 0x82, 0x99, 0x31, 0x32, 0x00, 0x78, 0x39, 0x01, 0x06, 0x93,
    0xd1, 0x06, 0x10, 0x02, 0x0c, 0x65, 0xaa, 0xc7, 0x25, 0xe4, 0x98, 0x2e, 0xea,
];

/// Encrypts and authenticates messages with one derived key.
///
/// Message layout: `FormatVersion (1) || Nonce (12) || AES-256-GCM ciphertext || Tag (16)`.
/// The associated data is the format version followed by the context.
pub(crate) struct Cipher {
    key: Secret<[u8; 32]>,
}

impl Cipher {
    /// Cipher for values stored in the database.
    pub(crate) fn for_database(master_key: &Secret<[u8; KEY_LEN]>) -> Self {
        Self::derive(master_key, &DATABASE_SALT)
    }

    /// Cipher for values handed to the browser in the session cookie.
    pub(crate) fn for_sessions(master_key: &Secret<[u8; KEY_LEN]>) -> Self {
        Self::derive(master_key, &SESSION_SALT)
    }

    fn derive(master_key: &Secret<[u8; KEY_LEN]>, salt: &[u8]) -> Self {
        Self {
            key: derive_key(master_key, salt, KEY_INFO),
        }
    }

    pub(crate) fn encrypt(&self, context: &[u8], plaintext: &[u8]) -> Result<Vec<u8>, EncryptError> {
        let mut nonce = [0; NONCE_LEN];
        getrandom::fill(&mut nonce).map_err(EncryptError::Random)?;

        let ciphertext = self
            .aead()
            .encrypt(
                &Nonce::from(nonce),
                Payload {
                    msg: plaintext,
                    aad: &associated_data(FORMAT_VERSION, context),
                },
            )
            .map_err(|_| EncryptError::Encryption)?;

        let mut message = Vec::with_capacity(HEADER_LEN + ciphertext.len());
        message.push(FORMAT_VERSION);
        message.extend_from_slice(&nonce);
        message.extend_from_slice(&ciphertext);

        Ok(message)
    }

    pub(crate) fn decrypt(&self, context: &[u8], message: &[u8]) -> Result<Vec<u8>, DecryptError> {
        if !(HEADER_LEN + TAG_LEN <= message.len()) {
            return Err(DecryptError::Truncated);
        }

        let (header, ciphertext) = message.split_at(HEADER_LEN);
        let version = header[0];

        if version != FORMAT_VERSION {
            return Err(DecryptError::UnsupportedVersion(version));
        }

        let nonce: [u8; NONCE_LEN] = header[1..]
            .try_into()
            .expect("header holds the version byte followed by the nonce");

        self.aead()
            .decrypt(
                &Nonce::from(nonce),
                Payload {
                    msg: ciphertext,
                    aad: &associated_data(version, context),
                },
            )
            .map_err(|_| DecryptError::Authentication)
    }

    fn aead(&self) -> Aes256Gcm {
        // The expanded key schedule is zeroized when the returned value is dropped.
        Aes256Gcm::new(self.key.as_ref().into())
    }
}

/// Authenticates access tokens, so that guessed or forged tokens are rejected without a database lookup.
pub(crate) struct TokenMac {
    key: Secret<[u8; 32]>,
}

impl TokenMac {
    pub(crate) fn for_access_tokens(master_key: &Secret<[u8; KEY_LEN]>) -> Self {
        Self {
            key: derive_key(master_key, &TOKEN_MAC_SALT, TOKEN_MAC_KEY_INFO),
        }
    }

    pub(crate) fn tag(&self, message: &[u8]) -> [u8; TOKEN_TAG_LEN] {
        self.mac(message).finalize().into_bytes().into()
    }

    /// Compares in constant time.
    pub(crate) fn verify(&self, message: &[u8], tag: &[u8]) -> bool {
        self.mac(message).verify_slice(tag).is_ok()
    }

    fn mac(&self, message: &[u8]) -> Hmac<Sha256> {
        let mut mac = Hmac::<Sha256>::new_from_slice(self.key.as_ref()).expect("HMAC accepts keys of any length");
        mac.update(message);
        mac
    }
}

fn derive_key(master_key: &Secret<[u8; KEY_LEN]>, salt: &[u8], info: &[u8]) -> Secret<[u8; 32]> {
    let mut key = Secret::new([0; 32]);

    Hkdf::<Sha256>::new(Some(salt), master_key.as_ref())
        .expand(info, key.as_mut())
        .expect("32 bytes is a valid HKDF-SHA256 output length");

    key
}

#[derive(Debug, thiserror::Error)]
pub(crate) enum EncryptError {
    #[error("failed to generate nonce")]
    Random(#[source] getrandom::Error),
    #[error("message is too long to encrypt")]
    Encryption,
}

#[derive(Debug, thiserror::Error)]
pub(crate) enum DecryptError {
    #[error("message is too short")]
    Truncated,
    #[error("unsupported message format version {0}")]
    UnsupportedVersion(u8),
    #[error("message authentication failed")]
    Authentication,
}

fn associated_data(version: u8, context: &[u8]) -> Vec<u8> {
    let mut aad = Vec::with_capacity(1 + context.len());
    aad.push(version);
    aad.extend_from_slice(context);
    aad
}

#[cfg(test)]
mod tests {
    use super::*;

    fn master_key() -> Secret<[u8; KEY_LEN]> {
        Secret::new([7; KEY_LEN])
    }

    #[test]
    fn round_trip() {
        let cipher = Cipher::for_database(&master_key());

        for plaintext in [&b""[..], b"x", &[0xAB; 16], &[0xCD; 100]] {
            let message = cipher.encrypt(b"ctx", plaintext).unwrap();
            assert_eq!(message.len(), HEADER_LEN + plaintext.len() + TAG_LEN);
            assert_eq!(cipher.decrypt(b"ctx", &message).unwrap(), plaintext);
        }
    }

    #[test]
    fn same_plaintext_encrypts_differently() {
        let cipher = Cipher::for_database(&master_key());

        assert_ne!(
            cipher.encrypt(b"ctx", b"secret").unwrap(),
            cipher.encrypt(b"ctx", b"secret").unwrap()
        );
    }

    #[test]
    fn rejects_tampering() {
        let cipher = Cipher::for_database(&master_key());
        let message = cipher.encrypt(b"ctx", b"secret").unwrap();

        for idx in 1..message.len() {
            let mut tampered = message.clone();
            tampered[idx] ^= 1;
            assert!(matches!(
                cipher.decrypt(b"ctx", &tampered),
                Err(DecryptError::Authentication)
            ));
        }
    }

    #[test]
    fn rejects_other_version() {
        let cipher = Cipher::for_database(&master_key());
        let mut message = cipher.encrypt(b"ctx", b"secret").unwrap();
        message[0] = 2;

        assert!(matches!(
            cipher.decrypt(b"ctx", &message),
            Err(DecryptError::UnsupportedVersion(2))
        ));
    }

    #[test]
    fn rejects_other_context() {
        let cipher = Cipher::for_database(&master_key());
        let message = cipher.encrypt(b"ctx", b"secret").unwrap();

        assert!(matches!(
            cipher.decrypt(b"other", &message),
            Err(DecryptError::Authentication)
        ));
    }

    #[test]
    fn rejects_other_master_key() {
        let message = Cipher::for_database(&master_key()).encrypt(b"ctx", b"secret").unwrap();

        assert!(matches!(
            Cipher::for_database(&Secret::new([8; KEY_LEN])).decrypt(b"ctx", &message),
            Err(DecryptError::Authentication)
        ));
    }

    #[test]
    fn database_and_session_keys_are_independent() {
        let master_key = master_key();
        let message = Cipher::for_database(&master_key).encrypt(b"ctx", b"secret").unwrap();

        assert!(matches!(
            Cipher::for_sessions(&master_key).decrypt(b"ctx", &message),
            Err(DecryptError::Authentication)
        ));
    }

    #[test]
    fn rejects_truncated() {
        let cipher = Cipher::for_database(&master_key());
        let message = cipher.encrypt(b"ctx", b"").unwrap();

        assert!(matches!(
            cipher.decrypt(b"ctx", &message[..message.len() - 1]),
            Err(DecryptError::Truncated)
        ));
    }

    #[test]
    fn token_mac_verifies_its_own_tags_only() {
        let mac = TokenMac::for_access_tokens(&master_key());
        let tag = mac.tag(b"token payload");

        assert!(mac.verify(b"token payload", &tag));
        assert!(!mac.verify(b"token payload!", &tag));
        assert!(!mac.verify(b"token payload", &tag[..31]));
        assert!(!TokenMac::for_access_tokens(&Secret::new([8; KEY_LEN])).verify(b"token payload", &tag));
    }
}
