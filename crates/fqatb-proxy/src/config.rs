use std::env;
use std::net::SocketAddr;

use anyhow::Context as _;
use secret::Secret;

use crate::crypto::KEY_LEN;

const DEFAULT_LISTEN_ADDR: &str = "127.0.0.1:8080";
const DEFAULT_DATABASE_URL: &str = "sqlite://fqatb.db";

/// Settings read from the environment at start-up.
pub(crate) struct Config {
    /// `FQATB_LISTEN_ADDR`.
    pub(crate) listen_addr: SocketAddr,
    /// `FQATB_DATABASE_URL`.
    pub(crate) database_url: String,
    /// `FQATB_ENCRYPTION_KEY`, given as 64 hex characters.
    pub(crate) encryption_key: Secret<[u8; KEY_LEN]>,
    /// `FQATB_ADMIN_PASSWORD`, only used to initialize the admin on first start-up.
    pub(crate) admin_password: Option<Secret<String>>,
}

impl Config {
    pub(crate) fn from_env() -> anyhow::Result<Self> {
        let listen_addr = env::var("FQATB_LISTEN_ADDR")
            .as_deref()
            .unwrap_or(DEFAULT_LISTEN_ADDR)
            .parse()
            .context("invalid FQATB_LISTEN_ADDR")?;

        let database_url = env::var("FQATB_DATABASE_URL").unwrap_or_else(|_| DEFAULT_DATABASE_URL.to_owned());

        let encryption_key = {
            let hex_key = Secret::new(env::var("FQATB_ENCRYPTION_KEY").context("FQATB_ENCRYPTION_KEY is not set")?);
            let mut key = Secret::new([0; KEY_LEN]);
            hex::decode_to_slice(hex_key.as_ref().trim(), key.as_mut())
                .context("FQATB_ENCRYPTION_KEY must be exactly 64 hex characters")?;
            key
        };

        let admin_password = env::var("FQATB_ADMIN_PASSWORD").ok().map(Secret::new);

        Ok(Self {
            listen_addr,
            database_url,
            encryption_key,
            admin_password,
        })
    }
}
