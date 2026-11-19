use std::env;
use std::net::SocketAddr;
use std::path::PathBuf;

use anyhow::Context as _;
use reqwest::Url;
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
    /// `FQATB_BITBUCKET_URL`, the base URL of the Bitbucket Data Center server, such as `https://bitbucket.example.com`.
    pub(crate) bitbucket_url: Url,
    /// `FQATB_TLS_CERT` and `FQATB_TLS_KEY`; without them the proxy serves plain HTTP.
    pub(crate) tls: Option<TlsConfig>,
}

/// PEM files the proxy serves HTTPS with.
pub(crate) struct TlsConfig {
    /// Certificate chain, leaf certificate first.
    pub(crate) cert_path: PathBuf,
    /// Private key in PKCS#8, PKCS#1 or SEC1 form.
    pub(crate) key_path: PathBuf,
}

impl TlsConfig {
    /// Both paths turn TLS on and neither leaves it off; only one of them is a mistake.
    fn from_paths(cert_path: Option<String>, key_path: Option<String>) -> anyhow::Result<Option<Self>> {
        match (non_empty(cert_path), non_empty(key_path)) {
            (Some(cert_path), Some(key_path)) => Ok(Some(Self {
                cert_path: cert_path.into(),
                key_path: key_path.into(),
            })),
            (None, None) => Ok(None),
            (Some(_), None) => anyhow::bail!("FQATB_TLS_CERT is set but FQATB_TLS_KEY is not"),
            (None, Some(_)) => anyhow::bail!("FQATB_TLS_KEY is set but FQATB_TLS_CERT is not"),
        }
    }
}

fn non_empty(value: Option<String>) -> Option<String> {
    value.filter(|value| !value.trim().is_empty())
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

        let bitbucket_url = {
            let text = env::var("FQATB_BITBUCKET_URL").context("FQATB_BITBUCKET_URL is not set")?;
            let url = Url::parse(text.trim()).context("invalid FQATB_BITBUCKET_URL")?;
            anyhow::ensure!(
                matches!(url.scheme(), "http" | "https") && url.query().is_none() && url.fragment().is_none(),
                "FQATB_BITBUCKET_URL must be an http or https URL without a query or fragment"
            );
            url
        };

        let tls = TlsConfig::from_paths(env::var("FQATB_TLS_CERT").ok(), env::var("FQATB_TLS_KEY").ok())?;

        Ok(Self {
            listen_addr,
            database_url,
            encryption_key,
            bitbucket_url,
            tls,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn paths(cert: Option<&str>, key: Option<&str>) -> anyhow::Result<Option<TlsConfig>> {
        TlsConfig::from_paths(cert.map(str::to_owned), key.map(str::to_owned))
    }

    #[test]
    fn tls_is_on_with_both_paths() {
        let tls = paths(Some("cert.pem"), Some("key.pem")).unwrap().unwrap();
        assert_eq!(tls.cert_path, PathBuf::from("cert.pem"));
        assert_eq!(tls.key_path, PathBuf::from("key.pem"));
    }

    #[test]
    fn tls_is_off_without_paths() {
        assert!(paths(None, None).unwrap().is_none());
        assert!(paths(Some(""), Some(" ")).unwrap().is_none());
    }

    #[test]
    fn tls_needs_both_paths() {
        assert!(paths(Some("cert.pem"), None).is_err());
        assert!(paths(None, Some("key.pem")).is_err());
        assert!(paths(Some("cert.pem"), Some("")).is_err());
    }
}
