//! HTTP client for the upstream Bitbucket Data Center server.

use std::time::Duration;

use axum::http::{HeaderMap, HeaderName, Method, header};
use percent_encoding::{AsciiSet, NON_ALPHANUMERIC, utf8_percent_encode};
use reqwest::{Body, Certificate, Response, Url};
use secret::Secret;

/// Characters escaped in a path segment: everything except RFC 3986 unreserved characters.
const PATH_SEGMENT: &AsciiSet = &NON_ALPHANUMERIC.remove(b'-').remove(b'.').remove(b'_').remove(b'~');

/// Headers that describe one connection rather than the message, per RFC 9110, section 7.6.1.
const HOP_BY_HOP: [HeaderName; 8] = [
    header::CONNECTION,
    HeaderName::from_static("keep-alive"),
    header::PROXY_AUTHENTICATE,
    header::PROXY_AUTHORIZATION,
    header::TE,
    header::TRAILER,
    header::TRANSFER_ENCODING,
    header::UPGRADE,
];

pub(crate) struct BitbucketClient {
    http: reqwest::Client,
    /// Base URL without a trailing slash.
    base: String,
}

#[derive(Debug, thiserror::Error)]
pub(crate) enum ClientError {
    #[error("request to Bitbucket failed")]
    Request(#[from] reqwest::Error),

    #[error("Bitbucket answered with status {0}")]
    Status(reqwest::StatusCode),
}

impl BitbucketClient {
    /// With `ca_certs`, Bitbucket's certificate must chain to one of them, and the system's trusted CAs are ignored.
    pub(crate) fn new(base: &Url, ca_certs: Option<Vec<Certificate>>) -> Result<Self, reqwest::Error> {
        let mut builder = reqwest::Client::builder()
            // Redirects are the client's business; following them here would hide them and could leave Bitbucket.
            .redirect(reqwest::redirect::Policy::none())
            .connect_timeout(Duration::from_secs(10));

        if let Some(ca_certs) = ca_certs {
            builder = builder.tls_certs_only(ca_certs);
        }

        let http = builder.build()?;

        Ok(Self {
            http,
            base: base.as_str().trim_end_matches('/').to_owned(),
        })
    }

    /// Fetches a pull request as JSON.
    pub(crate) async fn pull_request(
        &self,
        token: &Secret<String>,
        project: &str,
        repository: &str,
        id: u64,
    ) -> Result<Vec<u8>, ClientError> {
        let url = format!(
            "{}/rest/api/latest/projects/{}/repos/{}/pull-requests/{id}",
            self.base,
            utf8_percent_encode(project, PATH_SEGMENT),
            utf8_percent_encode(repository, PATH_SEGMENT),
        );

        let response = self
            .http
            .get(url)
            .bearer_auth(token.as_ref())
            .header(header::ACCEPT, "application/json")
            .send()
            .await?;

        if !response.status().is_success() {
            return Err(ClientError::Status(response.status()));
        }

        Ok(response.bytes().await?.to_vec())
    }

    /// Sends a client's request to Bitbucket with the Bitbucket token in place of the client's credentials.
    ///
    /// `path_and_query` is forwarded exactly as received, still percent-encoded.
    pub(crate) async fn forward(
        &self,
        method: Method,
        path_and_query: &str,
        mut headers: HeaderMap,
        body: Body,
        token: &Secret<String>,
    ) -> Result<Response, reqwest::Error> {
        strip_request_headers(&mut headers);

        self.http
            .request(method, format!("{}{path_and_query}", self.base))
            .headers(headers)
            .bearer_auth(token.as_ref())
            .body(body)
            .send()
            .await
    }
}

/// Removes what must not reach Bitbucket: the client's credentials and cookies, and connection-specific headers.
fn strip_request_headers(headers: &mut HeaderMap) {
    strip_hop_by_hop(headers);

    for name in [
        header::AUTHORIZATION,
        header::COOKIE,
        header::HOST,
        header::CONTENT_LENGTH,
    ] {
        headers.remove(name);
    }
}

/// Removes what must not reach the client: Bitbucket's session cookies, which could later authenticate requests under a
/// different Bitbucket token, and connection-specific headers.
pub(crate) fn strip_response_headers(headers: &mut HeaderMap) {
    strip_hop_by_hop(headers);
    headers.remove(header::SET_COOKIE);
}

fn strip_hop_by_hop(headers: &mut HeaderMap) {
    // `Connection` may name further headers that only apply to this hop.
    let listed: Vec<HeaderName> = headers
        .get_all(header::CONNECTION)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .flat_map(|value| value.split(','))
        .filter_map(|name| HeaderName::try_from(name.trim()).ok())
        .collect();

    for name in HOP_BY_HOP.iter().chain(&listed) {
        headers.remove(name);
    }
}

#[cfg(test)]
mod tests {
    use axum::http::HeaderValue;

    use super::*;

    #[test]
    fn request_headers_lose_credentials_and_hop_by_hop_headers() {
        let mut headers = HeaderMap::new();
        for (name, value) in [
            ("authorization", "Bearer fgatb_x"),
            ("cookie", "fqatb_session=abc; other=1"),
            ("host", "proxy.example.com"),
            ("content-length", "12"),
            ("connection", "keep-alive, x-trace"),
            ("x-trace", "1"),
            ("transfer-encoding", "chunked"),
            ("accept", "application/json"),
            ("content-type", "application/json"),
            ("x-atlassian-token", "no-check"),
        ] {
            headers.append(HeaderName::from_static(name), HeaderValue::from_static(value));
        }

        strip_request_headers(&mut headers);

        let mut remaining: Vec<_> = headers.keys().map(HeaderName::as_str).collect();
        remaining.sort_unstable();
        assert_eq!(remaining, ["accept", "content-type", "x-atlassian-token"]);
    }

    /// Starts an HTTPS server for `localhost` whose certificate is signed by the test CA, and returns its base URL.
    async fn https_bitbucket() -> Url {
        use axum_server::Handle;
        use axum_server::tls_rustls::RustlsConfig;

        let config = RustlsConfig::from_pem(
            include_bytes!("../../tests/fixtures/tls/server.crt").to_vec(),
            include_bytes!("../../tests/fixtures/tls/server.key").to_vec(),
        )
        .await
        .unwrap();
        let app = axum::Router::new().fallback(|| async { axum::Json(serde_json::json!({ "id": 1 })) });

        let handle = Handle::<std::net::SocketAddr>::new();
        let server = axum_server::bind_rustls("127.0.0.1:0".parse().unwrap(), config).handle(handle.clone());
        tokio::spawn(server.serve(app.into_make_service()));
        let address = handle.listening().await.unwrap();

        format!("https://localhost:{}", address.port()).parse().unwrap()
    }

    #[tokio::test]
    async fn trusts_the_configured_ca() {
        let base = https_bitbucket().await;
        let ca_certs = Certificate::from_pem_bundle(include_bytes!("../../tests/fixtures/tls/ca.crt")).unwrap();
        let token = Secret::new("ATBB-x".to_owned());

        let client = BitbucketClient::new(&base, Some(ca_certs)).unwrap();
        assert_eq!(
            client.pull_request(&token, "PROJ", "api", 1).await.unwrap(),
            br#"{"id":1}"#
        );

        // Without it, the test CA is unknown.
        let client = BitbucketClient::new(&base, None).unwrap();
        assert!(matches!(
            client.pull_request(&token, "PROJ", "api", 1).await,
            Err(ClientError::Request(_))
        ));
    }

    #[tokio::test]
    async fn the_configured_ca_replaces_the_system_cas() {
        // The server certificate is not a CA, so nothing it is given to verify chains to it.
        let base = https_bitbucket().await;
        let unrelated = Certificate::from_pem_bundle(include_bytes!("../../tests/fixtures/tls/server.crt")).unwrap();

        let client = BitbucketClient::new(&base, Some(unrelated)).unwrap();
        assert!(
            client
                .pull_request(&Secret::new("ATBB-x".to_owned()), "PROJ", "api", 1)
                .await
                .is_err()
        );
    }

    #[test]
    fn response_headers_lose_cookies() {
        let mut headers = HeaderMap::new();
        headers.append(header::SET_COOKIE, HeaderValue::from_static("BITBUCKETSESSIONID=abc"));
        headers.append(header::CONTENT_TYPE, HeaderValue::from_static("application/json"));
        headers.append(header::CONNECTION, HeaderValue::from_static("close"));

        strip_response_headers(&mut headers);

        assert_eq!(headers.len(), 1);
        assert!(headers.contains_key(header::CONTENT_TYPE));
    }
}
