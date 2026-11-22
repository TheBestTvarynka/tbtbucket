//! The Bitbucket-compatible API: every request outside the admin panel.
//!
//! Clients authenticate with an access token exactly as they would with a Bitbucket HTTP access token.
//! Each request is classified, checked against the token's policy, and forwarded to Bitbucket with a Bitbucket token.

use axum::body::{Body, to_bytes};
use axum::extract::{Request, State};
use axum::http::{HeaderMap, HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use secret::Secret;
use tracing::{debug, error, warn};

use super::json_error;
use crate::bitbucket::classify::{BranchSource, Unsupported, classify};
use crate::bitbucket::client::strip_response_headers;
use crate::error::report;
use crate::services::Decision;
use crate::state::AppState;

/// Largest request body the proxy reads to find branch names.
const MAX_INSPECTED_BODY_LEN: usize = 1024 * 1024;

/// Path prefixes owned by the proxy itself, which are never forwarded.
const OWN_PREFIXES: [&str; 2] = ["/webapp", "/fgatbapi"];

pub(super) async fn proxy(State(state): State<AppState>, request: Request) -> Response {
    let path = request.uri().path();

    if OWN_PREFIXES
        .iter()
        .any(|prefix| path == *prefix || path.starts_with(&format!("{prefix}/")))
    {
        return StatusCode::NOT_FOUND.into_response();
    }

    let Some(presented) = credentials(request.headers()) else {
        return unauthorized("authentication with an access token is required");
    };

    let token = match state.access_token_service.authenticate(presented.as_ref()).await {
        Ok(Some(token)) => token,
        Ok(None) => return unauthorized("access token is invalid or expired"),
        Err(error) => return internal_error(&error),
    };

    let classified = match classify(request.method(), path) {
        Ok(classified) => classified,
        Err(Unsupported::Git) => return super::git::git(&state, &token, request).await,
        Err(unsupported) => {
            warn!(access_token_id = %token.id, method = %request.method(), path, reason = %unsupported, "Denied unsupported request");
            return json_error(StatusCode::FORBIDDEN, &unsupported.to_string());
        }
    };

    let (parts, body) = request.into_parts();
    let path_and_query = parts
        .uri
        .path_and_query()
        .map_or(parts.uri.path(), |value| value.as_str())
        .to_owned();

    let needs_body = matches!(
        classified.branches,
        BranchSource::BodyBranchName | BranchSource::BodyPullRequestRefs | BranchSource::PullRequestUpdate(_)
    );
    let (inspected, forwarded) = if needs_body {
        let Ok(bytes) = to_bytes(body, MAX_INSPECTED_BODY_LEN).await else {
            return json_error(StatusCode::PAYLOAD_TOO_LARGE, "request body is too large");
        };
        (Some(bytes.clone()), reqwest::Body::from(bytes))
    } else {
        (None, reqwest::Body::wrap_stream(body.into_data_stream()))
    };

    let allowed = match state
        .proxy_service
        .authorize(&token, &classified, inspected.as_deref())
        .await
    {
        Ok(Decision::Allow(allowed)) => allowed,
        Ok(Decision::Deny(reason)) => {
            warn!(
                access_token_id = %token.id,
                action = %classified.action,
                project = classified.project,
                repository = classified.repository,
                %reason,
                "Denied request"
            );
            return json_error(StatusCode::FORBIDDEN, &reason);
        }
        Err(error) => return internal_error(&error),
    };

    debug!(
        access_token_id = %token.id,
        action = %classified.action,
        project = classified.project,
        repository = classified.repository,
        rule = allowed.rule + 1,
        bitbucket_token_id = %allowed.bitbucket_token_id,
        "Allowed request"
    );

    let upstream = match state
        .proxy_service
        .forward(
            parts.method,
            &path_and_query,
            parts.headers,
            forwarded,
            &allowed.bitbucket_token,
        )
        .await
    {
        Ok(upstream) => upstream,
        Err(error) => {
            error!(error = report(&error), "Forwarding to Bitbucket failed");
            return json_error(StatusCode::BAD_GATEWAY, "Bitbucket is unreachable");
        }
    };

    upstream_response(upstream)
}

/// Passes Bitbucket's response on to the client, streaming its body, without its cookies and hop-by-hop headers.
pub(super) fn upstream_response(upstream: reqwest::Response) -> Response {
    let mut response = Response::builder().status(upstream.status());
    let mut headers = upstream.headers().clone();
    strip_response_headers(&mut headers);
    if let Some(response_headers) = response.headers_mut() {
        *response_headers = headers;
    }

    response
        .body(Body::from_stream(upstream.bytes_stream()))
        .unwrap_or_else(|_| StatusCode::BAD_GATEWAY.into_response())
}

/// Reads the access token the way Bitbucket reads HTTP access tokens: as a bearer token, or as the password of Basic
/// authentication with any username.
fn credentials(headers: &HeaderMap) -> Option<Secret<String>> {
    let value = headers.get(header::AUTHORIZATION)?.to_str().ok()?;
    let (scheme, credentials) = value.split_once(' ')?;
    let credentials = credentials.trim();

    if scheme.eq_ignore_ascii_case("bearer") {
        return Some(Secret::new(credentials.to_owned()));
    }

    if scheme.eq_ignore_ascii_case("basic") {
        let decoded = Secret::new(STANDARD.decode(credentials).ok()?);
        let decoded = std::str::from_utf8(decoded.as_ref()).ok()?;
        let (_, password) = decoded.split_once(':')?;
        return Some(Secret::new(password.to_owned()));
    }

    None
}

fn unauthorized(message: &str) -> Response {
    let mut response = json_error(StatusCode::UNAUTHORIZED, message);
    response.headers_mut().insert(
        header::WWW_AUTHENTICATE,
        HeaderValue::from_static("Basic realm=\"Bitbucket\""),
    );
    response
}

pub(super) fn internal_error(error: &crate::Error) -> Response {
    error!(error = report(error), "Request failed");
    json_error(StatusCode::INTERNAL_SERVER_ERROR, "internal server error")
}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, Mutex};

    use axum::Router;
    use axum::body::{Body, Bytes, to_bytes};
    use axum::extract::Request;
    use axum::http::{HeaderMap, StatusCode, header};
    use axum::response::{IntoResponse as _, Response};
    use secret::Secret;
    use serde_json::json;
    use time::{Duration, OffsetDateTime};
    use tokio::net::TcpListener;
    use tower::ServiceExt as _;
    use uuid::Uuid;

    use crate::routes::router;
    use crate::state::{AppState, ServerState};

    const REPO: &str = "/rest/api/latest/projects/PROJ/repos/api";

    /// A request received by the fake Bitbucket server.
    #[derive(Debug, Clone)]
    struct Received {
        method: String,
        path_and_query: String,
        headers: HeaderMap,
        body: Bytes,
    }

    struct Fixture {
        app: Router,
        state: AppState,
        received: Arc<Mutex<Vec<Received>>>,
        read_token: Uuid,
        write_token: Uuid,
    }

    /// Starts a fake Bitbucket server that records requests, knows a few pull requests, and sets a session cookie.
    async fn fixture() -> Fixture {
        let received = Arc::new(Mutex::new(Vec::new()));

        let recorder = Arc::clone(&received);
        let upstream = Router::new().fallback(move |request: Request| {
            let recorder = Arc::clone(&recorder);
            async move {
                let (parts, body) = request.into_parts();
                let body = to_bytes(body, usize::MAX).await.unwrap();
                let path_and_query = parts.uri.path_and_query().unwrap().as_str().to_owned();
                recorder.lock().unwrap().push(Received {
                    method: parts.method.to_string(),
                    path_and_query: path_and_query.clone(),
                    headers: parts.headers,
                    body,
                });

                let pull_request = |from: &str, from_project: &str, to: &str| {
                    let reference = |id: &str, project: &str| {
                        json!({ "id": format!("refs/heads/{id}"), "repository": { "slug": "api", "project": { "key": project } } })
                    };
                    json!({ "id": 1, "fromRef": reference(from, from_project), "toRef": reference(to, "PROJ") })
                };
                let pull_requests = format!("{REPO}/pull-requests/");
                if parts.method == "GET" && path_and_query.starts_with(&pull_requests) {
                    let fixture = match &path_and_query[pull_requests.len()..] {
                        "1" => Some(pull_request("feature/login", "PROJ", "main")),
                        "2" => Some(pull_request("feature/x", "~ALICE", "main")),
                        "3" => Some(pull_request("hotfix/x", "PROJ", "release/1")),
                        _ => None,
                    };
                    if let Some(fixture) = fixture {
                        return axum::Json(fixture).into_response();
                    }
                    return StatusCode::NOT_FOUND.into_response();
                }

                Response::builder()
                    .status(StatusCode::CREATED)
                    .header(header::SET_COOKIE, "BITBUCKETSESSIONID=upstream-session")
                    .header("x-upstream", "yes")
                    .body(Body::from(r#"{"from":"bitbucket"}"#))
                    .unwrap()
            }
        });
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        tokio::spawn(async move { axum::serve(listener, upstream).await.unwrap() });

        let state = Arc::new(ServerState::for_tests_with_bitbucket(&format!("http://{address}")).await);
        let read_token = state
            .bitbucket_token_service
            .add("read", Secret::new("ATBB-read".to_owned()))
            .await
            .unwrap();
        let write_token = state
            .bitbucket_token_service
            .add("write", Secret::new("ATBB-write".to_owned()))
            .await
            .unwrap();

        Fixture {
            app: router(Arc::clone(&state)),
            state,
            received,
            read_token,
            write_token,
        }
    }

    impl Fixture {
        async fn issue(&self, rules: serde_json::Value) -> String {
            let policy = serde_json::from_value(json!({ "version": 1, "rules": rules })).unwrap();
            let issued = self
                .state
                .access_token_service
                .issue(
                    &Uuid::new_v4().to_string(),
                    policy,
                    OffsetDateTime::now_utc() + Duration::days(1),
                )
                .await
                .unwrap();
            issued.token.as_ref().clone()
        }

        async fn send(&self, request: Request<Body>) -> (StatusCode, HeaderMap, String) {
            let response = self.app.clone().oneshot(request).await.unwrap();
            let (parts, body) = response.into_parts();
            let body = to_bytes(body, usize::MAX).await.unwrap();
            (parts.status, parts.headers, String::from_utf8(body.to_vec()).unwrap())
        }

        fn received(&self) -> Vec<Received> {
            self.received.lock().unwrap().clone()
        }

        /// Requests forwarded on behalf of clients, leaving out the proxy's own pull request lookups.
        fn forwarded(&self) -> Vec<Received> {
            self.received()
                .into_iter()
                .filter(|request| request.headers.contains_key("x-client"))
                .collect()
        }
    }

    fn request(method: &str, path: &str, token: &str, body: Option<serde_json::Value>) -> Request<Body> {
        Request::builder()
            .method(method)
            .uri(path)
            .header(header::AUTHORIZATION, format!("Bearer {token}"))
            .header(header::CONTENT_TYPE, "application/json")
            .header("x-client", "1")
            .body(body.map_or_else(Body::empty, |body| Body::from(body.to_string())))
            .unwrap()
    }

    fn error_message(body: &str) -> String {
        let body: serde_json::Value = serde_json::from_str(body).unwrap();
        body["errors"][0]["message"].as_str().unwrap().to_owned()
    }

    fn pr_body(from: &str, to: &str) -> serde_json::Value {
        let reference = |id: &str| json!({ "id": format!("refs/heads/{id}"), "repository": { "slug": "api", "project": { "key": "PROJ" } } });
        json!({ "title": "Change", "fromRef": reference(from), "toRef": reference(to) })
    }

    #[tokio::test]
    async fn forwards_allowed_requests_with_the_bitbucket_token() {
        let fixture = fixture().await;
        let token = fixture
            .issue(json!([{ "bitbucket_token": fixture.read_token, "actions": ["repo:read"], "project": "PROJ", "repository": "api" }]))
            .await;

        let mut request = request("GET", &format!("{REPO}/pull-requests?state=OPEN&limit=5"), &token, None);
        request
            .headers_mut()
            .insert(header::COOKIE, "tbtbucket_session=admin-session; other=1".parse().unwrap());
        let (status, headers, body) = fixture.send(request).await;

        assert_eq!(status, StatusCode::CREATED);
        assert_eq!(body, r#"{"from":"bitbucket"}"#);
        assert_eq!(headers.get("x-upstream").unwrap(), "yes");
        assert!(headers.get(header::SET_COOKIE).is_none());

        let forwarded = fixture.forwarded();
        assert_eq!(forwarded.len(), 1);
        assert_eq!(forwarded[0].method, "GET");
        assert_eq!(
            forwarded[0].path_and_query,
            format!("{REPO}/pull-requests?state=OPEN&limit=5")
        );
        assert_eq!(
            forwarded[0].headers.get(header::AUTHORIZATION).unwrap(),
            "Bearer ATBB-read"
        );
        assert!(forwarded[0].headers.get(header::COOKIE).is_none());
        assert!(!format!("{:?}", forwarded[0].headers).contains("fgatb_"));
    }

    #[tokio::test]
    async fn accepts_basic_authentication_with_any_username() {
        let fixture = fixture().await;
        let token = fixture
            .issue(json!([{ "bitbucket_token": fixture.read_token, "actions": ["repo:read"], "project": "PROJ", "repository": "api" }]))
            .await;

        let basic = base64::Engine::encode(&base64::engine::general_purpose::STANDARD, format!("ci-bot:{token}"));
        let request = Request::get(format!("{REPO}/browse/README.md"))
            .header(header::AUTHORIZATION, format!("Basic {basic}"))
            .header("x-client", "1")
            .body(Body::empty())
            .unwrap();

        let (status, _, _) = fixture.send(request).await;

        assert_eq!(status, StatusCode::CREATED);
        assert_eq!(
            fixture.forwarded()[0].headers.get(header::AUTHORIZATION).unwrap(),
            "Bearer ATBB-read"
        );
    }

    #[tokio::test]
    async fn rejects_missing_and_invalid_tokens() {
        let fixture = fixture().await;
        let token = fixture
            .issue(json!([{ "bitbucket_token": fixture.read_token, "actions": ["repo:read"], "project": "PROJ", "repository": "api" }]))
            .await;

        let missing = Request::get(REPO).body(Body::empty()).unwrap();
        let tampered = request("GET", REPO, &format!("{}x", &token[..token.len() - 1]), None);
        let bitbucket_token = request("GET", REPO, "ATBB-read", None);
        let management_token = fixture
            .state
            .management_token_service
            .issue("ci", OffsetDateTime::now_utc() + Duration::days(1))
            .await
            .unwrap()
            .token;
        let management_token = request("GET", REPO, management_token.as_ref(), None);

        for request in [missing, tampered, bitbucket_token, management_token] {
            let (status, headers, body) = fixture.send(request).await;
            assert_eq!(status, StatusCode::UNAUTHORIZED);
            assert_eq!(
                headers.get(header::WWW_AUTHENTICATE).unwrap(),
                "Basic realm=\"Bitbucket\""
            );
            assert!(error_message(&body).contains("access token"));
        }

        assert!(fixture.received().is_empty());
    }

    #[tokio::test]
    async fn denies_unsupported_and_unallowed_requests_without_forwarding() {
        let fixture = fixture().await;
        let token = fixture
            .issue(json!([{ "bitbucket_token": fixture.read_token, "actions": ["repo:read"], "project": "PROJ", "repository": "api" }]))
            .await;

        let cases = [
            ("PUT", REPO.to_owned(), "endpoint is not supported"),
            (
                "GET",
                "/rest/api/latest/dashboard/pull-requests".to_owned(),
                "endpoint is not supported",
            ),
            ("GET", format!("{REPO}/../web"), "path is malformed"),
            (
                "POST",
                format!("{REPO}/pull-requests/1/merge"),
                "access token does not allow pr:merge on PROJ/api",
            ),
            (
                "GET",
                "/rest/api/latest/projects/PROJ/repos/web".to_owned(),
                "access token does not allow repo:read on PROJ/web",
            ),
        ];

        for (method, path, message) in cases {
            let (status, _, body) = fixture.send(request(method, &path, &token, None)).await;
            assert_eq!(status, StatusCode::FORBIDDEN, "{method} {path}");
            assert!(error_message(&body).starts_with(message), "{method} {path}: {body}");
        }

        assert!(fixture.received().is_empty());
    }

    #[tokio::test]
    async fn pull_request_creation_checks_body_branches() {
        let fixture = fixture().await;
        let token = fixture
            .issue(json!([{ "bitbucket_token": fixture.write_token, "actions": ["pr:create"], "project": "PROJ", "repository": "api",
                            "branches": { "source": ["feature/**"], "target": ["main"] } }]))
            .await;

        let allowed = pr_body("feature/login", "main");
        let (status, _, _) = fixture
            .send(request(
                "POST",
                &format!("{REPO}/pull-requests"),
                &token,
                Some(allowed.clone()),
            ))
            .await;
        assert_eq!(status, StatusCode::CREATED);
        let forwarded = fixture.forwarded();
        assert_eq!(
            serde_json::from_slice::<serde_json::Value>(&forwarded[0].body).unwrap(),
            allowed
        );
        assert_eq!(
            forwarded[0].headers.get(header::AUTHORIZATION).unwrap(),
            "Bearer ATBB-write"
        );

        for (body, message) in [
            (
                pr_body("bugfix/x", "main"),
                "access token does not allow pr:create on PROJ/api from bugfix/x to main",
            ),
            (
                pr_body("feature/x", "release/1"),
                "access token does not allow pr:create on PROJ/api from feature/x to release/1",
            ),
            (
                json!({ "title": "No refs" }),
                "request body is invalid: body has no `fromRef`",
            ),
        ] {
            let (status, _, response) = fixture
                .send(request("POST", &format!("{REPO}/pull-requests"), &token, Some(body)))
                .await;
            assert_eq!(status, StatusCode::FORBIDDEN);
            assert_eq!(error_message(&response), message);
        }

        let mut fork = pr_body("feature/x", "main");
        fork["fromRef"]["repository"]["project"]["key"] = json!("~ALICE");
        let (status, _, response) = fixture
            .send(request("POST", &format!("{REPO}/pull-requests"), &token, Some(fork)))
            .await;
        assert_eq!(status, StatusCode::FORBIDDEN);
        assert!(error_message(&response).contains("another repository"));

        assert_eq!(fixture.forwarded().len(), 1);
    }

    #[tokio::test]
    async fn existing_pull_requests_are_checked_by_their_branches() {
        let fixture = fixture().await;
        let token = fixture
            .issue(json!([{ "bitbucket_token": fixture.write_token, "actions": ["pr:merge", "pr_comment:create"], "project": "PROJ", "repository": "api",
                            "branches": { "target": ["main"] } }]))
            .await;

        // Pull request 1 targets `main`.
        let (status, _, _) = fixture
            .send(request(
                "POST",
                &format!("{REPO}/pull-requests/1/merge?version=3"),
                &token,
                None,
            ))
            .await;
        assert_eq!(status, StatusCode::CREATED);

        // Pull request 3 targets `release/1`.
        let (status, _, body) = fixture
            .send(request(
                "POST",
                &format!("{REPO}/pull-requests/3/comments"),
                &token,
                Some(json!({ "text": "LGTM" })),
            ))
            .await;
        assert_eq!(status, StatusCode::FORBIDDEN);
        assert_eq!(
            error_message(&body),
            "access token does not allow pr_comment:create on PROJ/api from hotfix/x to release/1"
        );

        // Pull request 2 comes from a fork, and pull request 9 does not exist.
        for id in [2, 9] {
            let (status, _, _) = fixture
                .send(request(
                    "POST",
                    &format!("{REPO}/pull-requests/{id}/merge"),
                    &token,
                    None,
                ))
                .await;
            assert_eq!(status, StatusCode::FORBIDDEN);
        }

        let received = fixture.received();
        let lookups: Vec<_> = received.iter().filter(|request| request.method == "GET").collect();
        assert_eq!(lookups.len(), 4);
        assert!(
            lookups
                .iter()
                .all(|lookup| lookup.headers.get(header::AUTHORIZATION).unwrap() == "Bearer ATBB-write")
        );
        let merges: Vec<_> = received.iter().filter(|request| request.method == "POST").collect();
        assert_eq!(merges.len(), 1);
        assert_eq!(
            merges[0].path_and_query,
            format!("{REPO}/pull-requests/1/merge?version=3")
        );
    }

    #[tokio::test]
    async fn retargeting_needs_permission_for_both_targets() {
        let fixture = fixture().await;
        let token = fixture
            .issue(json!([{ "bitbucket_token": fixture.write_token, "actions": ["pr:update"], "project": "PROJ", "repository": "api",
                            "branches": { "target": ["main", "develop"] } }]))
            .await;
        let update = |target: &str| json!({ "version": 1, "title": "New title", "toRef": { "id": format!("refs/heads/{target}") } });

        let (status, _, _) = fixture
            .send(request(
                "PUT",
                &format!("{REPO}/pull-requests/1"),
                &token,
                Some(json!({ "version": 1, "title": "Renamed" })),
            ))
            .await;
        assert_eq!(status, StatusCode::CREATED);

        let (status, _, _) = fixture
            .send(request(
                "PUT",
                &format!("{REPO}/pull-requests/1"),
                &token,
                Some(update("develop")),
            ))
            .await;
        assert_eq!(status, StatusCode::CREATED);

        let (status, _, body) = fixture
            .send(request(
                "PUT",
                &format!("{REPO}/pull-requests/1"),
                &token,
                Some(update("release/2")),
            ))
            .await;
        assert_eq!(status, StatusCode::FORBIDDEN);
        assert!(error_message(&body).ends_with("from feature/login to release/2"));

        // Pull request 3 targets `release/1`, so moving it to `main` is not allowed either.
        let (status, _, _) = fixture
            .send(request(
                "PUT",
                &format!("{REPO}/pull-requests/3"),
                &token,
                Some(update("main")),
            ))
            .await;
        assert_eq!(status, StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn pull_request_lifecycle_and_comments() {
        let fixture = fixture().await;
        let token = fixture
            .issue(json!([
                { "bitbucket_token": fixture.read_token, "actions": ["repo:read"], "project": "PROJ", "repository": "api" },
                { "bitbucket_token": fixture.write_token, "actions": ["pr:update", "pr:decline", "pr:delete", "pr_comment:*"],
                  "project": "PROJ", "repository": "api", "branches": { "target": ["main"] } }
            ]))
            .await;
        let pr = format!("{REPO}/pull-requests/1");
        let reaction =
            "/rest/comment-likes/latest/projects/PROJ/repos/api/pull-requests/1/comments/7/reactions/thumbsup";

        // Reads go out with the read token, whatever plugin serves them.
        for path in [
            format!("{REPO}/pull-requests/1.diff"),
            format!("{pr}/activities?start=0&limit=25"),
            format!("{pr}/comments/7"),
            format!("{REPO}/commits?until=main"),
            "/rest/jira/latest/projects/PROJ/repos/api/pull-requests/1/issues".to_owned(),
            "/rest/insights/latest/projects/PROJ/repos/api/commits/abc123/reports".to_owned(),
        ] {
            fixture.send(request("GET", &path, &token, None)).await;
        }

        // Writes on pull request 1, which targets `main`, go out with the write token.
        let writes = [
            (
                "POST",
                format!("{pr}/participants"),
                Some(json!({ "user": { "name": "bob" }, "role": "REVIEWER" })),
            ),
            ("DELETE", format!("{pr}/participants?username=bob"), None),
            ("POST", format!("{pr}/comments"), Some(json!({ "text": "Looks good" }))),
            (
                "PUT",
                format!("{pr}/comments/7"),
                Some(json!({ "version": 0, "text": "Looks great" })),
            ),
            ("PUT", reaction.to_owned(), None),
            ("DELETE", reaction.to_owned(), None),
            ("DELETE", format!("{pr}/comments/7?version=1"), None),
            ("POST", format!("{pr}/decline?version=2"), None),
            ("DELETE", pr.clone(), Some(json!({ "version": 3 }))),
        ];
        for (method, path, body) in &writes {
            let (status, _, response) = fixture.send(request(method, path, &token, body.clone())).await;
            assert_eq!(status, StatusCode::CREATED, "{method} {path}: {response}");
        }

        let forwarded = fixture.forwarded();
        assert_eq!(forwarded.len(), 6 + writes.len());
        for (sent, (method, path, body)) in forwarded[6..].iter().zip(&writes) {
            assert_eq!(
                (sent.method.as_str(), sent.path_and_query.as_str()),
                (*method, path.as_str())
            );
            assert_eq!(sent.headers.get(header::AUTHORIZATION).unwrap(), "Bearer ATBB-write");
            if let Some(body) = body {
                assert_eq!(&serde_json::from_slice::<serde_json::Value>(&sent.body).unwrap(), body);
            }
        }
        assert!(
            forwarded[..6]
                .iter()
                .all(|sent| sent.headers.get(header::AUTHORIZATION).unwrap() == "Bearer ATBB-read")
        );

        // Pull request 3 targets `release/1`, and suggestions commit to the source branch.
        for (method, path, message) in [
            (
                "POST",
                format!("{REPO}/pull-requests/3/participants"),
                "access token does not allow pr:update",
            ),
            (
                "PUT",
                "/rest/comment-likes/latest/projects/PROJ/repos/api/pull-requests/3/comments/7/reactions/thumbsup"
                    .to_owned(),
                "access token does not allow pr_comment:create",
            ),
            (
                "PUT",
                format!("{pr}/comments/7/reactions/heart"),
                "endpoint is not supported",
            ),
            (
                "POST",
                format!("{REPO}/pull-requests/3/decline"),
                "access token does not allow pr:decline",
            ),
            (
                "POST",
                format!("{pr}/comments/7/apply-suggestion"),
                "endpoint is not supported",
            ),
            ("POST", format!("{pr}/merge"), "access token does not allow pr:merge"),
        ] {
            let (status, _, body) = fixture.send(request(method, &path, &token, None)).await;
            assert_eq!(status, StatusCode::FORBIDDEN, "{method} {path}");
            assert!(error_message(&body).starts_with(message), "{method} {path}: {body}");
        }
        assert_eq!(fixture.forwarded().len(), 6 + writes.len());
    }

    #[tokio::test]
    async fn rules_choose_their_bitbucket_token() {
        let fixture = fixture().await;
        let token = fixture
            .issue(json!([
                { "bitbucket_token": fixture.read_token, "actions": ["repo:read"], "project": "PROJ", "repository": "docs" },
                { "bitbucket_token": fixture.write_token, "actions": ["branch:create"], "project": "PROJ", "repository": "api",
                  "branches": { "branch": ["bot/**"] } }
            ]))
            .await;

        fixture
            .send(request(
                "GET",
                "/rest/api/1.0/projects/PROJ/repos/docs/raw/README.md",
                &token,
                None,
            ))
            .await;
        fixture
            .send(request(
                "POST",
                "/rest/branch-utils/latest/projects/PROJ/repos/api/branches",
                &token,
                Some(json!({ "name": "bot/update-deps", "startPoint": "main" })),
            ))
            .await;
        let (status, _, _) = fixture
            .send(request(
                "POST",
                "/rest/branch-utils/latest/projects/PROJ/repos/api/branches",
                &token,
                Some(json!({ "name": "main-copy", "startPoint": "main" })),
            ))
            .await;
        assert_eq!(status, StatusCode::FORBIDDEN);

        let authorizations: Vec<_> = fixture
            .forwarded()
            .iter()
            .map(|request| {
                request
                    .headers
                    .get(header::AUTHORIZATION)
                    .unwrap()
                    .to_str()
                    .unwrap()
                    .to_owned()
            })
            .collect();
        assert_eq!(authorizations, ["Bearer ATBB-read", "Bearer ATBB-write"]);
    }

    #[tokio::test]
    async fn removed_tokens_stop_working() {
        let fixture = fixture().await;
        let token = fixture
            .issue(json!([{ "bitbucket_token": fixture.read_token, "actions": ["repo:read"], "project": "PROJ", "repository": "api" }]))
            .await;
        assert_eq!(
            fixture.send(request("GET", REPO, &token, None)).await.0,
            StatusCode::CREATED
        );

        // Removing the Bitbucket token removes the access token that uses it.
        fixture
            .state
            .bitbucket_token_service
            .remove(fixture.read_token)
            .await
            .unwrap();

        assert_eq!(
            fixture.send(request("GET", REPO, &token, None)).await.0,
            StatusCode::UNAUTHORIZED
        );
    }

    #[tokio::test]
    async fn admin_paths_are_never_forwarded() {
        let fixture = fixture().await;
        let token = fixture
            .issue(json!([{ "bitbucket_token": fixture.read_token, "actions": ["repo:read"], "project": "PROJ", "repository": "api" }]))
            .await;

        for path in ["/webapp/unknown", "/fgatbapi/unknown", "/webapp"] {
            let (status, _, _) = fixture.send(request("POST", path, &token, None)).await;
            assert_ne!(status, StatusCode::CREATED, "{path}");
        }

        assert!(fixture.received().is_empty());
    }

    const GIT_REPO: &str = "/scm/PROJ/api.git";
    const OLD: &str = "1111111111111111111111111111111111111111";
    const NEW: &str = "2222222222222222222222222222222222222222";
    const ZERO: &str = "0000000000000000000000000000000000000000";

    /// A Git request with the token as the Basic password, as Git sends it; the body arrives in `chunks`.
    fn git_request(method: &str, uri: &str, token: &str, chunks: Vec<Vec<u8>>) -> Request<Body> {
        let basic = base64::Engine::encode(&base64::engine::general_purpose::STANDARD, format!("git:{token}"));
        let stream = futures_util::stream::iter(chunks.into_iter().map(Ok::<_, std::io::Error>));
        Request::builder()
            .method(method)
            .uri(uri)
            .header(header::AUTHORIZATION, format!("Basic {basic}"))
            .header("x-client", "1")
            .body(Body::from_stream(stream))
            .unwrap()
    }

    fn pkt(line: &str) -> Vec<u8> {
        let mut packet = format!("{:04x}", line.len() + 4).into_bytes();
        packet.extend_from_slice(line.as_bytes());
        packet
    }

    /// The body of a push: the commands, a flush packet, then `pack`.
    fn push_body(commands: &[String], pack: &[u8]) -> Vec<u8> {
        let mut body = Vec::new();
        for (idx, command) in commands.iter().enumerate() {
            let line = if idx == 0 {
                format!("{command}\0report-status side-band-64k agent=git/2.56.0\n")
            } else {
                format!("{command}\n")
            };
            body.extend(pkt(&line));
        }
        body.extend(b"0000");
        body.extend_from_slice(pack);
        body
    }

    #[tokio::test]
    async fn git_fetches_need_repo_read() {
        let fixture = fixture().await;
        let reader = fixture
            .issue(json!([{ "bitbucket_token": fixture.read_token, "actions": ["repo:read"], "project": "PROJ", "repository": "api" }]))
            .await;
        let pusher = fixture
            .issue(json!([{ "bitbucket_token": fixture.write_token, "actions": ["branch:create", "branch:git"], "project": "PROJ", "repository": "api" }]))
            .await;

        let advertisement = format!("{GIT_REPO}/info/refs?service=git-upload-pack");
        let (status, _, _) = fixture.send(git_request("GET", &advertisement, &reader, vec![])).await;
        assert_eq!(status, StatusCode::CREATED);
        let wants = b"0032want 2222222222222222222222222222222222222222\n00000009done\n".to_vec();
        let (status, _, _) = fixture
            .send(git_request(
                "POST",
                "/scm/proj/api/git-upload-pack",
                &reader,
                vec![wants.clone()],
            ))
            .await;
        assert_eq!(status, StatusCode::CREATED);

        let forwarded = fixture.forwarded();
        assert_eq!(forwarded[0].path_and_query, advertisement);
        assert_eq!(forwarded[1].body.as_ref(), wants.as_slice());
        assert!(
            forwarded
                .iter()
                .all(|sent| sent.headers.get(header::AUTHORIZATION).unwrap() == "Bearer ATBB-read")
        );

        // Pushing rights do not include reading, and other repositories are out of reach.
        for (token, uri) in [
            (&pusher, advertisement.clone()),
            (
                &reader,
                "/scm/PROJ/web.git/info/refs?service=git-upload-pack".to_owned(),
            ),
        ] {
            let (status, headers, body) = fixture.send(git_request("GET", &uri, token, vec![])).await;
            assert_eq!(status, StatusCode::FORBIDDEN, "{uri}");
            assert_eq!(headers.get(header::CONTENT_TYPE).unwrap(), "text/plain; charset=utf-8");
            assert!(
                body.starts_with("access token does not allow repo:read on PROJ/"),
                "{body}"
            );
        }

        // Only the smart protocol is forwarded.
        for uri in [
            format!("{GIT_REPO}/info/refs"),
            format!("{GIT_REPO}/HEAD"),
            "/scm/~alice/dotfiles.git/info/refs?service=git-upload-pack".to_owned(),
        ] {
            let (status, _, _) = fixture.send(git_request("GET", &uri, &reader, vec![])).await;
            assert_eq!(status, StatusCode::FORBIDDEN, "{uri}");
        }
        assert_eq!(fixture.forwarded().len(), 2);
    }

    #[tokio::test]
    async fn git_pushes_stream_the_pack_with_the_rule_token() {
        let fixture = fixture().await;
        let token = fixture
            .issue(json!([
                { "bitbucket_token": fixture.read_token, "actions": ["repo:read"], "project": "PROJ", "repository": "api" },
                { "bitbucket_token": fixture.write_token, "actions": ["branch:create", "branch:delete", "branch:git"],
                  "project": "PROJ", "repository": "api", "branches": { "branch": ["bot/**"] } }
            ]))
            .await;

        // The refs a push starts from are read with the first rule that reads or pushes.
        let advertisement = format!("{GIT_REPO}/info/refs?service=git-receive-pack");
        assert_eq!(
            fixture.send(git_request("GET", &advertisement, &token, vec![])).await.0,
            StatusCode::CREATED
        );

        // A pack larger than any buffer, with the commands split across chunks.
        let pack: Vec<u8> = (0..3_000_000u32).map(|idx| (idx % 251) as u8).collect();
        let body = push_body(
            &[
                format!("{OLD} {NEW} refs/heads/bot/deps"),
                format!("{ZERO} {NEW} refs/heads/bot/new"),
                format!("{OLD} {ZERO} refs/heads/bot/old"),
            ],
            &pack,
        );
        let chunks: Vec<Vec<u8>> = body
            .chunks(37)
            .take(5)
            .map(<[u8]>::to_vec)
            .chain([body[185..].to_vec()])
            .collect();
        let (status, _, _) = fixture
            .send(git_request(
                "POST",
                &format!("{GIT_REPO}/git-receive-pack"),
                &token,
                chunks,
            ))
            .await;
        assert_eq!(status, StatusCode::CREATED);

        let forwarded = fixture.forwarded();
        assert_eq!(forwarded.len(), 2);
        assert_eq!(
            forwarded[0].headers.get(header::AUTHORIZATION).unwrap(),
            "Bearer ATBB-read"
        );
        assert_eq!(forwarded[1].path_and_query, format!("{GIT_REPO}/git-receive-pack"));
        assert_eq!(
            forwarded[1].headers.get(header::AUTHORIZATION).unwrap(),
            "Bearer ATBB-write"
        );
        assert!(
            forwarded[1].body.as_ref() == body.as_slice(),
            "the push reaches Bitbucket byte for byte"
        );
    }

    #[tokio::test]
    async fn denied_git_pushes_are_reported_in_git_format() {
        let fixture = fixture().await;
        let token = fixture
            .issue(json!([
                { "bitbucket_token": fixture.read_token, "actions": ["repo:read", "branch:create"], "project": "PROJ", "repository": "api" },
                { "bitbucket_token": fixture.write_token, "actions": ["branch:create", "branch:git"],
                  "project": "PROJ", "repository": "api", "branches": { "branch": ["bot/**"] } },
                { "bitbucket_token": fixture.write_token, "actions": ["branch:create", "branch:git"],
                  "project": "PROJ", "repository": "api", "branches": { "branch": ["release/*"] } }
            ]))
            .await;
        let receive_pack = format!("{GIT_REPO}/git-receive-pack");

        for (commands, denied_ref, reason) in [
            (
                vec![format!("{OLD} {NEW} refs/heads/main")],
                "refs/heads/main",
                "access token does not allow Git to push to branch main",
            ),
            (
                vec![format!("{OLD} {ZERO} refs/heads/bot/old")],
                "refs/heads/bot/old",
                "access token does not allow Git to delete branch bot/old",
            ),
            (
                vec![
                    format!("{OLD} {NEW} refs/heads/bot/x"),
                    format!("{ZERO} {NEW} refs/tags/v1"),
                ],
                "refs/tags/v1",
                "only branches can be pushed through the proxy",
            ),
            (
                vec![
                    format!("{OLD} {NEW} refs/heads/bot/x"),
                    format!("{OLD} {NEW} refs/heads/release/1"),
                ],
                "refs/heads/release/1",
                "access token does not allow Git to push to branch release/1",
            ),
        ] {
            let body = push_body(&commands, b"PACK pack data");
            let (status, headers, report) = fixture
                .send(git_request("POST", &receive_pack, &token, vec![body]))
                .await;

            assert_eq!(status, StatusCode::OK, "{denied_ref}");
            assert_eq!(
                headers.get(header::CONTENT_TYPE).unwrap(),
                "application/x-git-receive-pack-result"
            );
            assert!(report.contains(&format!("ng {denied_ref} {reason}\n")), "{report}");
            assert!(
                report.contains(&format!("\u{2}access token denied the push: {reason}\n")),
                "{report}"
            );
        }

        // A client that asks for no report gets a plain error.
        let mut body = pkt(&format!("{OLD} {NEW} refs/heads/main\0agent=git/2.56.0\n"));
        body.extend(b"0000PACK");
        let (status, _, message) = fixture
            .send(git_request("POST", &receive_pack, &token, vec![body]))
            .await;
        assert_eq!(status, StatusCode::FORBIDDEN);
        assert_eq!(message, "access token does not allow Git to push to branch main\n");

        // Without branch:git anywhere, pushes are denied outright, and so are malformed ones.
        let reader = fixture
            .issue(json!([{ "bitbucket_token": fixture.read_token, "actions": ["repo:read", "branch:*"], "project": "PROJ", "repository": "web" }]))
            .await;
        let body = push_body(&[format!("{OLD} {NEW} refs/heads/main")], b"PACK");
        let (_, _, report) = fixture
            .send(git_request(
                "POST",
                "/scm/PROJ/api.git/git-receive-pack",
                &reader,
                vec![body],
            ))
            .await;
        assert!(
            report.contains("access token does not allow Git pushes to PROJ/api"),
            "{report}"
        );
        let (status, _, _) = fixture
            .send(git_request("POST", &receive_pack, &token, vec![b"0000".to_vec()]))
            .await;
        assert_eq!(status, StatusCode::FORBIDDEN);

        assert!(fixture.forwarded().is_empty(), "denied pushes never reach Bitbucket");
    }
}
