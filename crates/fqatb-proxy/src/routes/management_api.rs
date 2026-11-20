//! The management API: Bitbucket tokens and access tokens over JSON, for scripts that do not use the admin panel.
//!
//! Every route requires `Authorization: Bearer <management token>`.
//! The admin session cookie is deliberately not accepted, so that a page in the admin's browser cannot call the API on
//! their behalf.
//! Errors use the same JSON format as the proxy's Bitbucket-compatible API.

use axum::extract::rejection::{JsonRejection, PathRejection, QueryRejection};
use axum::extract::{FromRequestParts, Path, Query, State};
use axum::http::request::Parts;
use axum::http::{HeaderValue, StatusCode, header};
use axum::response::{IntoResponse as _, Response};
use axum::routing::{delete, get};
use axum::{Json, Router};
use secret::Secret;
use serde::{Deserialize, Serialize};
use serde_json::json;
use time::format_description::well_known::Rfc3339;
use time::{OffsetDateTime, UtcOffset};
use tracing::info;
use uuid::Uuid;

use super::access_tokens::rule_error_message;
use super::json_error;
use crate::Error;
use crate::db::ManagementTokenSummary;
use crate::policy::{Policy, PolicyError, PolicySpec};
use crate::services::{
    AccessTokenRejection, BitbucketTokenRejection, MAX_ACCESS_TOKEN_NAME_LEN, MAX_TOKEN_LEN, MAX_TOKEN_NAME_LEN,
    TOKEN_LIFETIMES_DAYS, token_expiry,
};
use crate::state::AppState;

const BITBUCKET_TOKENS_PATH: &str = "/fgatbapi/v1/bitbucket_tokens";
const BITBUCKET_TOKEN_PATH: &str = "/fgatbapi/v1/bitbucket_tokens/{id}";
const ACCESS_TOKENS_PATH: &str = "/fgatbapi/v1/access_tokens";
const ACCESS_TOKEN_PATH: &str = "/fgatbapi/v1/access_tokens/{id}";

pub(super) fn router() -> Router<AppState> {
    Router::new()
        .route(
            BITBUCKET_TOKENS_PATH,
            get(list_bitbucket_tokens).post(add_bitbucket_token),
        )
        .route(BITBUCKET_TOKEN_PATH, delete(remove_bitbucket_token))
        .route(ACCESS_TOKENS_PATH, get(list_access_tokens).post(create_access_token))
        .route(ACCESS_TOKEN_PATH, delete(remove_access_token))
}

/// A request authenticated with a management token.
struct ManagementAuth {
    token: ManagementTokenSummary,
}

impl FromRequestParts<AppState> for ManagementAuth {
    type Rejection = Response;

    async fn from_request_parts(parts: &mut Parts, state: &AppState) -> std::result::Result<Self, Self::Rejection> {
        let presented = parts
            .headers
            .get(header::AUTHORIZATION)
            .and_then(|value| value.to_str().ok())
            .and_then(|value| value.split_once(' '))
            .filter(|(scheme, _)| scheme.eq_ignore_ascii_case("bearer"))
            .map(|(_, token)| Secret::new(token.trim().to_owned()));

        let Some(presented) = presented else {
            return Err(unauthorized("authentication with a management token is required"));
        };

        match state.management_token_service.authenticate(presented.as_ref()).await {
            Ok(Some(token)) => Ok(Self { token }),
            Ok(None) => Err(unauthorized("management token is invalid or expired")),
            Err(error) => Err(api_error(error)),
        }
    }
}

#[derive(Serialize)]
struct BitbucketTokenJson {
    id: Uuid,
    name: String,
    created_at: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct AddBitbucketToken {
    name: String,
    token: Secret<String>,
}

#[derive(Serialize)]
struct AddedBitbucketToken {
    id: Uuid,
    name: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RemoveBitbucketTokenQuery {
    /// Whether to also remove the access tokens that use the Bitbucket token.
    #[serde(default)]
    remove_access_tokens: bool,
}

#[derive(Serialize)]
struct RemovedBitbucketToken {
    removed_access_tokens: Vec<String>,
}

#[derive(Serialize)]
struct AccessTokenJson {
    id: Uuid,
    name: String,
    created_at: String,
    expires_at: String,
    expired: bool,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CreateAccessToken {
    name: String,
    expires_in_days: u16,
    policy: PolicySpec,
}

#[derive(Serialize)]
struct CreatedAccessToken {
    id: Uuid,
    name: String,
    /// The full token: this response is the only time it is available.
    token: String,
    expires_at: String,
}

async fn list_bitbucket_tokens(_auth: ManagementAuth, State(state): State<AppState>) -> Response {
    match state.bitbucket_token_service.list().await {
        Ok(tokens) => {
            let tokens: Vec<_> = tokens
                .into_iter()
                .map(|token| BitbucketTokenJson {
                    id: token.id,
                    name: token.name,
                    created_at: timestamp(token.created_at),
                })
                .collect();
            Json(tokens).into_response()
        }
        Err(error) => api_error(error),
    }
}

async fn add_bitbucket_token(
    auth: ManagementAuth,
    State(state): State<AppState>,
    body: std::result::Result<Json<AddBitbucketToken>, JsonRejection>,
) -> Response {
    let Json(body) = match body {
        Ok(body) => body,
        Err(rejection) => return json_rejection(&rejection),
    };

    match state.bitbucket_token_service.add(&body.name, body.token).await {
        Ok(id) => {
            let name = body.name.trim().to_owned();
            info!(management_token_id = %auth.token.id, bitbucket_token_id = %id, %name, "Bitbucket token added through the management API");
            (StatusCode::CREATED, Json(AddedBitbucketToken { id, name })).into_response()
        }
        Err(Error::InvalidBitbucketToken(rejection)) => {
            let message = match rejection {
                BitbucketTokenRejection::EmptyName => "name is empty".to_owned(),
                BitbucketTokenRejection::NameTooLong => {
                    format!("name is longer than {MAX_TOKEN_NAME_LEN} characters")
                }
                BitbucketTokenRejection::NameTaken => "a Bitbucket token with this name already exists".to_owned(),
                BitbucketTokenRejection::EmptyToken => "token is empty".to_owned(),
                BitbucketTokenRejection::TokenTooLong => format!("token is longer than {MAX_TOKEN_LEN} bytes"),
            };
            json_error(StatusCode::UNPROCESSABLE_ENTITY, &message)
        }
        Err(error) => api_error(error),
    }
}

/// Removes a Bitbucket token.
///
/// Access tokens that use it would stop working, so they are removed with it, but only when the caller asks for it
/// with `remove_access_tokens=true`; otherwise the request fails with `409 Conflict` naming them.
async fn remove_bitbucket_token(
    auth: ManagementAuth,
    State(state): State<AppState>,
    id: std::result::Result<Path<Uuid>, PathRejection>,
    query: std::result::Result<Query<RemoveBitbucketTokenQuery>, QueryRejection>,
) -> Response {
    let Ok(Path(id)) = id else {
        return json_error(StatusCode::NOT_FOUND, "Bitbucket token does not exist");
    };
    let Query(query) = match query {
        Ok(query) => query,
        Err(rejection) => return json_error(StatusCode::BAD_REQUEST, &rejection.body_text()),
    };

    let dependents = match state.bitbucket_token_service.dependent_access_tokens(id).await {
        Ok(dependents) => dependents,
        Err(error) => return api_error(error),
    };

    if !dependents.is_empty() && !query.remove_access_tokens {
        let message = format!(
            "Bitbucket token is used by access tokens {}; repeat the request with remove_access_tokens=true to remove them too",
            dependents.join(", ")
        );
        // The error format, with the dependents also in a field of their own for scripts.
        let body = json!({
            "errors": [{ "context": null, "message": message, "exceptionName": null }],
            "access_tokens": dependents,
        });
        return (StatusCode::CONFLICT, Json(body)).into_response();
    }

    match state.bitbucket_token_service.remove(id).await {
        Ok(true) => {
            info!(
                management_token_id = %auth.token.id,
                bitbucket_token_id = %id,
                removed_access_tokens = dependents.len(),
                "Bitbucket token removed through the management API"
            );
            if dependents.is_empty() {
                StatusCode::NO_CONTENT.into_response()
            } else {
                Json(RemovedBitbucketToken {
                    removed_access_tokens: dependents,
                })
                .into_response()
            }
        }
        Ok(false) => json_error(StatusCode::NOT_FOUND, "Bitbucket token does not exist"),
        Err(error) => api_error(error),
    }
}

async fn list_access_tokens(_auth: ManagementAuth, State(state): State<AppState>) -> Response {
    let now = OffsetDateTime::now_utc();

    match state.access_token_service.list().await {
        Ok(tokens) => {
            let tokens: Vec<_> = tokens
                .into_iter()
                .map(|token| AccessTokenJson {
                    id: token.id,
                    name: token.name,
                    created_at: timestamp(token.created_at),
                    expires_at: timestamp(token.expires_at),
                    expired: !(now < token.expires_at),
                })
                .collect();
            Json(tokens).into_response()
        }
        Err(error) => api_error(error),
    }
}

async fn create_access_token(
    auth: ManagementAuth,
    State(state): State<AppState>,
    body: std::result::Result<Json<CreateAccessToken>, JsonRejection>,
) -> Response {
    let Json(body) = match body {
        Ok(body) => body,
        Err(rejection) => return json_rejection(&rejection),
    };

    let Some(expires_at) = token_expiry(body.expires_in_days, OffsetDateTime::now_utc()) else {
        let offered = TOKEN_LIFETIMES_DAYS.map(|days| days.to_string()).join(", ");
        return json_error(
            StatusCode::UNPROCESSABLE_ENTITY,
            &format!("expires_in_days must be one of {offered}"),
        );
    };

    let policy = match Policy::try_from(body.policy) {
        Ok(policy) => policy,
        Err(error) => {
            let message = match error {
                PolicyError::UnsupportedVersion(version) => format!("unsupported policy version {version}"),
                PolicyError::NoRules => "policy has no rules".to_owned(),
                PolicyError::Rule { rule, error } => format!("rule {rule}: {}", rule_error_message(error)),
            };
            return json_error(StatusCode::UNPROCESSABLE_ENTITY, &message);
        }
    };
    let rules = policy.rules().len();

    match state.access_token_service.issue(&body.name, policy, expires_at).await {
        Ok(issued) => {
            let name = body.name.trim().to_owned();
            info!(
                management_token_id = %auth.token.id,
                access_token_id = %issued.id,
                %name,
                rules,
                %expires_at,
                "Access token issued through the management API"
            );
            let created = CreatedAccessToken {
                id: issued.id,
                name,
                token: issued.token.as_ref().clone(),
                expires_at: timestamp(expires_at),
            };
            (StatusCode::CREATED, Json(created)).into_response()
        }
        Err(Error::InvalidAccessToken(rejection)) => {
            let message = match rejection {
                AccessTokenRejection::EmptyName => "name is empty".to_owned(),
                AccessTokenRejection::NameTooLong => {
                    format!("name is longer than {MAX_ACCESS_TOKEN_NAME_LEN} characters")
                }
                AccessTokenRejection::NameTaken => "an access token with this name already exists".to_owned(),
                AccessTokenRejection::AlreadyExpired => "expiration is not in the future".to_owned(),
                AccessTokenRejection::UnknownBitbucketToken => {
                    "policy uses a Bitbucket token that does not exist".to_owned()
                }
            };
            json_error(StatusCode::UNPROCESSABLE_ENTITY, &message)
        }
        Err(error) => api_error(error),
    }
}

async fn remove_access_token(
    auth: ManagementAuth,
    State(state): State<AppState>,
    id: std::result::Result<Path<Uuid>, PathRejection>,
) -> Response {
    let Ok(Path(id)) = id else {
        return json_error(StatusCode::NOT_FOUND, "access token does not exist");
    };

    match state.access_token_service.remove(id).await {
        Ok(true) => {
            info!(management_token_id = %auth.token.id, access_token_id = %id, "Access token removed through the management API");
            StatusCode::NO_CONTENT.into_response()
        }
        Ok(false) => json_error(StatusCode::NOT_FOUND, "access token does not exist"),
        Err(error) => api_error(error),
    }
}

/// Formats a timestamp as RFC 3339 in UTC with whole seconds, e.g. `2026-11-20T09:30:00Z`.
fn timestamp(at: OffsetDateTime) -> String {
    at.to_offset(UtcOffset::UTC)
        .replace_nanosecond(0)
        .expect("0 is a valid nanosecond")
        .format(&Rfc3339)
        .expect("a UTC timestamp with a four-digit year formats as RFC 3339")
}

fn unauthorized(message: &str) -> Response {
    let mut response = json_error(StatusCode::UNAUTHORIZED, message);
    response
        .headers_mut()
        .insert(header::WWW_AUTHENTICATE, HeaderValue::from_static("Bearer"));
    response
}

/// A body that is not JSON, or not of the expected shape.
fn json_rejection(rejection: &JsonRejection) -> Response {
    json_error(rejection.status(), &rejection.body_text())
}

fn api_error(error: Error) -> Response {
    tracing::error!(error = crate::error::report(&error), "Management API request failed");
    json_error(StatusCode::INTERNAL_SERVER_ERROR, "internal server error")
}

#[cfg(test)]
mod tests {
    use axum::body::Body;
    use axum::http::{Request, StatusCode, header};
    use serde_json::{Value, json};
    use time::{Duration, OffsetDateTime};

    use crate::routes::testing::*;
    use crate::state::AppState;

    const BITBUCKET_TOKENS: &str = "/fgatbapi/v1/bitbucket_tokens";
    const ACCESS_TOKENS: &str = "/fgatbapi/v1/access_tokens";

    async fn management_token(state: &AppState) -> String {
        state
            .management_token_service
            .issue("automation", OffsetDateTime::now_utc() + Duration::days(1))
            .await
            .unwrap()
            .token
            .as_ref()
            .clone()
    }

    fn api(method: &str, uri: &str, token: &str, body: Option<Value>) -> Request<Body> {
        let builder = Request::builder()
            .method(method)
            .uri(uri)
            .header(header::AUTHORIZATION, format!("Bearer {token}"));
        match body {
            Some(body) => builder
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(body.to_string()))
                .unwrap(),
            None => builder.body(Body::empty()).unwrap(),
        }
    }

    async fn call(app: &axum::Router, request: Request<Body>) -> (StatusCode, Value) {
        let response = send(app, request).await;
        let status = response.status();
        let text = body_text(response).await;
        let body = if text.is_empty() {
            Value::Null
        } else {
            serde_json::from_str(&text).unwrap_or_else(|_| panic!("not JSON: {text}"))
        };
        (status, body)
    }

    fn message(body: &Value) -> &str {
        body["errors"][0]["message"].as_str().unwrap()
    }

    fn policy(bitbucket_token: &str) -> Value {
        json!({ "version": 1, "rules": [
            { "bitbucket_token": bitbucket_token, "actions": ["repo:read"], "project": "PROJ", "repository": "api" }
        ] })
    }

    #[tokio::test]
    async fn requires_a_management_token() {
        let (app, state, cookie) = setup_logged_in().await;
        let removed = management_token(&state).await;
        let removed_id = state.management_token_service.list().await.unwrap()[0].id;
        state.management_token_service.remove(removed_id).await.unwrap();

        let bitbucket_token = state
            .bitbucket_token_service
            .add("read", secret::Secret::new("ATBB-read".to_owned()))
            .await
            .unwrap();
        let access_token = state
            .access_token_service
            .issue(
                "ci",
                serde_json::from_value(policy(&bitbucket_token.to_string())).unwrap(),
                OffsetDateTime::now_utc() + Duration::days(1),
            )
            .await
            .unwrap()
            .token;

        let body = json!({ "name": "new", "token": "ATBB-new" });
        let session_only = with_cookie(Request::get(BITBUCKET_TOKENS), &cookie);
        let mut requests = vec![
            Request::get(ACCESS_TOKENS).body(Body::empty()).unwrap(),
            session_only,
            api("GET", BITBUCKET_TOKENS, access_token.as_ref(), None),
            api("POST", BITBUCKET_TOKENS, &removed, Some(body.clone())),
            api("POST", BITBUCKET_TOKENS, "fgatbm_garbage", Some(body)),
        ];
        let mut basic = api("GET", BITBUCKET_TOKENS, "x", None);
        basic.headers_mut().insert(
            header::AUTHORIZATION,
            format!(
                "Basic {}",
                base64::Engine::encode(&base64::engine::general_purpose::STANDARD, format!("x:{removed}"))
            )
            .parse()
            .unwrap(),
        );
        requests.push(basic);

        for request in requests {
            let uri = request.uri().to_string();
            let response = send(&app, request).await;
            assert_eq!(response.status(), StatusCode::UNAUTHORIZED, "{uri}");
            assert_eq!(response.headers().get(header::WWW_AUTHENTICATE).unwrap(), "Bearer");
            let body: Value = serde_json::from_str(&body_text(response).await).unwrap();
            assert!(message(&body).contains("management token"), "{uri}: {body}");
        }

        assert_eq!(state.bitbucket_token_service.list().await.unwrap().len(), 1);
    }

    #[tokio::test]
    async fn bitbucket_tokens() {
        let (app, state) = setup().await;
        let token = management_token(&state).await;

        let (status, body) = call(&app, api("GET", BITBUCKET_TOKENS, &token, None)).await;
        assert_eq!((status, body), (StatusCode::OK, json!([])));

        let (status, added) = call(
            &app,
            api(
                "POST",
                BITBUCKET_TOKENS,
                &token,
                Some(json!({ "name": " ci ", "token": "ATBB-secret" })),
            ),
        )
        .await;
        assert_eq!(status, StatusCode::CREATED);
        assert_eq!(added["name"], "ci");
        let id = added["id"].as_str().unwrap().to_owned();

        let response = send(&app, api("GET", BITBUCKET_TOKENS, &token, None)).await;
        let text = body_text(response).await;
        assert!(!text.contains("ATBB-secret"), "values are never listed: {text}");
        let listed: Value = serde_json::from_str(&text).unwrap();
        assert_eq!(listed[0]["id"], id.as_str());
        assert_eq!(listed[0]["name"], "ci");
        assert!(listed[0]["created_at"].as_str().unwrap().ends_with('Z'));

        for (body, status, expected) in [
            (
                json!({ "name": "ci", "token": "ATBB-other" }),
                StatusCode::UNPROCESSABLE_ENTITY,
                "a Bitbucket token with this name already exists",
            ),
            (
                json!({ "name": "other", "token": " " }),
                StatusCode::UNPROCESSABLE_ENTITY,
                "token is empty",
            ),
            (
                json!({ "name": "other" }),
                StatusCode::UNPROCESSABLE_ENTITY,
                "missing field `token`",
            ),
            (
                json!({ "name": "other", "token": "x", "admin": true }),
                StatusCode::UNPROCESSABLE_ENTITY,
                "unknown field `admin`",
            ),
        ] {
            let (actual, response) = call(&app, api("POST", BITBUCKET_TOKENS, &token, Some(body.clone()))).await;
            assert_eq!(actual, status, "{body}");
            assert!(message(&response).contains(expected), "{body}: {response}");
        }

        let mut not_json = api("POST", BITBUCKET_TOKENS, &token, None);
        not_json
            .headers_mut()
            .insert(header::CONTENT_TYPE, "application/json".parse().unwrap());
        *not_json.body_mut() = Body::from("{");
        assert_eq!(call(&app, not_json).await.0, StatusCode::BAD_REQUEST);

        let (status, body) = call(&app, api("DELETE", &format!("{BITBUCKET_TOKENS}/{id}"), &token, None)).await;
        assert_eq!((status, body), (StatusCode::NO_CONTENT, Value::Null));
        for missing in [id.as_str(), "not-a-uuid"] {
            let (status, _) = call(
                &app,
                api("DELETE", &format!("{BITBUCKET_TOKENS}/{missing}"), &token, None),
            )
            .await;
            assert_eq!(status, StatusCode::NOT_FOUND, "{missing}");
        }
        assert!(state.bitbucket_token_service.list().await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn access_tokens() {
        let (app, state) = setup().await;
        let token = management_token(&state).await;
        let (_, added) = call(
            &app,
            api(
                "POST",
                BITBUCKET_TOKENS,
                &token,
                Some(json!({ "name": "read", "token": "ATBB-read" })),
            ),
        )
        .await;
        let bitbucket_token = added["id"].as_str().unwrap().to_owned();

        let (status, created) = call(
            &app,
            api(
                "POST",
                ACCESS_TOKENS,
                &token,
                Some(json!({ "name": "ci", "expires_in_days": 7, "policy": policy(&bitbucket_token) })),
            ),
        )
        .await;
        assert_eq!(status, StatusCode::CREATED, "{created}");
        let access_token = created["token"].as_str().unwrap().to_owned();
        assert!(access_token.starts_with("fgatb_"));
        let expires_at = OffsetDateTime::parse(
            created["expires_at"].as_str().unwrap(),
            &time::format_description::well_known::Rfc3339,
        )
        .unwrap();
        assert_eq!((expires_at - OffsetDateTime::now_utc()).whole_hours(), 7 * 24 - 1);

        // The token works on the proxy: it passes authorization, and only Bitbucket itself is out of reach here.
        let repo = "/rest/api/latest/projects/PROJ/repos/api";
        let proxied = send(&app, api("GET", repo, &access_token, None)).await;
        assert_eq!(proxied.status(), StatusCode::BAD_GATEWAY);
        let other = send(
            &app,
            api("GET", "/rest/api/latest/projects/PROJ/repos/web", &access_token, None),
        )
        .await;
        assert_eq!(other.status(), StatusCode::FORBIDDEN);

        let response = send(&app, api("GET", ACCESS_TOKENS, &token, None)).await;
        let text = body_text(response).await;
        assert!(!text.contains("fgatb_"), "tokens are never listed: {text}");
        let listed: Value = serde_json::from_str(&text).unwrap();
        assert_eq!(listed[0]["id"], created["id"]);
        assert_eq!(listed[0]["expired"], false);

        let rule_with_source = json!({ "version": 1, "rules": [
            { "bitbucket_token": bitbucket_token, "actions": ["repo:read"], "project": "PROJ", "repository": "api",
              "branches": { "source": ["feature/**"] } }
        ] });
        for (body, expected) in [
            (
                json!({ "name": "ci", "expires_in_days": 7, "policy": policy(&bitbucket_token) }),
                "an access token with this name already exists",
            ),
            (
                json!({ "name": "other", "expires_in_days": 14, "policy": policy(&bitbucket_token) }),
                "expires_in_days must be one of 1, 7, 30, 90",
            ),
            (
                json!({ "name": "other", "expires_in_days": 7, "policy": { "version": 1, "rules": [] } }),
                "policy has no rules",
            ),
            (
                json!({ "name": "other", "expires_in_days": 7, "policy": rule_with_source }),
                "rule 1: source branches only limit pull request and comment actions",
            ),
            (
                json!({ "name": "other", "expires_in_days": 7, "policy": policy(&uuid::Uuid::new_v4().to_string()) }),
                "policy uses a Bitbucket token that does not exist",
            ),
        ] {
            let (status, response) = call(&app, api("POST", ACCESS_TOKENS, &token, Some(body.clone()))).await;
            assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{body}");
            assert!(message(&response).starts_with(expected), "{body}: {response}");
        }

        let id = created["id"].as_str().unwrap();
        let (status, _) = call(&app, api("DELETE", &format!("{ACCESS_TOKENS}/{id}"), &token, None)).await;
        assert_eq!(status, StatusCode::NO_CONTENT);
        let (status, _) = call(&app, api("DELETE", &format!("{ACCESS_TOKENS}/{id}"), &token, None)).await;
        assert_eq!(status, StatusCode::NOT_FOUND);
        assert_eq!(
            send(&app, api("GET", repo, &access_token, None)).await.status(),
            StatusCode::UNAUTHORIZED
        );
    }

    #[tokio::test]
    async fn removing_a_used_bitbucket_token_needs_confirmation() {
        let (app, state) = setup().await;
        let token = management_token(&state).await;
        let (_, added) = call(
            &app,
            api(
                "POST",
                BITBUCKET_TOKENS,
                &token,
                Some(json!({ "name": "read", "token": "ATBB-read" })),
            ),
        )
        .await;
        let bitbucket_token = added["id"].as_str().unwrap().to_owned();
        for name in ["ci", "backup"] {
            let body = json!({ "name": name, "expires_in_days": 1, "policy": policy(&bitbucket_token) });
            assert_eq!(
                call(&app, api("POST", ACCESS_TOKENS, &token, Some(body))).await.0,
                StatusCode::CREATED
            );
        }
        let path = format!("{BITBUCKET_TOKENS}/{bitbucket_token}");

        let (status, body) = call(&app, api("DELETE", &path, &token, None)).await;
        assert_eq!(status, StatusCode::CONFLICT);
        assert_eq!(body["access_tokens"], json!(["backup", "ci"]));
        assert!(message(&body).contains("remove_access_tokens=true"));
        assert_eq!(state.access_token_service.list().await.unwrap().len(), 2);

        let (status, body) = call(
            &app,
            api("DELETE", &format!("{path}?remove_access_tokens=true"), &token, None),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body, json!({ "removed_access_tokens": ["backup", "ci"] }));
        assert!(state.access_token_service.list().await.unwrap().is_empty());
        assert!(state.bitbucket_token_service.list().await.unwrap().is_empty());
    }
}
