//! Management of Bitbucket access tokens.
//!
//! The page lives in the admin panel, while the actions it performs through htmx live under [`API_PATH`].
//! Every action answers with the HTML fragment that htmx swaps into the page, so the page never reloads.

use askama::Template;
use askama_web::WebTemplate;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse as _, Response};
use axum::routing::{delete, get, post};
use axum::{Form, Router};
use secret::Secret;
use serde::Deserialize;
use tracing::info;
use uuid::Uuid;

use super::auth::AuthSession;
use super::utc_minutes;
use crate::db::BitbucketTokenSummary;
use crate::services::{BitbucketTokenRejection, MAX_TOKEN_LEN, MAX_TOKEN_NAME_LEN};
use crate::state::AppState;
use crate::{Error, Result};

pub(super) const PAGE_PATH: &str = "/webapp/bitbucket_tokens";
const API_PATH: &str = "/fgatbapi/bitbucket_tokens";
const API_TOKEN_PATH: &str = "/fgatbapi/bitbucket_tokens/{id}";

pub(super) fn router() -> Router<AppState> {
    Router::new()
        .route(PAGE_PATH, get(page))
        .route(API_PATH, post(add))
        .route(API_TOKEN_PATH, delete(remove))
}

/// The whole page.
#[derive(Template, WebTemplate)]
#[template(path = "bitbucket_tokens.html")]
struct TokensPage {
    tokens: Vec<TokenRow>,
    name: String,
    error: Option<String>,
    max_name_len: usize,
}

/// The add form together with the list, swapped in after an add attempt.
#[derive(Template, WebTemplate)]
#[template(path = "partials/bitbucket_tokens_section.html")]
struct TokensSection {
    tokens: Vec<TokenRow>,
    /// Name to keep in the form after a rejected add.
    name: String,
    error: Option<String>,
    max_name_len: usize,
}

/// The list alone, swapped in after a removal.
#[derive(Template, WebTemplate)]
#[template(path = "partials/bitbucket_tokens_list.html")]
struct TokensList {
    tokens: Vec<TokenRow>,
}

/// A token as shown in the list.
struct TokenRow {
    id: Uuid,
    name: String,
    /// Creation time in UTC, e.g. `2026-11-18 20:00`.
    created_at: String,
    /// The removal confirmation, naming the access tokens removed along with it.
    confirm: String,
}

impl TokenRow {
    fn new(token: BitbucketTokenSummary, dependents: &[String]) -> Self {
        let mut confirm = format!("Remove the token \"{}\"? This cannot be undone.", token.name);
        if !dependents.is_empty() {
            let names = dependents
                .iter()
                .map(|name| format!("\"{name}\""))
                .collect::<Vec<_>>()
                .join(", ");
            confirm.push_str(&format!(
                "\n\nThese access tokens use it and will be removed too: {names}."
            ));
        }

        Self {
            id: token.id,
            name: token.name,
            created_at: utc_minutes(token.created_at),
            confirm,
        }
    }
}

#[derive(Deserialize)]
struct AddTokenForm {
    name: String,
    token: Secret<String>,
}

async fn page(_auth: AuthSession, State(state): State<AppState>) -> Result<TokensPage> {
    Ok(TokensPage {
        tokens: token_rows(&state).await?,
        name: String::new(),
        error: None,
        max_name_len: MAX_TOKEN_NAME_LEN,
    })
}

async fn add(_auth: AuthSession, State(state): State<AppState>, Form(form): Form<AddTokenForm>) -> Result<Response> {
    let (status, name, error) = match state.bitbucket_token_service.add(&form.name, form.token).await {
        Ok(token_id) => {
            info!(%token_id, name = form.name.trim(), "Bitbucket token added");
            (StatusCode::OK, String::new(), None)
        }
        Err(Error::InvalidBitbucketToken(rejection)) => {
            let message = match rejection {
                BitbucketTokenRejection::EmptyName => "Enter a name for the token".to_owned(),
                BitbucketTokenRejection::NameTooLong => {
                    format!("The name must be at most {MAX_TOKEN_NAME_LEN} characters long")
                }
                BitbucketTokenRejection::NameTaken => "A token with this name already exists".to_owned(),
                BitbucketTokenRejection::EmptyToken => "Enter the token value".to_owned(),
                BitbucketTokenRejection::TokenTooLong => {
                    format!("The token must be at most {MAX_TOKEN_LEN} bytes long")
                }
            };
            (StatusCode::UNPROCESSABLE_ENTITY, form.name, Some(message))
        }
        Err(error) => return Err(error),
    };

    let section = TokensSection {
        tokens: token_rows(&state).await?,
        name,
        error,
        max_name_len: MAX_TOKEN_NAME_LEN,
    };

    Ok((status, section).into_response())
}

/// Removes the token and returns the updated list.
///
/// Removing a token that no longer exists is not an error, so a repeated request still shows the current list.
async fn remove(_auth: AuthSession, State(state): State<AppState>, Path(id): Path<Uuid>) -> Result<TokensList> {
    let dependents = state.bitbucket_token_service.dependent_access_tokens(id).await?;

    if state.bitbucket_token_service.remove(id).await? {
        info!(token_id = %id, removed_access_tokens = ?dependents, "Bitbucket token removed");
    }

    Ok(TokensList {
        tokens: token_rows(&state).await?,
    })
}

async fn token_rows(state: &AppState) -> Result<Vec<TokenRow>> {
    let tokens = state.bitbucket_token_service.list().await?;

    let mut rows = Vec::with_capacity(tokens.len());
    for token in tokens {
        let dependents = state.bitbucket_token_service.dependent_access_tokens(token.id).await?;
        rows.push(TokenRow::new(token, &dependents));
    }

    Ok(rows)
}

#[cfg(test)]
mod tests {
    use axum::body::Body;
    use axum::http::{Request, StatusCode, header};
    use axum::response::Response;

    use crate::routes::testing::*;

    fn add_request(cookie: &str, name: &str, token: &str) -> Request<Body> {
        with_form(
            authenticated(Request::post("/fgatbapi/bitbucket_tokens"), cookie).header("hx-request", "true"),
            &[("name", name), ("token", token)],
        )
    }

    fn remove_request(cookie: &str, id: &str) -> Request<Body> {
        authenticated(Request::delete(format!("/fgatbapi/bitbucket_tokens/{id}")), cookie)
            .header("hx-request", "true")
            .body(Body::empty())
            .unwrap()
    }

    /// Extracts the ID from the first remove button in the rendered list.
    fn first_token_id(html: &str) -> String {
        let (_, rest) = html.split_once(r#"hx-delete="/fgatbapi/bitbucket_tokens/"#).unwrap();
        rest.split('"').next().unwrap().to_owned()
    }

    fn assert_htmx_login_redirect(response: &Response) {
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        assert_eq!(response.headers().get("hx-redirect").unwrap(), "/webapp/login");
    }

    #[tokio::test]
    async fn page_requires_session() {
        let (app, _state) = setup().await;

        let response = send(&app, get("/webapp/bitbucket_tokens")).await;

        assert_eq!(response.status(), StatusCode::SEE_OTHER);
        assert_eq!(location(&response), "/webapp/login");
    }

    #[tokio::test]
    async fn api_requires_session() {
        let (app, state) = setup().await;

        assert_htmx_login_redirect(&send(&app, add_request("forged", "ci", "value")).await);
        assert_htmx_login_redirect(&send(&app, remove_request("forged", &uuid::Uuid::new_v4().to_string())).await);
        assert!(state.bitbucket_token_service.list().await.unwrap().is_empty());

        // Without the htmx header the browser gets a regular redirect.
        let response = send(
            &app,
            form_request("/fgatbapi/bitbucket_tokens", &[("name", "ci"), ("token", "v")]),
        )
        .await;
        assert_eq!(response.status(), StatusCode::SEE_OTHER);
        assert_eq!(location(&response), "/webapp/login");
    }

    #[tokio::test]
    async fn page_shows_header_form_and_empty_list() {
        let (app, _state, cookie) = setup_logged_in().await;

        let response = send(&app, with_cookie(Request::get("/webapp/bitbucket_tokens"), &cookie)).await;
        assert_eq!(response.status(), StatusCode::OK);
        let html = body_text(response).await;

        assert!(html.contains(r#"<a href="/webapp/bitbucket_tokens">/bitbucket_tokens</a>"#));
        assert!(html.contains(r#"hx-post="/fgatbapi/bitbucket_tokens""#));
        assert!(html.contains("No tokens found"));
        assert!(html.contains("htmx.org@"));
        assert!(html.contains(
            r#"<p class="page-hint"><a href="https://confluence.atlassian.com/bitbucketserver102/http-access-tokens-1791787433.html" target="_blank" rel="noopener noreferrer">Bitbucket HTTP access tokens</a>"#
        ));
    }

    #[tokio::test]
    async fn add_then_remove() {
        let (app, state, cookie) = setup_logged_in().await;

        let response = send(&app, add_request(&cookie, "deploy <ci>", "ATBB-secret-value")).await;
        assert_eq!(response.status(), StatusCode::OK);
        let section = body_text(response).await;
        assert!(section.starts_with(r#"<section id="bitbucket-tokens">"#));
        assert!(section.contains("<td>deploy &#60;ci&#62;</td>"));
        assert!(section.contains("Added (UTC)"));
        assert!(!section.contains("No tokens found"));
        assert!(!section.contains("ATBB-secret-value"));
        assert!(section.contains(r#"name="name""#) && section.contains(r#"value="""#));

        let page = body_text(send(&app, with_cookie(Request::get("/webapp/bitbucket_tokens"), &cookie)).await).await;
        assert!(page.contains("<td>deploy &#60;ci&#62;</td>"));
        assert!(
            page.contains(r#"hx-confirm="Remove the token &#34;deploy &#60;ci&#62;&#34;? This cannot be undone.""#)
        );

        let response = send(&app, remove_request(&cookie, &first_token_id(&page))).await;
        assert_eq!(response.status(), StatusCode::OK);
        let list = body_text(response).await;
        assert!(list.starts_with(r#"<div id="bitbucket-tokens-list">"#));
        assert!(list.contains("No tokens found"));
        assert!(state.bitbucket_token_service.list().await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn add_rejects_invalid_input_and_keeps_name() {
        let (app, _state, cookie) = setup_logged_in().await;

        send(&app, add_request(&cookie, "ci", "value")).await;

        let response = send(&app, add_request(&cookie, "ci", "other")).await;
        assert_eq!(response.status(), StatusCode::UNPROCESSABLE_ENTITY);
        let section = body_text(response).await;
        assert!(section.contains("A token with this name already exists"));
        assert!(section.contains(r#"value="ci""#));

        let response = send(&app, add_request(&cookie, "release", "  ")).await;
        assert_eq!(response.status(), StatusCode::UNPROCESSABLE_ENTITY);
        assert!(body_text(response).await.contains("Enter the token value"));
    }

    #[tokio::test]
    async fn remove_unknown_token_returns_list() {
        let (app, _state, cookie) = setup_logged_in().await;

        let response = send(&app, remove_request(&cookie, &uuid::Uuid::new_v4().to_string())).await;
        assert_eq!(response.status(), StatusCode::OK);
        assert!(body_text(response).await.contains("No tokens found"));

        let response = send(&app, remove_request(&cookie, "not-a-uuid")).await;
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn api_paths_are_not_under_webapp() {
        let (app, _state, cookie) = setup_logged_in().await;

        let response = send(
            &app,
            with_form(
                authenticated(Request::post("/webapp/bitbucket_tokens"), &cookie),
                &[("name", "ci"), ("token", "value")],
            ),
        )
        .await;

        assert_eq!(response.status(), StatusCode::METHOD_NOT_ALLOWED);
        assert!(response.headers().get(header::ALLOW).is_some());
    }
}
