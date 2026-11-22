//! Management tokens, the admin panel's home page.
//!
//! The page lives in the admin panel, while the actions it performs through htmx live under [`API_PATH`].

use askama::Template;
use askama_web::WebTemplate;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse as _, Response};
use axum::routing::{delete, get, post};
use axum::{Form, Router};
use serde::Deserialize;
use time::OffsetDateTime;
use tracing::info;
use uuid::Uuid;

use super::auth::AuthSession;
use super::{LifetimeOption, form_token_expiry, lifetime_options, utc_minutes};
use crate::db::ManagementTokenSummary;
use crate::services::{DEFAULT_TOKEN_LIFETIME_DAYS, MAX_MANAGEMENT_TOKEN_NAME_LEN, ManagementTokenRejection};
use crate::state::AppState;
use crate::{Error, Result};

pub(super) const PAGE_PATH: &str = "/webapp/management_tokens";
const API_PATH: &str = "/fgatbapi/management_tokens";
const API_TOKEN_PATH: &str = "/fgatbapi/management_tokens/{id}";

pub(super) fn router() -> Router<AppState> {
    Router::new()
        .route(PAGE_PATH, get(page))
        .route(API_PATH, post(create))
        .route(API_TOKEN_PATH, delete(remove))
}

/// The whole page.
#[derive(Template, WebTemplate)]
#[template(path = "management_tokens.html")]
struct ManagementTokensPage {
    issued: Option<IssuedView>,
    name: String,
    lifetime_options: Vec<LifetimeOption>,
    error: Option<String>,
    max_name_len: usize,
    tokens: Vec<TokenRow>,
}

/// The issued token, the form and the list, swapped in after a create attempt.
#[derive(Template, WebTemplate)]
#[template(path = "partials/management_tokens_section.html")]
struct ManagementTokensSection {
    issued: Option<IssuedView>,
    /// Name to keep in the form after a rejected attempt.
    name: String,
    lifetime_options: Vec<LifetimeOption>,
    error: Option<String>,
    max_name_len: usize,
    tokens: Vec<TokenRow>,
}

impl From<ManagementTokensSection> for ManagementTokensPage {
    fn from(section: ManagementTokensSection) -> Self {
        Self {
            issued: section.issued,
            name: section.name,
            lifetime_options: section.lifetime_options,
            error: section.error,
            max_name_len: section.max_name_len,
            tokens: section.tokens,
        }
    }
}

/// The list alone, swapped in after a removal.
#[derive(Template, WebTemplate)]
#[template(path = "partials/management_tokens_list.html")]
struct ManagementTokensList {
    tokens: Vec<TokenRow>,
}

/// A newly issued token, shown once.
struct IssuedView {
    name: String,
    token: String,
}

/// A token as shown in the list.
struct TokenRow {
    id: Uuid,
    name: String,
    created_at: String,
    expires_at: String,
    expired: bool,
}

impl TokenRow {
    fn new(token: ManagementTokenSummary, now: OffsetDateTime) -> Self {
        Self {
            id: token.id,
            name: token.name,
            created_at: utc_minutes(token.created_at),
            expires_at: utc_minutes(token.expires_at),
            expired: !(now < token.expires_at),
        }
    }
}

#[derive(Deserialize)]
struct CreateForm {
    name: String,
    expiry: String,
}

/// The form as typed, to render again.
struct FormView {
    name: String,
    expiry: String,
}

impl FormView {
    fn empty() -> Self {
        Self {
            name: String::new(),
            expiry: DEFAULT_TOKEN_LIFETIME_DAYS.to_string(),
        }
    }
}

async fn page(_auth: AuthSession, State(state): State<AppState>) -> Result<ManagementTokensPage> {
    Ok(section(&state, None, FormView::empty(), None).await?.into())
}

async fn create(_auth: AuthSession, State(state): State<AppState>, Form(form): Form<CreateForm>) -> Result<Response> {
    let typed = FormView {
        name: form.name,
        expiry: form.expiry,
    };

    let expires_at = match form_token_expiry(&typed.expiry, OffsetDateTime::now_utc()) {
        Ok(expires_at) => expires_at,
        Err(message) => return rejected(&state, typed, message).await,
    };

    match state.management_token_service.issue(&typed.name, expires_at).await {
        Ok(issued) => {
            let name = typed.name.trim().to_owned();
            info!(management_token_id = %issued.id, %name, %expires_at, "Management token issued");

            let issued = IssuedView {
                name,
                token: issued.token.as_ref().clone(),
            };
            Ok(section(&state, Some(issued), FormView::empty(), None)
                .await?
                .into_response())
        }
        Err(Error::InvalidManagementToken(rejection)) => {
            let message = match rejection {
                ManagementTokenRejection::EmptyName => "Enter a name for the token".to_owned(),
                ManagementTokenRejection::NameTooLong => {
                    format!("The name must be at most {MAX_MANAGEMENT_TOKEN_NAME_LEN} characters long")
                }
                ManagementTokenRejection::NameTaken => "A management token with this name already exists".to_owned(),
                ManagementTokenRejection::AlreadyExpired => "The expiration date must be in the future".to_owned(),
            };
            rejected(&state, typed, message).await
        }
        Err(error) => Err(error),
    }
}

/// Removes the token and returns the updated list.
///
/// Removing a token that no longer exists is not an error, so a repeated request still shows the current list.
async fn remove(
    _auth: AuthSession,
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
) -> Result<ManagementTokensList> {
    if state.management_token_service.remove(id).await? {
        info!(management_token_id = %id, "Management token removed");
    }

    Ok(ManagementTokensList {
        tokens: token_rows(&state).await?,
    })
}

async fn rejected(state: &AppState, form: FormView, message: String) -> Result<Response> {
    let section = section(state, None, form, Some(message)).await?;
    Ok((StatusCode::UNPROCESSABLE_ENTITY, section).into_response())
}

async fn section(
    state: &AppState,
    issued: Option<IssuedView>,
    form: FormView,
    error: Option<String>,
) -> Result<ManagementTokensSection> {
    Ok(ManagementTokensSection {
        issued,
        lifetime_options: lifetime_options(&form.expiry),
        name: form.name,
        error,
        max_name_len: MAX_MANAGEMENT_TOKEN_NAME_LEN,
        tokens: token_rows(state).await?,
    })
}

async fn token_rows(state: &AppState) -> Result<Vec<TokenRow>> {
    let now = OffsetDateTime::now_utc();
    let tokens = state.management_token_service.list().await?;
    Ok(tokens.into_iter().map(|token| TokenRow::new(token, now)).collect())
}

#[cfg(test)]
mod tests {
    use axum::body::Body;
    use axum::http::{Request, StatusCode};

    use crate::routes::testing::*;

    const MANAGEMENT_TOKENS: &str = "/fgatbapi/management_tokens";

    fn create_request(cookie: &str, fields: &[(&str, &str)]) -> Request<Body> {
        with_form(
            authenticated(Request::post(MANAGEMENT_TOKENS), cookie).header("hx-request", "true"),
            fields,
        )
    }

    /// Extracts the one-time token from the rendered section.
    fn issued_token(html: &str) -> &str {
        let start = html.find("fgatbm_").expect("the token is shown");
        let end = html[start..].find('"').unwrap();
        &html[start..start + end]
    }

    /// Whether the creation form is shown, and the button that opens it hidden.
    fn form_is_open(html: &str) -> bool {
        let tag = |start: &str| {
            let start = html.find(start).expect("the element is rendered");
            &html[start..start + html[start..].find('>').unwrap()]
        };
        // The `hidden` attribute comes last; scripts inside the tags mention `.hidden` too.
        let form_hidden = tag(r#"<form id="management-token-form""#)
            .trim_end()
            .ends_with(" hidden");
        let button_hidden = tag(r#"class="add-token""#).trim_end().ends_with("hidden");
        assert_ne!(
            form_hidden, button_hidden,
            "exactly one of the form and its button is shown"
        );
        !form_hidden
    }

    #[tokio::test]
    async fn page_requires_session() {
        let (app, _state) = setup().await;

        let response = send(&app, get("/webapp/management_tokens")).await;

        assert_eq!(response.status(), StatusCode::SEE_OTHER);
        assert_eq!(location(&response), "/webapp/login");
    }

    #[tokio::test]
    async fn create_shows_token_once_and_lists_it() {
        let (app, state, cookie) = setup_logged_in().await;

        let html = body_text(send(&app, with_cookie(Request::get("/webapp/management_tokens"), &cookie)).await).await;
        assert!(html.contains("<title>Management tokens"));
        assert!(html.contains(r#"<a href="/webapp/management_tokens">/management_tokens</a>"#));
        assert!(html.contains(">Add management token</button>"));
        assert!(!form_is_open(&html));
        assert!(html.contains(r#"<option value="30" selected>30 days</option>"#));
        assert!(html.contains("No tokens found"));

        let response = send(&app, create_request(&cookie, &[("name", " deploy "), ("expiry", "7")])).await;
        assert_eq!(response.status(), StatusCode::OK);
        let html = body_text(response).await;

        let token = issued_token(&html).to_owned();
        assert_eq!(html.matches(&token).count(), 1);
        assert!(html.contains("<td>deploy</td>"));
        assert!(!form_is_open(&html), "the form closes once the token is issued");

        let authenticated = state
            .management_token_service
            .authenticate(&token)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(authenticated.name, "deploy");
        let lifetime = authenticated.expires_at - authenticated.created_at;
        assert_eq!(lifetime.whole_days(), 7);

        // The token is never shown again.
        let page = body_text(send(&app, with_cookie(Request::get("/webapp/management_tokens"), &cookie)).await).await;
        assert!(!page.contains("fgatbm_"));
        assert!(page.contains("<td>deploy</td>"));
    }

    #[tokio::test]
    async fn create_rejects_invalid_input_and_keeps_it() {
        let (app, state, cookie) = setup_logged_in().await;
        state
            .management_token_service
            .issue("taken", time::OffsetDateTime::now_utc() + time::Duration::days(1))
            .await
            .unwrap();

        for (fields, message) in [
            ([("name", " "), ("expiry", "7")], "Enter a name for the token"),
            (
                [("name", "taken"), ("expiry", "7")],
                "A management token with this name already exists",
            ),
            ([("name", "ci"), ("expiry", "365")], "Choose when the token expires"),
        ] {
            let response = send(&app, create_request(&cookie, &fields)).await;
            assert_eq!(response.status(), StatusCode::UNPROCESSABLE_ENTITY, "{message}");
            let html = body_text(response).await;
            assert!(html.contains(message), "{message}: {html}");
            assert!(form_is_open(&html), "{message}: the form stays open to show the error");
            assert!(!html.contains("fgatbm_"));
        }

        let response = send(&app, create_request(&cookie, &[("name", "ci"), ("expiry", "365")])).await;
        assert!(body_text(response).await.contains(r#"name="name" value="ci""#));
        assert_eq!(state.management_token_service.list().await.unwrap().len(), 1);
    }

    #[tokio::test]
    async fn remove() {
        let (app, state, cookie) = setup_logged_in().await;
        send(&app, create_request(&cookie, &[("name", "ci"), ("expiry", "1")])).await;
        let id = state.management_token_service.list().await.unwrap()[0].id;

        let response = send(
            &app,
            authenticated(Request::delete(format!("{MANAGEMENT_TOKENS}/{id}")), &cookie)
                .header("hx-request", "true")
                .body(Body::empty())
                .unwrap(),
        )
        .await;

        assert_eq!(response.status(), StatusCode::OK);
        assert!(body_text(response).await.contains("No tokens found"));
        assert!(state.management_token_service.list().await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn api_requires_session() {
        let (app, state) = setup().await;

        let response = send(
            &app,
            with_form(
                Request::post(MANAGEMENT_TOKENS).header("hx-request", "true"),
                &[("name", "ci"), ("expiry", "7")],
            ),
        )
        .await;

        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        assert!(state.management_token_service.list().await.unwrap().is_empty());
    }
}
