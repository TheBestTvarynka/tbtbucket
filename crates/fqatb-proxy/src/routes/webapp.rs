//! Admin panel pages, served under [`BASE_PATH`].

use askama::Template;
use askama_web::WebTemplate;
use axum::extract::State;
use axum::http::StatusCode;
use axum::response::{IntoResponse as _, Redirect, Response};
use axum::routing::{get, post};
use axum::{Form, Router};
use axum_extra::extract::CookieJar;
use secret::Secret;
use serde::Deserialize;
use tracing::{info, warn};

use super::auth::{AuthSession, removal_cookie, session_cookie};
use crate::services::{MIN_PASSWORD_LEN, PasswordRequirement};
use crate::state::AppState;
use crate::{Error, Result};

/// Path prefix of every admin panel page.
///
/// Everything outside of it is left for proxied requests.
pub(super) const BASE_PATH: &str = "/webapp";
pub(super) const HOME_PATH: &str = "/webapp/";
pub(super) const LOGIN_PATH: &str = "/webapp/login";
const LOGOUT_PATH: &str = "/webapp/logout";
const SIGNUP_PATH: &str = "/webapp/signup";

/// Routes of the admin panel.
///
/// The routes carry the full path rather than being nested under [`BASE_PATH`], because a nested `/` route does not match the trailing slash of [`HOME_PATH`].
pub(super) fn router() -> Router<AppState> {
    Router::new()
        .route(BASE_PATH, get(|| async { Redirect::permanent(HOME_PATH) }))
        .route(HOME_PATH, get(home))
        .route(SIGNUP_PATH, get(signup_page).post(signup))
        .route(LOGIN_PATH, get(login_page).post(login))
        .route(LOGOUT_PATH, post(logout))
}

#[derive(Template, WebTemplate)]
#[template(path = "signup.html")]
struct SignupPage {
    min_password_len: usize,
    error: Option<String>,
}

impl SignupPage {
    fn new(error: Option<String>) -> Self {
        Self {
            min_password_len: MIN_PASSWORD_LEN,
            error,
        }
    }
}

#[derive(Template, WebTemplate)]
#[template(path = "login.html")]
struct LoginPage {
    error: Option<&'static str>,
}

#[derive(Template, WebTemplate)]
#[template(path = "home.html")]
struct HomePage;

#[derive(Deserialize)]
struct SignupForm {
    password: Secret<String>,
    password_confirmation: Secret<String>,
}

#[derive(Deserialize)]
struct LoginForm {
    password: Secret<String>,
}

async fn home(_session: AuthSession) -> HomePage {
    HomePage
}

/// Shows the sign-up form until the admin is initialized, and redirects to the login page afterwards.
async fn signup_page(State(state): State<AppState>) -> Result<Response> {
    if state.admin_service.admin_id().await?.is_some() {
        return Ok(Redirect::to(LOGIN_PATH).into_response());
    }

    Ok(SignupPage::new(None).into_response())
}

/// Sets the admin password and sends the browser to the login page.
///
/// No session is issued here: the admin logs in with the new password like on any later visit.
async fn signup(State(state): State<AppState>, Form(form): Form<SignupForm>) -> Result<Response> {
    // Hashing is deliberately slow, so requests that cannot succeed are turned away before it.
    if state.admin_service.admin_id().await?.is_some() {
        return Ok(Redirect::to(LOGIN_PATH).into_response());
    }

    if form.password != form.password_confirmation {
        let page = SignupPage::new(Some("Passwords do not match".to_owned()));
        return Ok((StatusCode::UNPROCESSABLE_ENTITY, page).into_response());
    }

    match state.admin_service.init(form.password).await {
        Ok(admin_id) => {
            info!(%admin_id, "Admin signed up");
            Ok(Redirect::to(LOGIN_PATH).into_response())
        }
        Err(Error::WeakPassword(requirement)) => {
            let message = match requirement {
                PasswordRequirement::MinLength => {
                    format!("Password must be at least {MIN_PASSWORD_LEN} characters long")
                }
                PasswordRequirement::Digit => "Password must contain at least one digit".to_owned(),
                PasswordRequirement::SpecialCharacter => {
                    "Password must contain at least one special character, such as ! or #".to_owned()
                }
            };
            let page = SignupPage::new(Some(message));
            Ok((StatusCode::UNPROCESSABLE_ENTITY, page).into_response())
        }
        // Another sign-up won the race.
        Err(Error::AdminAlreadyInitialized) => Ok(Redirect::to(LOGIN_PATH).into_response()),
        Err(error) => Err(error),
    }
}

/// Shows the login form once the admin is initialized, and redirects to the sign-up page before that.
async fn login_page(State(state): State<AppState>) -> Result<Response> {
    if state.admin_service.admin_id().await?.is_none() {
        return Ok(Redirect::to(SIGNUP_PATH).into_response());
    }

    Ok(LoginPage { error: None }.into_response())
}

async fn login(State(state): State<AppState>, jar: CookieJar, Form(form): Form<LoginForm>) -> Result<Response> {
    let admin_id = match state.admin_service.authenticate(form.password).await {
        Ok(admin_id) => admin_id,
        Err(Error::AdminNotInitialized) => return Ok(Redirect::to(SIGNUP_PATH).into_response()),
        Err(Error::InvalidCredentials) => {
            warn!("Rejected admin login with invalid password");

            let page = LoginPage {
                error: Some("Invalid password"),
            };
            return Ok((StatusCode::UNAUTHORIZED, page).into_response());
        }
        Err(error) => return Err(error),
    };

    let session = state.session_service.create(admin_id).await?;

    info!(session_id = %session.id, "Admin logged in");

    Ok((jar.add(session_cookie(session.token)), Redirect::to(HOME_PATH)).into_response())
}

async fn logout(State(state): State<AppState>, auth: AuthSession, jar: CookieJar) -> Result<(CookieJar, Redirect)> {
    state.session_service.end(auth.id).await?;

    info!(session_id = %auth.id, "Admin logged out");

    Ok((jar.remove(removal_cookie()), Redirect::to(LOGIN_PATH)))
}

#[cfg(test)]
mod tests {
    use axum::body::Body;
    use axum::http::{Request, StatusCode, header};

    use crate::routes::testing::*;

    fn signup_request(password: &str, confirmation: &str) -> Request<Body> {
        form_request(
            "/webapp/signup",
            &[("password", password), ("password_confirmation", confirmation)],
        )
    }

    #[tokio::test]
    async fn base_path_redirects_to_home() {
        let (app, _state) = setup().await;

        let response = send(&app, get("/webapp")).await;

        assert_eq!(response.status(), StatusCode::PERMANENT_REDIRECT);
        assert_eq!(location(&response), "/webapp/");
    }

    #[tokio::test]
    async fn home_redirects_to_login_without_session() {
        let (app, _state) = setup().await;

        let response = send(&app, get("/webapp/")).await;

        assert_eq!(response.status(), StatusCode::SEE_OTHER);
        assert_eq!(location(&response), "/webapp/login");
    }

    #[tokio::test]
    async fn login_page_renders() {
        let (app, _state) = setup().await;

        let response = send(&app, get("/webapp/login")).await;

        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn paths_outside_prefix_belong_to_the_bitbucket_api() {
        let (app, _state) = setup().await;

        // Without an access token, the Bitbucket-compatible API answers instead of an admin page.
        for uri in ["/", "/login", "/logout"] {
            let response = send(&app, get(uri)).await;
            assert_eq!(response.status(), StatusCode::UNAUTHORIZED, "{uri}");
            assert!(body_text(response).await.contains(r#""errors""#), "{uri}");
        }
    }

    #[tokio::test]
    async fn wrong_password_is_rejected() {
        let (app, state) = setup().await;

        let response = send(&app, login_request("wrong password")).await;

        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        assert!(response.headers().get(header::SET_COOKIE).is_none());
        assert_eq!(state.db.session_count().await, 0);
    }

    #[tokio::test]
    async fn login_home_logout() {
        let (app, state) = setup().await;

        let response = send(&app, login_request(PASSWORD)).await;
        assert_eq!(response.status(), StatusCode::SEE_OTHER);
        assert_eq!(location(&response), "/webapp/");
        let cookie = session_cookie(&response);
        assert_eq!(state.db.session_count().await, 1);

        let response = send(&app, with_cookie(Request::get("/webapp/"), &cookie)).await;
        assert_eq!(response.status(), StatusCode::OK);
        let home = body_text(response).await;
        assert!(home.contains(r#"<a href="/webapp/bitbucket_tokens">/bitbucket_tokens</a>"#));
        assert!(home.contains(r#"action="/webapp/logout""#));

        let response = send(&app, with_cookie(Request::post("/webapp/logout"), &cookie)).await;
        assert_eq!(response.status(), StatusCode::SEE_OTHER);
        assert_eq!(location(&response), "/webapp/login");
        assert_eq!(state.db.session_count().await, 0);

        let response = send(&app, with_cookie(Request::get("/webapp/"), &cookie)).await;
        assert_eq!(response.status(), StatusCode::SEE_OTHER);
        assert_eq!(location(&response), "/webapp/login");
    }

    #[tokio::test]
    async fn forged_cookie_is_rejected() {
        let (app, _state) = setup().await;

        let response = send(&app, with_cookie(Request::get("/webapp/"), "AAAA")).await;

        assert_eq!(response.status(), StatusCode::SEE_OTHER);
        assert_eq!(location(&response), "/webapp/login");
    }

    #[tokio::test]
    async fn uninitialized_admin_is_sent_to_signup() {
        let (app, _state) = setup_uninitialized().await;

        let response = send(&app, get("/webapp/login")).await;
        assert_eq!(response.status(), StatusCode::SEE_OTHER);
        assert_eq!(location(&response), "/webapp/signup");

        let response = send(&app, login_request(PASSWORD)).await;
        assert_eq!(response.status(), StatusCode::SEE_OTHER);
        assert_eq!(location(&response), "/webapp/signup");

        assert_eq!(send(&app, get("/webapp/signup")).await.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn signup_rejects_invalid_passwords() {
        let (app, state) = setup_uninitialized().await;

        let mismatch = send(&app, signup_request(PASSWORD, "0ther!pass")).await;
        assert_eq!(mismatch.status(), StatusCode::UNPROCESSABLE_ENTITY);

        for weak in ["ab1!", "nodigits!", "nospecial1"] {
            let response = send(&app, signup_request(weak, weak)).await;
            assert_eq!(response.status(), StatusCode::UNPROCESSABLE_ENTITY, "{weak}");
        }

        assert!(state.admin_service.admin_id().await.unwrap().is_none());
    }

    #[tokio::test]
    async fn signup_then_login() {
        let (app, state) = setup_uninitialized().await;

        let response = send(&app, signup_request(PASSWORD, PASSWORD)).await;
        assert_eq!(response.status(), StatusCode::SEE_OTHER);
        assert_eq!(location(&response), "/webapp/login");
        assert!(response.headers().get(header::SET_COOKIE).is_none());
        assert_eq!(state.db.session_count().await, 0);

        let response = send(&app, login_request(PASSWORD)).await;
        assert_eq!(response.status(), StatusCode::SEE_OTHER);
        let cookie = session_cookie(&response);

        let response = send(&app, with_cookie(Request::get("/webapp/"), &cookie)).await;
        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn signup_closed_once_initialized() {
        let (app, state) = setup().await;
        let admin_id = state.admin_service.admin_id().await.unwrap();

        let response = send(&app, get("/webapp/signup")).await;
        assert_eq!(response.status(), StatusCode::SEE_OTHER);
        assert_eq!(location(&response), "/webapp/login");

        let other = "0ther!pass";
        let response = send(&app, signup_request(other, other)).await;
        assert_eq!(response.status(), StatusCode::SEE_OTHER);
        assert_eq!(location(&response), "/webapp/login");

        assert_eq!(state.admin_service.admin_id().await.unwrap(), admin_id);
        assert_eq!(
            send(&app, login_request(other)).await.status(),
            StatusCode::UNAUTHORIZED
        );
    }
}
