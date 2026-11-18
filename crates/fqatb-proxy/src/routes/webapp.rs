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
use crate::state::AppState;
use crate::{Error, Result};

/// Path prefix of every admin panel page.
///
/// Everything outside of it is left for proxied requests.
pub(super) const BASE_PATH: &str = "/webapp";
pub(super) const HOME_PATH: &str = "/webapp/";
pub(super) const LOGIN_PATH: &str = "/webapp/login";
const LOGOUT_PATH: &str = "/webapp/logout";

/// Routes of the admin panel.
///
/// The routes carry the full path rather than being nested under [`BASE_PATH`], because a nested `/` route does not match the trailing slash of [`HOME_PATH`].
pub(super) fn router() -> Router<AppState> {
    Router::new()
        .route(BASE_PATH, get(|| async { Redirect::permanent(HOME_PATH) }))
        .route(HOME_PATH, get(home))
        .route(LOGIN_PATH, get(login_page).post(login))
        .route(LOGOUT_PATH, post(logout))
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
struct LoginForm {
    password: Secret<String>,
}

async fn home(_session: AuthSession) -> HomePage {
    HomePage
}

async fn login_page() -> LoginPage {
    LoginPage { error: None }
}

async fn login(State(state): State<AppState>, jar: CookieJar, Form(form): Form<LoginForm>) -> Result<Response> {
    let admin_id = match state.admin_service.authenticate(form.password).await {
        Ok(admin_id) => admin_id,
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
    use std::sync::Arc;

    use axum::Router;
    use axum::body::Body;
    use axum::http::{Request, StatusCode, header};
    use axum::response::Response;
    use tower::ServiceExt as _;

    use crate::routes::auth::COOKIE_NAME;
    use crate::routes::router;
    use crate::state::{AppState, ServerState};

    const PASSWORD: &str = "correct horse battery staple";

    async fn setup() -> (Router, AppState) {
        let state = Arc::new(ServerState::for_tests(PASSWORD).await);
        (router(Arc::clone(&state)), state)
    }

    async fn send(app: &Router, request: Request<Body>) -> Response {
        app.clone().oneshot(request).await.unwrap()
    }

    fn get(uri: &str) -> Request<Body> {
        Request::get(uri).body(Body::empty()).unwrap()
    }

    fn login_request(password: &str) -> Request<Body> {
        Request::post("/webapp/login")
            .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
            .body(Body::from(format!("password={}", password.replace(' ', "+"))))
            .unwrap()
    }

    fn with_cookie(builder: axum::http::request::Builder, cookie: &str) -> Request<Body> {
        builder
            .header(header::COOKIE, format!("{COOKIE_NAME}={cookie}"))
            .body(Body::empty())
            .unwrap()
    }

    fn session_cookie(response: &Response) -> String {
        let set_cookie = response.headers().get(header::SET_COOKIE).unwrap().to_str().unwrap();

        assert!(set_cookie.contains("Path=/webapp"));
        assert!(set_cookie.contains("HttpOnly"));
        assert!(set_cookie.contains("Secure"));
        assert!(set_cookie.contains("SameSite=Strict"));

        set_cookie
            .strip_prefix(&format!("{COOKIE_NAME}="))
            .unwrap()
            .split(';')
            .next()
            .unwrap()
            .to_owned()
    }

    fn location(response: &Response) -> &str {
        response.headers().get(header::LOCATION).unwrap().to_str().unwrap()
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
    async fn pages_outside_prefix_are_not_served() {
        let (app, _state) = setup().await;

        for uri in ["/", "/login", "/logout"] {
            assert_eq!(send(&app, get(uri)).await.status(), StatusCode::NOT_FOUND);
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
}
