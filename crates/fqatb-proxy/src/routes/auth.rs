//! Session cookie handling for the admin panel.

use axum::extract::FromRequestParts;
use axum::http::request::Parts;
use axum::response::{IntoResponse as _, Redirect, Response};
use axum_extra::extract::CookieJar;
use axum_extra::extract::cookie::{Cookie, SameSite};
use uuid::Uuid;

use super::webapp::{BASE_PATH, LOGIN_PATH};
use crate::db::Session;
use crate::services::SESSION_TTL;
use crate::state::AppState;

pub(super) const COOKIE_NAME: &str = "fqatb_session";

/// Builds the cookie that carries the session token.
///
/// The cookie is scoped to the admin panel, so it is never sent along with proxied requests.
pub(super) fn session_cookie(token: String) -> Cookie<'static> {
    Cookie::build((COOKIE_NAME, token))
        .path(BASE_PATH)
        .http_only(true)
        .secure(true)
        .same_site(SameSite::Strict)
        .max_age(time::Duration::seconds(
            i64::try_from(SESSION_TTL.as_secs()).expect("TTL fits in i64"),
        ))
        .build()
}

/// Builds a cookie whose removal clears the session cookie.
pub(super) fn removal_cookie() -> Cookie<'static> {
    Cookie::build(COOKIE_NAME).path(BASE_PATH).build()
}

/// An authenticated admin session.
///
/// Extracting it from a request that has no valid session redirects the browser to the login page.
pub(super) struct AuthSession {
    pub(super) id: Uuid,
    #[expect(dead_code, reason = "no handler reads session details yet")]
    pub(super) session: Session,
}

impl FromRequestParts<AppState> for AuthSession {
    type Rejection = Response;

    async fn from_request_parts(parts: &mut Parts, state: &AppState) -> Result<Self, Self::Rejection> {
        let jar = CookieJar::from_headers(&parts.headers);

        let Some(cookie) = jar.get(COOKIE_NAME) else {
            return Err(Redirect::to(LOGIN_PATH).into_response());
        };

        match state.session_service.resolve(cookie.value()).await {
            Ok(Some((id, session))) => Ok(Self { id, session }),
            Ok(None) => Err((jar.remove(removal_cookie()), Redirect::to(LOGIN_PATH)).into_response()),
            Err(error) => Err(error.into_response()),
        }
    }
}
