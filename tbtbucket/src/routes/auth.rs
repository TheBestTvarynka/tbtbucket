//! Session cookie handling for the admin panel.

use axum::extract::FromRequestParts;
use axum::http::StatusCode;
use axum::http::request::Parts;
use axum::response::{IntoResponse as _, Redirect, Response};
use axum_extra::extract::CookieJar;
use axum_extra::extract::cookie::{Cookie, SameSite};
use uuid::Uuid;

use super::webapp::LOGIN_PATH;
use crate::db::Session;
use crate::services::SESSION_TTL;
use crate::state::AppState;

pub(super) const COOKIE_NAME: &str = "tbtbucket_session";

/// The session cookie is sent to the admin panel pages and to their API, which live under different prefixes.
///
/// Browsers therefore also send it along with requests meant for Bitbucket, so the proxy must strip it before forwarding.
const COOKIE_PATH: &str = "/";

/// Request header that htmx sets on every request it issues.
const HX_REQUEST: &str = "hx-request";

/// Response header that makes htmx navigate the whole page instead of swapping the response in.
const HX_REDIRECT: &str = "hx-redirect";

/// Builds the cookie that carries the session token.
pub(super) fn session_cookie(token: String) -> Cookie<'static> {
    Cookie::build((COOKIE_NAME, token))
        .path(COOKIE_PATH)
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
    Cookie::build(COOKIE_NAME).path(COOKIE_PATH).build()
}

/// An authenticated admin session.
///
/// Extracting it from a request that has no valid session redirects the browser to the login page.
/// For htmx requests the redirect is an `HX-Redirect` header, so that htmx loads the login page in place of the whole page rather than swapping it into a fragment.
pub(super) struct AuthSession {
    pub(super) id: Uuid,
    #[expect(dead_code, reason = "no handler reads session details yet")]
    pub(super) session: Session,
}

impl FromRequestParts<AppState> for AuthSession {
    type Rejection = Response;

    async fn from_request_parts(parts: &mut Parts, state: &AppState) -> Result<Self, Self::Rejection> {
        let jar = CookieJar::from_headers(&parts.headers);
        let is_htmx = parts.headers.get(HX_REQUEST).is_some_and(|value| value == "true");

        let Some(cookie) = jar.get(COOKIE_NAME) else {
            return Err(login_redirect(is_htmx));
        };

        match state.session_service.resolve(cookie.value()).await {
            Ok(Some((id, session))) => Ok(Self { id, session }),
            Ok(None) => Err((jar.remove(removal_cookie()), login_redirect(is_htmx)).into_response()),
            Err(error) => Err(error.into_response()),
        }
    }
}

fn login_redirect(is_htmx: bool) -> Response {
    if is_htmx {
        (StatusCode::UNAUTHORIZED, [(HX_REDIRECT, LOGIN_PATH)]).into_response()
    } else {
        Redirect::to(LOGIN_PATH).into_response()
    }
}
