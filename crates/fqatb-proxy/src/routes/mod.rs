//! HTTP layer: thin handlers that translate requests into service calls.

mod access_tokens;
mod auth;
mod bitbucket_tokens;
mod health;
mod proxy;
#[cfg(test)]
mod testing;
mod webapp;

use axum::Router;
use axum::routing::get;
use time::{OffsetDateTime, UtcOffset};
use tower_http::trace::TraceLayer;

use crate::state::AppState;

/// Builds the HTTP router.
///
/// `/health`, the sign-up page and the login page are reachable without a session.
/// Other admin panel pages and the `/fgatbapi` API require one through the [`auth::AuthSession`] extractor.
/// Every other path is the Bitbucket-compatible API, which requires an access token.
pub(crate) fn router(state: AppState) -> Router {
    Router::new()
        .route("/health", get(health::health))
        .merge(webapp::router())
        .merge(bitbucket_tokens::router())
        .merge(access_tokens::router())
        .fallback(proxy::proxy)
        .layer(TraceLayer::new_for_http())
        .with_state(state)
}

/// Formats a timestamp in UTC to the minute, e.g. `2026-11-18 20:00`.
fn utc_minutes(at: OffsetDateTime) -> String {
    let at = at.to_offset(UtcOffset::UTC);

    format!(
        "{:04}-{:02}-{:02} {:02}:{:02}",
        at.year(),
        u8::from(at.month()),
        at.day(),
        at.hour(),
        at.minute()
    )
}
