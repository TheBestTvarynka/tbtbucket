//! HTTP layer: thin handlers that translate requests into service calls.

mod auth;
mod bitbucket_tokens;
mod health;
#[cfg(test)]
mod testing;
mod webapp;

use axum::Router;
use axum::routing::get;
use tower_http::trace::TraceLayer;

use crate::state::AppState;

/// Builds the HTTP router.
///
/// `/health`, the sign-up page and the login page are reachable without a session.
/// Other admin panel pages and the `/fgatbapi` API require one through the [`auth::AuthSession`] extractor.
pub(crate) fn router(state: AppState) -> Router {
    Router::new()
        .route("/health", get(health::health))
        .merge(webapp::router())
        .merge(bitbucket_tokens::router())
        .layer(TraceLayer::new_for_http())
        .with_state(state)
}
