//! HTTP layer: thin handlers that translate requests into service calls.

mod auth;
mod health;
mod webapp;

use axum::Router;
use axum::routing::get;
use tower_http::trace::TraceLayer;

use crate::state::AppState;

/// Builds the HTTP router.
///
/// `/health` and the login page are reachable without a session.
/// Other admin panel pages require one through the [`auth::AuthSession`] extractor.
pub(crate) fn router(state: AppState) -> Router {
    Router::new()
        .route("/health", get(health::health))
        .merge(webapp::router())
        .layer(TraceLayer::new_for_http())
        .with_state(state)
}
