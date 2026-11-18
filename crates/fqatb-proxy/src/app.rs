use axum::Router;
use axum::routing::get;
use sqlx::SqlitePool;
use tower_http::trace::TraceLayer;

use crate::health;

/// State shared by all request handlers.
#[derive(Clone)]
pub(crate) struct AppState {
    pub(crate) db: SqlitePool,
}

/// Builds the HTTP router.
///
/// `/health` is intentionally unauthenticated so that load balancers and orchestrators can probe it.
pub(crate) fn router(state: AppState) -> Router {
    Router::new()
        .route("/health", get(health::health))
        .layer(TraceLayer::new_for_http())
        .with_state(state)
}
