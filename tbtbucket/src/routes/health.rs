use axum::extract::State;
use axum::http::StatusCode;
use tracing::warn;

use crate::error::report;
use crate::state::AppState;

/// Reports whether the proxy can serve requests.
///
/// Returns `200 OK` when the database answers a trivial query, and `503 Service Unavailable` otherwise.
pub(super) async fn health(State(state): State<AppState>) -> (StatusCode, &'static str) {
    match state.db.ping().await {
        Ok(()) => (StatusCode::OK, "ok"),
        Err(error) => {
            warn!(error = report(&error), "Database health check failed");
            (StatusCode::SERVICE_UNAVAILABLE, "database unavailable")
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use axum::body::Body;
    use axum::http::{Request, StatusCode};
    use http_body_util::BodyExt as _;
    use tower::ServiceExt as _;

    use crate::routes::router;
    use crate::state::{AppState, ServerState};

    async fn get_health(state: AppState) -> (StatusCode, String) {
        let response = router(state)
            .oneshot(Request::get("/health").body(Body::empty()).unwrap())
            .await
            .unwrap();

        let status = response.status();
        let body = response.into_body().collect().await.unwrap().to_bytes();

        (status, String::from_utf8(body.to_vec()).unwrap())
    }

    #[tokio::test]
    async fn healthy_when_database_reachable() {
        let state = Arc::new(ServerState::for_tests().await);

        assert_eq!(get_health(state).await, (StatusCode::OK, "ok".to_owned()));
    }

    #[tokio::test]
    async fn unavailable_when_database_closed() {
        let state = Arc::new(ServerState::for_tests().await);
        state.db.close().await;

        assert_eq!(
            get_health(state).await,
            (StatusCode::SERVICE_UNAVAILABLE, "database unavailable".to_owned())
        );
    }
}
