use axum::extract::State;
use axum::http::StatusCode;
use tracing::warn;

use crate::app::AppState;

/// Reports whether the proxy can serve requests.
///
/// Returns `200 OK` when the database answers a trivial query, and `503 Service Unavailable` otherwise.
pub(crate) async fn health(State(state): State<AppState>) -> (StatusCode, &'static str) {
    match sqlx::query("SELECT 1").execute(&state.db).await {
        Ok(_) => (StatusCode::OK, "ok"),
        Err(error) => {
            warn!(%error, "Database health check failed");
            (StatusCode::SERVICE_UNAVAILABLE, "database unavailable")
        }
    }
}

#[cfg(test)]
mod tests {
    use axum::body::Body;
    use axum::http::{Request, StatusCode};
    use http_body_util::BodyExt as _;
    use sqlx::SqlitePool;
    use tower::ServiceExt as _;

    use crate::app::{AppState, router};

    async fn get_health(db: SqlitePool) -> (StatusCode, String) {
        let response = router(AppState { db })
            .oneshot(Request::get("/health").body(Body::empty()).unwrap())
            .await
            .unwrap();

        let status = response.status();
        let body = response.into_body().collect().await.unwrap().to_bytes();

        (status, String::from_utf8(body.to_vec()).unwrap())
    }

    #[tokio::test]
    async fn healthy_when_database_reachable() {
        let db = SqlitePool::connect("sqlite::memory:").await.unwrap();

        assert_eq!(get_health(db).await, (StatusCode::OK, "ok".to_owned()));
    }

    #[tokio::test]
    async fn unavailable_when_database_closed() {
        let db = SqlitePool::connect("sqlite::memory:").await.unwrap();
        db.close().await;

        assert_eq!(
            get_health(db).await,
            (
                StatusCode::SERVICE_UNAVAILABLE,
                "database unavailable".to_owned()
            )
        );
    }
}
