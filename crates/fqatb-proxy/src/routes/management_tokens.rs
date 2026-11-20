//! Management tokens, the admin panel's home page.

use askama::Template;
use askama_web::WebTemplate;
use axum::Router;
use axum::routing::get;

use super::auth::AuthSession;
use crate::state::AppState;

pub(super) const PAGE_PATH: &str = "/webapp/management_tokens";

pub(super) fn router() -> Router<AppState> {
    Router::new().route(PAGE_PATH, get(page))
}

#[derive(Template, WebTemplate)]
#[template(path = "management_tokens.html")]
struct ManagementTokensPage;

async fn page(_auth: AuthSession) -> ManagementTokensPage {
    ManagementTokensPage
}

#[cfg(test)]
mod tests {
    use axum::http::{Request, StatusCode};

    use crate::routes::testing::*;

    #[tokio::test]
    async fn page_requires_session() {
        let (app, _state) = setup().await;

        let response = send(&app, get("/webapp/management_tokens")).await;

        assert_eq!(response.status(), StatusCode::SEE_OTHER);
        assert_eq!(location(&response), "/webapp/login");
    }

    #[tokio::test]
    async fn page_renders_with_the_header() {
        let (app, _state, cookie) = setup_logged_in().await;

        let response = send(&app, with_cookie(Request::get("/webapp/management_tokens"), &cookie)).await;

        assert_eq!(response.status(), StatusCode::OK);
        let html = body_text(response).await;
        assert!(html.contains("<title>Management tokens"));
        assert!(html.contains(r#"<a href="/webapp/management_tokens">/management_tokens</a>"#));
    }
}
