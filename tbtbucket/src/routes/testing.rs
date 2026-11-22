//! Helpers for driving the router in tests.

use std::sync::Arc;

use axum::Router;
use axum::body::Body;
use axum::http::request::Builder;
use axum::http::{Request, header};
use axum::response::Response;
use http_body_util::BodyExt as _;
use secret::Secret;
use tower::ServiceExt as _;

use super::auth::COOKIE_NAME;
use super::router;
use crate::state::{AppState, ServerState};

/// Admin password set up by [`setup`].
pub(super) const PASSWORD: &str = "s3cret!pass";

/// Builds an app whose admin is not initialized yet.
pub(super) async fn setup_uninitialized() -> (Router, AppState) {
    let state = Arc::new(ServerState::for_tests().await);
    (router(Arc::clone(&state)), state)
}

/// Builds an app whose admin password is [`PASSWORD`].
pub(super) async fn setup() -> (Router, AppState) {
    let (app, state) = setup_uninitialized().await;
    state
        .admin_service
        .init(Secret::new(PASSWORD.to_owned()))
        .await
        .unwrap();
    (app, state)
}

/// Builds an app with an initialized admin and returns a session cookie value for it.
pub(super) async fn setup_logged_in() -> (Router, AppState, String) {
    let (app, state) = setup().await;
    let cookie = session_cookie(&send(&app, login_request(PASSWORD)).await);
    (app, state, cookie)
}

pub(super) async fn send(app: &Router, request: Request<Body>) -> Response {
    app.clone().oneshot(request).await.unwrap()
}

pub(super) async fn body_text(response: Response) -> String {
    let bytes = response.into_body().collect().await.unwrap().to_bytes();
    String::from_utf8(bytes.to_vec()).unwrap()
}

pub(super) fn get(uri: &str) -> Request<Body> {
    Request::get(uri).body(Body::empty()).unwrap()
}

/// Encodes form fields as `application/x-www-form-urlencoded`.
pub(super) fn form_body(fields: &[(&str, &str)]) -> String {
    fields
        .iter()
        .map(|(key, value)| format!("{}={}", encode(key), encode(value)))
        .collect::<Vec<_>>()
        .join("&")
}

pub(super) fn form_request(uri: &str, fields: &[(&str, &str)]) -> Request<Body> {
    with_form(Request::post(uri), fields)
}

pub(super) fn with_form(builder: Builder, fields: &[(&str, &str)]) -> Request<Body> {
    builder
        .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
        .body(Body::from(form_body(fields)))
        .unwrap()
}

pub(super) fn login_request(password: &str) -> Request<Body> {
    form_request("/webapp/login", &[("password", password)])
}

/// Adds the session cookie to a request under construction.
pub(super) fn authenticated(builder: Builder, cookie: &str) -> Builder {
    builder.header(header::COOKIE, format!("{COOKIE_NAME}={cookie}"))
}

pub(super) fn with_cookie(builder: Builder, cookie: &str) -> Request<Body> {
    authenticated(builder, cookie).body(Body::empty()).unwrap()
}

/// Returns the session cookie value set by a successful login, after checking its attributes.
pub(super) fn session_cookie(response: &Response) -> String {
    let set_cookie = response.headers().get(header::SET_COOKIE).unwrap().to_str().unwrap();
    let mut attributes = set_cookie.split("; ");

    let value = attributes
        .next()
        .unwrap()
        .strip_prefix(&format!("{COOKIE_NAME}="))
        .unwrap()
        .to_owned();

    let attributes: Vec<_> = attributes.collect();
    for expected in ["Path=/", "HttpOnly", "Secure", "SameSite=Strict"] {
        assert!(attributes.contains(&expected), "{expected} missing from {set_cookie}");
    }

    value
}

pub(super) fn location(response: &Response) -> &str {
    response.headers().get(header::LOCATION).unwrap().to_str().unwrap()
}

/// Percent-encodes everything except unreserved characters.
fn encode(value: &str) -> String {
    value
        .bytes()
        .map(|byte| match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' => char::from(byte).to_string(),
            _ => format!("%{byte:02X}"),
        })
        .collect()
}
