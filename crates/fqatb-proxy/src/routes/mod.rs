//! HTTP layer: thin handlers that translate requests into service calls.

mod access_tokens;
mod auth;
mod bitbucket_tokens;
mod health;
mod management_api;
mod management_tokens;
mod proxy;
#[cfg(test)]
mod testing;
mod webapp;

use axum::Router;
use axum::http::StatusCode;
use axum::response::{IntoResponse as _, Response};
use axum::routing::get;
use serde_json::json;
use time::{OffsetDateTime, UtcOffset};
use tower_http::trace::TraceLayer;

use crate::services::{TOKEN_LIFETIMES_DAYS, lifetime_label, token_expiry};
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
        .merge(management_tokens::router())
        .merge(management_api::router())
        .fallback(proxy::proxy)
        .layer(TraceLayer::new_for_http())
        .with_state(state)
}

/// An error in the JSON format Bitbucket uses, `{"errors": [{"message": …}]}`.
///
/// The proxy answers in it so that clients report the error like any other Bitbucket error, and the management API
/// uses it too, so that one client can read both.
fn json_error(status: StatusCode, message: &str) -> Response {
    let body = json!({ "errors": [{ "context": null, "message": message, "exceptionName": null }] });
    (status, axum::Json(body)).into_response()
}

/// A lifetime offered in a token form.
struct LifetimeOption {
    days: u16,
    label: String,
    selected: bool,
}

/// The lifetimes offered in a token form, with `selected` (the form field's value) preselected.
fn lifetime_options(selected: &str) -> Vec<LifetimeOption> {
    TOKEN_LIFETIMES_DAYS
        .iter()
        .map(|&days| LifetimeOption {
            days,
            label: lifetime_label(days),
            selected: selected == days.to_string(),
        })
        .collect()
}

/// Turns a token form's lifetime field into the expiration time, with a message for the form if it is not offered.
fn form_token_expiry(value: &str, now: OffsetDateTime) -> Result<OffsetDateTime, String> {
    value
        .parse()
        .ok()
        .and_then(|days| token_expiry(days, now))
        .ok_or_else(|| "Choose when the token expires".to_owned())
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
