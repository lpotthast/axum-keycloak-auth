//! Fixtures for driving the middleware: a ready-to-use offline layer, requests with and without
//! credentials, and response bodies.

use axum::{
    body::{Body, to_bytes},
    response::Response,
};
use http::{Request, header::AUTHORIZATION};
use serde_json::Value;

use crate::layer::KeycloakAuthLayer;

use super::{ManualClock, TEST_AUDIENCE, offline_instance};

/// A layer over [`offline_instance`], expecting [`TEST_AUDIENCE`] and validating at
/// [`super::validation_time`]. Every other setting has its default.
///
/// The layer's configuration fields are public, so tests adjust them directly before creating a
/// service:
///
/// ```ignore
/// let mut layer = offline_layer();
/// layer.passthrough_mode = PassthroughMode::Pass;
/// let service = KeycloakAuthService::new(inner, &layer);
/// ```
pub(crate) fn offline_layer() -> KeycloakAuthLayer<String, Value> {
    KeycloakAuthLayer::<String, Value>::builder()
        .instance(offline_instance())
        .expected_audiences(vec![String::from(TEST_AUDIENCE)])
        .build()
        .with_clock(ManualClock::at_validation_time())
}

/// A `GET /` request carrying `token` in an `Authorization: Bearer` header.
pub(crate) fn bearer_request(token: &str) -> Request<Body> {
    Request::builder()
        .header(AUTHORIZATION, format!("Bearer {token}"))
        .body(Body::empty())
        .expect("the bearer test request must build")
}

/// A `GET /` request without credentials.
pub(crate) fn anonymous_request() -> Request<Body> {
    Request::builder()
        .body(Body::empty())
        .expect("the anonymous test request must build")
}

/// The body of `response` as text. Bodies above 64 KiB are rejected, as no test expects one.
pub(crate) async fn response_text(response: Response) -> String {
    let body = to_bytes(response.into_body(), 64 * 1024)
        .await
        .expect("the response body must be readable");
    String::from_utf8(body.to_vec()).expect("the response body must be UTF-8")
}
