//! # axum-keycloak-auth
//!
//! Protect axum routes with a JWT emitted by Keycloak.
//!
//! Note: This is still in an early stage and not security-audited.
//!
//! ## Usage
//!
//! This library provides `KeycloakAuthLayer`, a tower layer / service implementation that parses and validates a JWT.
//!
//! To demonstrate the likely case of still requiring some (e.g. /health) public routes,
//! let us define two functions to create the respective routers,
//! adding a `KeycloakAuthLayer` only to the router whose routes should be protected.
//!
//! Note that specifying `required_roles` is optional. Remember that, if omitted,
//! role-presence should/must be checked in each route-handler.
//! The library will generally only check that any given request was performed with a valid JWT.
//! Consider using this builder field if you have a long list of route-handlers
//! which all require the same roles to be present.
//!
//! ```rust
//! use std::sync::Arc;
//! use axum::{http::StatusCode, response::{Response, IntoResponse}, routing::get, Extension, Router};
//! use axum_keycloak_auth::{error::AuthError, service::KeycloakAuthLayer, decode::KeycloakToken, PassthroughMode, expect_role};
//! use jsonwebtoken::DecodingKey;
//!
//! pub fn public_router() -> Router {
//!     Router::new()
//!         .route("/health", get(health))
//! }
//! pub fn protected_router(decoding_key: Arc<DecodingKey>) -> Router {
//!     Router::new()
//!         .route("/protected", get(protected))
//!         .layer(
//!              KeycloakAuthLayer::<String>::builder()
//!                  .decoding_key(decoding_key)
//!                  .passthrough_mode(PassthroughMode::Block)
//!                  .persist_raw_claims(false)
//!                  .expected_audiences(vec![String::from("account")])
//!                  .required_roles(vec![String::from("administrator")])
//!                  .build(),
//!         )
//! }
//!
//! // Lets also define the handlers defined in our routers.
//! //
//! // The `health` handler can always be called without a JWT,
//! // as we only attached an instance of the `KeycloakAuthLayer` to the protected router.
//! //
//! // The `KeycloakAuthLayer` makes the parsed token data available using axum's `Extension`'s.
//! // including the users roles, the uuid of the user, its name, email, ...
//! // The `protected` handler will (in the default `PassthroughMode::Block` case) only be called
//! // if the request contained a valid JWT which not already expired.
//! // The `protected` handler may then access that data to get access to the decoded keycloak user information,
//!
//! pub async fn health() -> impl IntoResponse {
//!     StatusCode::OK
//! }
//!
//! pub async fn protected(Extension(token): Extension<KeycloakToken<String>>) -> Response {
//!     expect_role!(&token, "administrator");
//!
//!     tracing::info!("Token payload is {token:#?}");
//!     (
//!         StatusCode::OK,
//!         format!(
//!             "Hello {name} ({subject}). Your token is valid for another {valid_for} seconds.",
//!             name = token.full_name,
//!             subject = token.subject,
//!             valid_for = (token.expires_at - time::OffsetDateTime::now_utc()).whole_seconds()
//!         ),
//!     ).into_response()
//! }
//!
//! // The `KeycloakAuthLayer` requires a `jsonwebtoken::DecodingKey` in order to be able to decode a given JWT.
//! // Lets define a helper functions to create one. Note: The const key is there for brevity.
//! // You should probably read this from an environment variable or construct the DecodingKey in an entirely different way.
//!
//! fn create_decoding_key() -> Result<DecodingKey, AuthError> {
//!     const KC_REALM_PUBLIC_KEY: &str = r#"
//!     -----BEGIN PUBLIC KEY-----
//!     MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAv1+Qqa8AgodwBjYQzX0mvY4l9XUQzxNgg5wOutcnRZNNiMjdA8wsP33pYj7hY07xaI4ff3Oc7XMXqKkSXF0+xDEYC2hRuqknfpZzkbH5hvGn3t970zIlguqWUy/zWyy+xT/Wn1m2eWgtjGB2PO4Z1xnT3p26h1tbOoi8Yr8pecGQH2GyFsrXQI5QzXk4XVMdMWIe1xIVzEmZnnizPt0+ACv7J3Z3bMpUFb7m3qxM5uA/hg3LWbozVxj61+T2L5JQXxKzJFTfzBV1M73cLFmTwrEPzyTZNSZj6ug/9q2v+S4laRQA7InxbFAvXJU5oKIqW9qTGLpYDEV/XayhA+ESZwIDAQAB
//!     -----END PUBLIC KEY-----
//!     "#;
//!
//!     DecodingKey::from_rsa_pem(KC_REALM_PUBLIC_KEY.as_bytes())
//!         .map_err(|err| AuthError::CreateDecodingKey { source: err })
//! }
//!
//! // Your final router can be created by merging the public and protected routes.
//!
//! // Most likely async using #[tokio::main].
//! fn main() {
//!     // [...]
//!     let decoding_key = Arc::new(create_decoding_key().expect("Public key from which a DecodingKey can be constructed"));
//!     let router = public_router().merge(protected_router(decoding_key));
//!     // [...]
//! }
//! ```
//!
//! ## Using a custom role type
//!
//! You probably noticed a generic `<String>` when creating the `KeycloakAuthLayer` and defining the handler extension.
//!
//! This is the type representing a single role and can be replaced with any type implementing the `axum_keycloak_auth::role::Role` trait.
//!
//! You could for example create an enum containing all your known roles as variants with a special variant for unknown role names.
//!
//! ```rust
//! #[derive(Debug, PartialEq, Eq, Clone)]
//! pub enum Role {
//!     Administrator,
//!     Unknown(String),
//! }
//!
//! impl axum_keycloak_auth::role::Role for Role {}
//!
//! impl std::fmt::Display for Role {
//!     fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
//!         match self {
//!             Role::Administrator => f.write_str("Administrator"),
//!             Role::Unknown(unknown) => f.write_fmt(format_args!("Unknown role: {unknown}")),
//!         }
//!     }
//! }
//!
//! impl From<String> for Role {
//!     fn from(value: String) -> Self {
//!         match value.as_ref() {
//!             "administrator" => Role::Administrator,
//!             _ => Role::Unknown(value),
//!         }
//!     }
//! }
//!
//! // You could then (remember to update both locations of the generic type) check for roles using your enum:
//!
//! use axum::{http::StatusCode, response::{Response, IntoResponse}, Extension};
//! use axum_keycloak_auth::{decode::KeycloakToken, expect_role};
//!
//! pub async fn protected(Extension(token): Extension<KeycloakToken<Role>>) -> Response {
//!     expect_role!(&token, Role::Administrator);
//!     StatusCode::OK.into_response()
//! }
//! ```
//!
//! ## Passthrough modes
//!
//! The `KeycloakAuthLayer` provides a `passthrough_mode` field, allowing you to choose between the following modes:
//!
//! - `PassthroughMode::Block`: Immediately return an error-response should authentication fail. This is the preferred mode and the default if omitted.
//! - `PassthroughMode::Pass`: Always store a `KeycloakAuthStatus` containing the authentication result and defer the response generation to the handler or any deeper layers. You may want to use this mode i fine-grained error handling is required or you want to use additional layers which could still prove the user authenticated.
//!

#![forbid(unsafe_code)]
//#![warn(missing_docs)]
#![deny(clippy::unwrap_used)]

use std::sync::Arc;

use role::Role;

pub mod decode;
pub mod error;
pub mod layer;
pub mod middleware;
pub mod oidc;
pub mod oidc_discovery;
pub mod role;
pub mod service;

/// The mode in which the authentication middleware may operate in.
///
/// ```PassthroughMode::Block```: Immediately return a `Response` if authentication failed.
/// On successful authentication, the parsed token content is stored as an axum extension as a `KeycloakToken`.
///
/// ```PassthroughMode::Pass```:  Forward to the response handler regardless of whether there was an authentication failure.
/// In this mode, the authentication status is stored as an axum extension as a `KeycloakAuthStatus`.
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum PassthroughMode {
    Block,
    Pass,
}

#[derive(Debug, Clone)]
#[allow(clippy::large_enum_variant)]
pub enum KeycloakAuthStatus<R: Role> {
    // This variant is fairly large, but probably used most of the time. Leaving this non-boxed results in one less allocation each request.
    Success(decode::KeycloakToken<R>),
    Failure(Arc<error::AuthError>),
}
