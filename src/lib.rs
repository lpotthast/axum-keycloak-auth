//! Protect axum routes with a JWT emitted by Keycloak.
//!
//! # Usage
//!
//! This library provides the `KeycloakAuthInstance` which manages OIDC discovery and hold onto decoding keys
//! and the `KeycloakAuthLayer`, a tower layer / service implementation that parses and validates incoming JWTs.
//!
//! Let's set up a protected Axum route!
//!
//! To demonstrate the likely case of still requiring some (e.g. /health) public routes,
//! let us define two functions to create the respective public and protected routers,
//! adding a `KeycloakAuthLayer` only to the router whose routes should be protected.
//!
//! Specifying the `required_roles` is optional. If omitted, role-presence can be checked in each route-handler individually.
//! The library will then only check that a request was performed with a valid JWT.
//! Consider using this builder field if you have a long list of route-handlers
//! which all require the same roles to be present.
//!
//! ```rust
//! use std::sync::Arc;
//! use axum::{http::StatusCode, response::{Response, IntoResponse}, routing::get, Extension, Router};
//! use axum_keycloak_auth::{Url, error::AuthError, instance::KeycloakConfig, instance::KeycloakAuthInstance, layer::KeycloakAuthLayer, decode::KeycloakToken, PassthroughMode, expect_role};
//!
//! pub fn public_router() -> Router {
//!     Router::new()
//!         .route("/health", get(health))
//! }
//!
//! pub fn protected_router(instance: KeycloakAuthInstance) -> Router {
//!     Router::new()
//!         .route("/protected", get(protected))
//!         .layer(
//!              KeycloakAuthLayer::<String>::builder()
//!                  .instance(instance)
//!                  .passthrough_mode(PassthroughMode::Block)
//!                  .persist_raw_claims(false)
//!                  .expected_audiences(vec![String::from("account")])
//!                  .required_roles(vec![String::from("administrator")])
//!                  .build(),
//!         )
//! }
//!
//! // You may have multiple routers that you want to see protected by a `KeycloakAuthLayer`.
//! // You can safely attach new `KeycloakAuthLayer`s to different routers, but consider using only a single `KeycloakAuthInstance` for all of these layers.
//! // Remember: The `KeycloakAuthInstance` manages the keys used to decode incoming JWTs and dynamically fetches them from your Keycloak server.
//! // Having multiple instances simoultaniously would incease pressure on your Keycloak instance on service startup and unnecesssarily store duplicated data.
//! // The `KeycloakAuthLayer` therefore really takes an `Arc<KeycloakAuthInstance>` in its `instance` method!
//! // Presence of the `Into` trait in the `instance` methods argument let us hide that fact in the previous example.
//!
//! #[allow(dead_code)]
//! pub fn protect(router:Router, instance: Arc<KeycloakAuthInstance>) -> Router {
//!     router.layer(
//!         KeycloakAuthLayer::<String>::builder()
//!             .instance(instance)
//!             .passthrough_mode(PassthroughMode::Block)
//!             .persist_raw_claims(false)
//!             .expected_audiences(vec![String::from("account")])
//!             .required_roles(vec![String::from("administrator")])
//!             .build(),
//!     )
//! }
//!
//! // Lets also define the handlers ('health' and 'protected') defined in our routers.
//!
//! // The `health` handler can always be called without a JWT,
//! // as we only attached an instance of the `KeycloakAuthLayer` to the protected router.
//!
//! // The `KeycloakAuthLayer` makes the parsed token data available using axum's `Extension`'s,
//! // including the users roles, the uuid of the user, its name, email, ...
//! // The `protected` handler will (in the default `PassthroughMode::Block` case) only be called
//! // if the request contained a valid JWT which not already expired.
//! // It may then access that data (as `KeycloakToken<YourRoleType>`) through an Extension
//! // to get access to the decoded keycloak user information as shown below.
//!
//! pub async fn health() -> impl IntoResponse {
//!     StatusCode::OK
//! }
//!
//! pub async fn protected(Extension(token): Extension<KeycloakToken<String>>) -> Response {
//!     expect_role!(&token, "administrator");
//!
//!     tracing::info!("Token payload is {token:#?}");
//!
//!     (
//!         StatusCode::OK,
//!         format!(
//!             "Hello {name} ({subject}). Your token is valid for another {valid_for} seconds.",
//!             name = token.extra.profile.preferred_username,
//!             subject = token.subject,
//!             valid_for = (token.expires_at - time::OffsetDateTime::now_utc()).whole_seconds()
//!         ),
//!     ).into_response()
//! }
//!
//! // You can construct a `KeycloakAuthInstance` using a single value of type `KeycloakConfig`, which is constructed using the builder pattern.
//! // You may want to immediately wrap it inside an `Arc` if you intend to pass it to multiple `KeycloakAuthLayer`s. We are not doing this in this example.
//!
//! // Your final router can be created by merging the public and protected routers.
//!
//! #[tokio::main]
//! async fn main() {
//!     let keycloak_auth_instance = KeycloakAuthInstance::new(
//!         KeycloakConfig::builder()
//!             .server(Url::parse("https://localhost:8443/").unwrap())
//!             .realm(String::from("MyRealm"))
//!             .build(),
//!     );
//!     let router = public_router().merge(protected_router(keycloak_auth_instance));
//!
//!     // let addr_and_port = String::from("0.0.0.0:8080");
//!     // let socket_addr: std::net::SocketAddr = addr_and_port.parse().unwrap();
//!     // println!("Listening on: {}", addr_and_port);
//!
//!     // let tcp_listener = tokio::net::TcpListener::bind(socket_addr).await.unwrap();
//!     // axum::serve(tcp_listener, router.into_make_service()).await.unwrap();
//! }
//! ```
//!
//! # Using a custom role type
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
//! # Passthrough modes
//!
//! The `KeycloakAuthLayer` provides a `passthrough_mode` field, allowing you to choose between the following modes:
//!
//! - `PassthroughMode::Block`: Immediately return an error-response should authentication fail. This is the preferred mode and the default if omitted.
//! - `PassthroughMode::Pass`: Always store a `KeycloakAuthStatus` containing the authentication result and defer the response generation to the handler or any deeper layers. You may want to use this mode i fine-grained error handling is required or you want to use additional layers which could still prove the user authenticated.
//!
//! # Using custom token extractors
//!
//! By default, request headers are checked for presence of an "authorization" header,
//! which is expected to contain the typical "`Bearer <token>`" string.
//!
//! You have the ability to change this behavior to your liking through use of the `TokenExtractor` trait,
//! which allows for customized strategies on how to retrieve the token from an axum request.
//!
//! The `token_extractors` field on the `KeycloakAuthLayer` builder accepts a non-empty vec of extractors.
//!
//! ```rust,no_run
//! use std::sync::Arc;
//! use axum_keycloak_auth::{
//!     NonEmpty, PassthroughMode,
//!     instance::KeycloakAuthInstance,
//!     layer::KeycloakAuthLayer,
//!     extract::{AuthHeaderTokenExtractor, QueryParamTokenExtractor, TokenExtractor}
//! };
//!
//! let instance: KeycloakAuthInstance = todo!();
//!
//! let layer = KeycloakAuthLayer::<String>::builder()
//!     .instance(instance)
//!     .passthrough_mode(PassthroughMode::Block)
//!     .expected_audiences(vec![String::from("account")])
//!     // ...
//!     .token_extractors(NonEmpty::<Arc<dyn TokenExtractor>> {
//!         head: Arc::new(AuthHeaderTokenExtractor::default()),
//!         tail: vec![
//!             Arc::new(QueryParamTokenExtractor::default()),
//!             Arc::new(QueryParamTokenExtractor::extracting_key("jwt")),
//!         ],
//!     })
//!     .build();
//! ```
//!
//! Extractors are called in order of their definition in the `token_extractors` vec.
//! The token from the first extractor able to successfully extract one is used to further validate the request.
//! Other extractors are no longer considered.
//!
//! This crate implements two extraction strategies:
//!   - `AuthHeaderTokenExtractor`: Extracts the token from the `http::header::AUTHORIZATION` header.
//!   - `QueryParamTokenExtractor`: Extracts the token from a query parameter (by default named "token"). Use with caution!
//!
//! By default, when not explicitly setting `token_extractors`, a single `AuthHeaderTokenExtractor::default()` is used.
//!

#![forbid(unsafe_code)]
//#![warn(missing_docs)]
#![deny(clippy::unwrap_used)]

use std::sync::Arc;

use role::Role;

mod action;
pub mod decode;
pub mod error;
pub mod extract;
pub mod instance;
pub mod layer;
pub mod oidc;
pub mod oidc_discovery;
pub mod role;
pub mod service;

// Re-export the Url struct used when configuring a `KeycloakAuthInstance`.
pub use url::Url;

// Re-export the NonEmpty struct used when configuring a `KeycloakAuthLayer`.
pub use nonempty::NonEmpty;

use serde::de::DeserializeOwned;

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
pub enum KeycloakAuthStatus<R, Extra>
where
    R: Role,
    Extra: DeserializeOwned + Clone,
{
    // This variant is fairly large, but probably used most of the time. Leaving this non-boxed results in one less allocation each request.
    Success(decode::KeycloakToken<R, Extra>),
    Failure(Arc<error::AuthError>),
}
