//! Authenticate Axum requests with access tokens issued by Keycloak.
//!
//! [`KeycloakAuthInstance`](instance::KeycloakAuthInstance) fetches and caches a realm's OIDC
//! discovery document and JSON Web Key Set (JWKS). [`KeycloakAuthLayer`](layer::KeycloakAuthLayer)
//! extracts a bearer token, verifies it, applies a
//! [`ValidationPolicy`](validation::ValidationPolicy), and optionally enforces roles.
//!
//! # Example
//!
//! ```rust,no_run
//! use std::time::Duration;
//!
//! use axum::{Extension, Router, routing::get};
//! use axum_keycloak_auth::{
//!     PassthroughMode,
//!     instance::{KeycloakAuthInstance, KeycloakConfig, ServerUrl},
//!     layer::KeycloakAuthLayer,
//!     token::KeycloakToken,
//!     validation::{Algorithm, ValidationPolicy},
//! };
//!
//! async fn protected(Extension(token): Extension<KeycloakToken<String>>) -> String {
//!     format!("authenticated subject: {}", token.subject)
//! }
//!
//! #[tokio::main]
//! async fn main() -> Result<(), Box<dyn std::error::Error>> {
//!     let config = KeycloakConfig::builder()
//!         .server(ServerUrl::parse("https://keycloak.example/")?)
//!         .realm(String::from("my-realm"))
//!         .build();
//!     let policy = ValidationPolicy::strict()
//!         .expected_issuers([config.issuer()])
//!         .allowed_algorithms([Algorithm::RS256])
//!         .build()?;
//!     let http_client = reqwest::Client::builder()
//!         .connect_timeout(Duration::from_secs(10))
//!         .timeout(Duration::from_secs(30))
//!         .build()?;
//!     let instance = KeycloakAuthInstance::builder()
//!         .config(config)
//!         .http_client(http_client)
//!         .build();
//!
//!     let app: Router = Router::new().route("/protected", get(protected)).layer(
//!         KeycloakAuthLayer::<String>::builder()
//!             .instance(instance)
//!             .passthrough_mode(PassthroughMode::Block)
//!             .expected_audiences(vec!["my-api".to_owned()])
//!             .validation_policy(policy)
//!             .build(),
//!     );
//!     # let _ = app;
//!     Ok(())
//! }
//! ```
//!
//! The `reqwest::Client` used for discovery is yours to configure, including its timeouts, proxies,
//! and TLS backend. Build it with the same `reqwest` major version as this crate, which also
//! re-exports it as [`reqwest`].
//!
//! Token signatures are verified by `jsonwebtoken`, using the crypto backend selected through the
//! `aws-lc-rs` or `rust-crypto` feature. Neither is enabled by default, and the crate does not
//! compile without one. Enable exactly one of them. If both of `jsonwebtoken`'s backends end up
//! enabled in the dependency graph, `jsonwebtoken` cannot choose one and panics on every token
//! verification, unless the application installs a [`jsonwebtoken::crypto::CryptoProvider`] at
//! startup. This crate never installs a provider itself. It re-exports the `jsonwebtoken` version
//! it uses as [`jsonwebtoken`].
//!
//! Apply the layer only to protected routes. Share one `KeycloakAuthInstance` across layers so
//! they use one key cache and one refresh coordinator.
//!
//! # Authentication result
//!
//! [`PassthroughMode::Block`] is the default. It rejects failed authentication and inserts a
//! [`KeycloakToken`](token::KeycloakToken) extension after successful authentication.
//! [`PassthroughMode::Pass`] always calls the inner service and inserts a [`KeycloakAuthStatus`]
//! extension containing either the token or the authentication error.
//!
//! Use [`KeycloakAuthLayer::required_roles`](layer::KeycloakAuthLayer::required_roles) for roles
//! shared by every route under a layer. For per-handler checks, use the methods on
//! [`role::ExpectRoles`] or the role-checking macros. Use `String` for untyped role names, or
//! implement [`role::Role`] to parse them into an application-specific type.
//!
//! # Validation
//!
//! The default [`ValidationPolicy::legacy`](validation::ValidationPolicy::legacy) preset preserves
//! the acceptance rules of earlier releases. For new deployments,
//! [`ValidationPolicy::strict`](validation::ValidationPolicy::strict) requires issuer and audience
//! checks, restricts signature algorithms, requires a `Bearer` payload token type, and validates
//! `nbf` and future `iat` values. The documentation of both presets lists their exact behavior.
//!
//! [`KeycloakAuthLayer::validate_raw_token`](layer::KeycloakAuthLayer::validate_raw_token) applies
//! the same validation outside the middleware.
//!
//! # Token extraction
//!
//! By default, the layer reads `Authorization: Bearer <token>`. Configure
//! [`KeycloakAuthLayer::token_extractors`](layer::KeycloakAuthLayer::token_extractors) to use
//! multiple or custom [`TokenExtractor`](extract::TokenExtractor) implementations. A request must
//! carry its token in exactly one of their sources, as RFC 6750 requires. The [`extract`] module
//! describes how other requests are rejected.
//!
//! [`QueryParamTokenExtractor`](extract::QueryParamTokenExtractor) reads tokens from URLs, where
//! they can leak through browser history, referrer headers, and request logs.
//!
//! # Key discovery and refresh
//!
//! [`KeycloakAuthInstance::builder`](instance::KeycloakAuthInstance::builder) creates an instance
//! with your `reqwest::Client`, starts discovery in the background, and returns immediately.
//!
//! A background task owned by the instance refreshes the keys every four minutes by default,
//! independently of request traffic, so requests do not wait for routine refreshes. It also keeps
//! retrying a failed initial discovery. Validation additionally requests a shared, rate-limited
//! refresh when no usable keys are cached or when no cached key can verify a token with an unknown
//! `kid`.
//!
//! Keys expire once they are older than the maximum key age, five minutes by default, which only
//! happens while refreshes fail, for example because Keycloak is unreachable. By default, expired
//! keys are used for one more minute and then rejected, so that a key removed from Keycloak, for
//! example because it was compromised, stops verifying tokens at most six minutes after the last
//! successful refresh. While keys are rejected, requests fail with `503 Service Unavailable`, and
//! the instance reports itself as not operational. [`ExpiredKeys`](instance::ExpiredKeys) also
//! offers to keep using expired keys until Keycloak is reachable again, or to reject them right
//! away. Key ages are measured on both the monotonic and the wall clock, so time the system spent
//! suspended counts as well.
//!
//! One discovery, including its retries, is abandoned after one minute by default, so that a
//! Keycloak that stops answering cannot block later refreshes. The background task belongs to the
//! Tokio runtime that creates the instance, so create it on the runtime that serves requests.
//!
//! Configure these ages, the request retries, and how long requests wait for a refresh with a
//! [`DiscoveryConfig`](instance::DiscoveryConfig), passed to
//! [`KeycloakAuthInstanceBuilder::discovery_config`](instance::KeycloakAuthInstanceBuilder::discovery_config).
//!
//! # Readiness
//!
//! Requests fail with `503 Service Unavailable` while the instance has no usable keys, for example
//! while Keycloak is still starting. Report this through a readiness check, so that a
//! scheduler such as Kubernetes only routes traffic to the application once it can authenticate
//! requests:
//!
//! ```rust
//! use std::sync::Arc;
//!
//! use axum::{Router, extract::State, http::StatusCode, routing::get};
//! use axum_keycloak_auth::instance::KeycloakAuthInstance;
//!
//! async fn ready(State(instance): State<Arc<KeycloakAuthInstance>>) -> StatusCode {
//!     if instance.operational_status().is_operational {
//!         StatusCode::OK
//!     } else {
//!         StatusCode::SERVICE_UNAVAILABLE
//!     }
//! }
//!
//! fn readiness_router(instance: Arc<KeycloakAuthInstance>) -> Router {
//!     Router::new().route("/ready", get(ready)).with_state(instance)
//! }
//! ```
//!
//! Keep the readiness route outside the authentication layer, and share the same
//! `Arc<KeycloakAuthInstance>` with the layer. Once usable keys were discovered, the instance stays
//! operational even if a later refresh fails, until [`ExpiredKeys`](instance::ExpiredKeys) rejects
//! the expired keys. A Keycloak outage can therefore take every instance out of rotation within a
//! few minutes. The instance becomes operational again with the first successful refresh.
//!
//! Use this for readiness checks, not liveness checks. Restarting the application does not make
//! Keycloak reachable.
//!
//! [`OperationalStatus`](instance::OperationalStatus) also carries the latest discovery failure for
//! health reporting.
//!
//! As an advanced alternative, applications that must not run at all without Keycloak can await
//! [`KeycloakAuthInstance::wait_for_discovery`](instance::KeycloakAuthInstance::wait_for_discovery)
//! at startup and exit on its error.

#![forbid(unsafe_code)]
#![warn(missing_docs)]
#![deny(clippy::unwrap_used)]

#[cfg(not(any(feature = "aws-lc-rs", feature = "rust-crypto")))]
compile_error!(
    "axum-keycloak-auth needs a crypto backend to verify token signatures. Enable exactly one of its \
     `aws-lc-rs` or `rust-crypto` features. See the README section \"Crypto backend\"."
);

use std::sync::Arc;

use role::Role;

mod clock;
mod discovery;
pub mod error;
pub mod extract;
mod http;
pub mod instance;
pub mod layer;
mod logging;
mod oidc;
pub mod role;
mod server_url;
pub mod service;
pub mod token;
pub mod validation;

#[cfg(test)]
mod test_support;

/// URL type wrapped by [`instance::ServerUrl`].
pub use url::Url;

/// HTTP client library whose `Client` [`instance::KeycloakAuthInstance::builder`] requires.
///
/// Build the client through this re-export, or depend on the same `reqwest` major version
/// directly. A direct dependency is also how an application selects `reqwest` features, such as
/// its TLS backend.
pub use reqwest;

/// JWT library this crate verifies token signatures with.
///
/// Install a custom `CryptoProvider` through this re-export, as in
/// `axum_keycloak_auth::jsonwebtoken::crypto::CryptoProvider::install_default`, or through a direct
/// dependency on the same `jsonwebtoken` major version. A provider installed into another
/// `jsonwebtoken` version has no effect on this crate.
pub use jsonwebtoken;

/// Non-empty collection type used for configured token extractors.
pub use nonempty::NonEmpty;

/// Items used by this crate's exported macros. Not public API.
#[doc(hidden)]
pub mod __private {
    pub use axum::response::IntoResponse;
}

use serde::de::DeserializeOwned;

/// Controls whether failed authentication stops the request.
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum PassthroughMode {
    /// Reject failed authentication. On success, insert a
    /// [`token::KeycloakToken`] request extension and call the inner service.
    Block,

    /// Always call the inner service and insert a [`KeycloakAuthStatus`] request extension with
    /// the authentication result.
    Pass,
}

/// Authentication result inserted as a request extension in [`PassthroughMode::Pass`].
///
/// `R` and `Extra` must match the role and additional-claims types configured on the layer.
#[derive(Debug, Clone)]
#[allow(clippy::large_enum_variant)]
pub enum KeycloakAuthStatus<R, Extra>
where
    R: Role,
    Extra: DeserializeOwned + Clone,
{
    /// Authentication succeeded with the validated token.
    // Keep the common variant inline to avoid one allocation per authenticated request.
    Success(token::KeycloakToken<R, Extra>),

    /// Authentication failed with the detailed error.
    Failure(Arc<error::AuthError>),
}
