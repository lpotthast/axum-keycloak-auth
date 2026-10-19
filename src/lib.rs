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
//! use axum::{Extension, Router, routing::get};
//! use axum_keycloak_auth::{
//!     PassthroughMode, Url,
//!     instance::{KeycloakAuthInstance, KeycloakConfig},
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
//!     let server = Url::parse("https://keycloak.example/")?;
//!     let realm = "my-realm";
//!     let instance = KeycloakAuthInstance::connect(
//!         KeycloakConfig::builder()
//!             .server(server.clone())
//!             .realm(realm.to_owned())
//!             .build(),
//!     )
//!     .await?;
//!     let policy = ValidationPolicy::strict()
//!         .expected_issuers(vec![format!("{server}realms/{realm}")])
//!         .allowed_algorithms(vec![Algorithm::RS256])
//!         .build()?;
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
//! the validation behavior of earlier releases. For new deployments,
//! [`ValidationPolicy::strict`](validation::ValidationPolicy::strict) requires issuer and audience
//! checks, restricts signature algorithms, requires a `Bearer` payload token type, and validates
//! `nbf` and future `iat` values. See [`validation`] for the exact preset behavior.
//!
//! [`KeycloakAuthLayer::validate_raw_token`](layer::KeycloakAuthLayer::validate_raw_token) applies
//! the same validation outside the middleware.
//!
//! # Token extraction
//!
//! By default, the layer reads `Authorization: Bearer <token>`. Configure
//! [`KeycloakAuthLayer::token_extractors`](layer::KeycloakAuthLayer::token_extractors) to use
//! multiple or custom [`TokenExtractor`](extract::TokenExtractor) implementations. Extractors run
//! in order, and the first token found is validated. An absent credential source always falls
//! through. The default
//! [`TokenExtractionErrorPolicy::Fallback`](extract::TokenExtractionErrorPolicy::Fallback) also
//! ignores unusable sources for compatibility, while
//! [`TokenExtractionErrorPolicy::Reject`](extract::TokenExtractionErrorPolicy::Reject) rejects the
//! first unusable source.
//!
//! [`QueryParamTokenExtractor`](extract::QueryParamTokenExtractor) reads tokens from URLs, where
//! they can leak through browser history, referrer headers, and request logs.
//!
//! # Key discovery and refresh
//!
//! [`KeycloakAuthInstance::connect`](instance::KeycloakAuthInstance::connect) waits for initial
//! discovery and returns an error if it fails.
//! [`KeycloakAuthInstance::new`](instance::KeycloakAuthInstance::new) starts discovery in the
//! background instead.
//!
//! Validation may request an on-demand refresh when no usable keys are cached or when no cached
//! key can verify a token with an unknown `kid`. Refreshes are shared and rate-limited, and the
//! last usable key set remains available after a provider failure. There is no periodic refresh.
//! A removed key remains trusted until another refresh replaces the set or the process restarts.
//! Changed key material under an existing `kid` does not itself trigger a refresh, so publish
//! rotated keys under a new `kid`. Use
//! [`KeycloakAuthInstance::operational_status`](instance::KeycloakAuthInstance::operational_status)
//! for health reporting.

#![forbid(unsafe_code)]
#![warn(missing_docs)]
#![deny(clippy::unwrap_used)]

use std::sync::Arc;

use role::Role;

mod clock;
#[deprecated(
    note = "Moved to `token` and `validation`. This alias module will be removed in the next breaking release."
)]
pub mod decode;
mod discovery;
pub mod error;
pub mod extract;
mod http;
pub mod instance;
pub mod layer;
#[allow(missing_docs)]
pub mod oidc;
pub mod oidc_discovery;
pub mod role;
pub mod service;
pub mod token;
pub mod validation;

#[cfg(test)]
mod test_support;

/// URL type used by [`instance::KeycloakConfig`].
pub use url::Url;

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
