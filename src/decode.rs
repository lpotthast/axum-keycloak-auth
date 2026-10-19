//! Deprecated re-export of [`crate::token`].
//!
//! Replace `axum_keycloak_auth::decode::X` with `axum_keycloak_auth::token::X`. The old path will
//! be removed in the next breaking release.
//!
//! Rust reports the deprecation only where the `decode` module itself is named, for example in
//! `use axum_keycloak_auth::decode;`. Paths through the module, such as
//! `axum_keycloak_auth::decode::KeycloakToken`, compile without a warning.

pub use crate::token::*;
