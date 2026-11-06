//! Token validation policy and signature algorithm configuration.
//!
//! [`ValidationPolicy`] controls accepted audiences, issuers, algorithms, token types, time claims,
//! required claims, and authorized parties. Start with [`ValidationPolicy::legacy`] to preserve
//! historical behavior or [`ValidationPolicy::strict`] for stricter defaults, then customize the
//! returned [`ValidationPolicyBuilder`].
//!
//! The middleware and [`crate::layer::KeycloakAuthLayer::validate_raw_token`] enforce the same
//! policy.

mod pipeline;
mod policy;

use crate::discovery::DecodingKeys;

pub(crate) use pipeline::Validator;
pub use policy::{ValidationPolicy, ValidationPolicyBuilder};

/// Re-export of the token signature algorithm type accepted by
/// [`ValidationPolicyBuilder::allowed_algorithms`].
pub use jsonwebtoken::Algorithm;

/// The validator's port to trusted key material. Implemented by `KeycloakAuthInstance` and kept
/// abstract so validation does not depend on provider I/O.
pub(crate) trait KeySource {
    /// A point-in-time snapshot of the trusted decoding keys.
    fn decoding_keys(&self) -> DecodingKeys;

    /// Requests a refresh of the key material because a token names an unknown `kid`, if the
    /// observed generation is still current. Implementations are expected to rate-limit and to
    /// share concurrent refreshes. Returns whether a generation newer than the observed one was
    /// published.
    async fn refresh_for_unknown_kid(&self, observed_generation: usize) -> bool;

    /// Like [`Self::refresh_for_unknown_kid`], because no key material is available yet.
    async fn refresh_for_missing_keys(&self, observed_generation: usize) -> bool;

    /// Like [`Self::refresh_for_unknown_kid`], for keys withheld because they expired. Implementations
    /// may decline to wait, for example while the provider is failing, so that the rejection is
    /// not delayed.
    async fn refresh_expired_keys(&self, observed_generation: usize) -> bool;

    /// Starts a refresh, without waiting for it, if the key material is due for one. A backup for
    /// background refreshes.
    fn refresh_if_stale(&self);
}
