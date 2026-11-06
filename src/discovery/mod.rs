//! Internal OIDC discovery and JWKS cache.
//!
//! [`provider`] fetches the discovery document and JWKS. [`lifecycle`] coordinates refreshes and
//! health state. [`config`] holds the discovery configuration and calculates refresh delays.
//! [`keys`] publishes generation-tagged key snapshots.

mod config;
mod keys;
mod lifecycle;
mod provider;

use std::{ops::Deref, sync::Arc};

use futures::future::BoxFuture;
use url::Url;

use crate::{error::AuthError, server_url::ServerUrl};

pub use config::{DiscoveryConfig, DiscoveryConfigBuilder, ExpiredKeys};
pub(crate) use keys::{DecodingKeys, DiscoveredData};
pub(crate) use lifecycle::Discovery;
pub use lifecycle::{DiscoveryFailure, OperationalStatus};
pub(crate) use provider::default_discovery_op;

#[cfg(test)]
pub(crate) use lifecycle::RefreshStateSnapshot;

#[derive(Debug, Clone)]
pub(crate) struct OidcDiscoveryEndpoint(pub(crate) Url);

impl OidcDiscoveryEndpoint {
    pub(crate) fn new(server: &ServerUrl, realm: &str) -> Self {
        Self(server.discovery_url(realm))
    }
}

impl Deref for OidcDiscoveryEndpoint {
    type Target = Url;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

/// Why a discovery runs. Recorded as `discovery_kind` in the discovery's tracing span, so that
/// operators can tell routine refreshes from refreshes that requests caused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum DiscoveryKind {
    /// The first discovery, started when the instance is created.
    Initial,
    /// The background task refreshes keys that reached `refresh_after`, or retries a failed
    /// discovery after its backoff.
    Scheduled,
    /// A request found the keys due for a refresh before the background task refreshed them, for
    /// example because the task is disabled or fell behind.
    Overdue,
    /// A request found no keys, because no discovery succeeded yet.
    NoKeys,
    /// No cached key verified a token naming an unknown `kid`, so the signing key may have been
    /// rotated. Anyone can send such tokens, which is why on-demand refreshes are rate-limited.
    UnknownKid,
    /// A request found the keys expired, because refreshing them failed or fell behind.
    KeysExpired,
}

#[derive(Debug, Clone)]
pub(crate) struct DiscoveryRequest {
    attempt: usize,
    kind: DiscoveryKind,
}

pub(crate) type DiscoveryResult = Result<Arc<DiscoveredData>, AuthError>;

pub(crate) type DiscoveryOp = Arc<
    dyn Fn(OidcDiscoveryEndpoint, DiscoveryRequest) -> BoxFuture<'static, DiscoveryResult>
        + Send
        + Sync,
>;
