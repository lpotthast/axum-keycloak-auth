//! Internal OIDC discovery and JWKS cache.
//!
//! [`provider`] fetches the discovery document and JWKS. [`lifecycle`] coordinates refreshes and
//! health state.
//! [`policy`] calculates refresh delays. [`keys`] publishes generation-tagged key snapshots.

mod keys;
mod lifecycle;
mod policy;
mod provider;

use std::{ops::Deref, sync::Arc};

use futures::future::BoxFuture;
use url::Url;

use crate::{error::AuthError, server_url::ServerUrl};

pub(crate) use keys::{DecodingKeys, DiscoveredData};
pub(crate) use lifecycle::Discovery;
pub use lifecycle::OperationalStatus;
pub(crate) use policy::RefreshPolicy;
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DiscoveryKind {
    Initial,
    OnDemand,
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
