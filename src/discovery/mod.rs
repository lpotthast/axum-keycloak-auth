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

use crate::error::AuthError;

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
    pub(crate) fn from_server_and_realm(server: Url, realm: &str) -> Self {
        let mut url = server;
        url.path_segments_mut()
            .expect("URL not to be a 'cannot-be-a-base' URL. We have to append segments.")
            // A trailing slash on the server URL (`https://host/auth/`) must not produce an empty
            // path segment (`/auth//realms/...`).
            .pop_if_empty()
            .extend(&["realms", realm, ".well-known", "openid-configuration"]);
        Self(url)
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

#[cfg(test)]
mod tests {
    use assertr::prelude::*;
    use url::Url;

    use super::OidcDiscoveryEndpoint;

    #[test]
    fn discovery_endpoint_is_derived_from_server_url_with_or_without_trailing_slash() {
        for server in [
            "https://host",
            "https://host/",
            "https://host/auth",
            "https://host/auth/",
        ] {
            let endpoint = OidcDiscoveryEndpoint::from_server_and_realm(
                Url::parse(server).expect("test URL must parse"),
                "my-realm",
            );
            let expected_prefix = if server.contains("auth") {
                "https://host/auth/realms/"
            } else {
                "https://host/realms/"
            };
            assert_that!(endpoint.as_str())
                .with_subject_name(server)
                .is_equal_to(format!(
                    "{expected_prefix}my-realm/.well-known/openid-configuration"
                ));
        }
    }
}
