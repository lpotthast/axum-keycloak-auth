//! Ready-made [`KeycloakAuthInstance`]s and their discovery data: offline instances that never
//! perform I/O, and instances discovering against the [`MockOidcServer`].

use std::sync::Arc;

use assertr::prelude::*;
use jsonwebtoken::{
    Algorithm,
    jwk::{Jwk, JwkSet},
};
use url::Url;

use crate::{
    discovery::{DiscoveredData, RefreshPolicy},
    instance::{KeycloakAuthInstance, KeycloakConfig},
    oidc::OidcConfig,
};

use super::{
    RSA_KEY_A, TEST_KID, TEST_REALM,
    mock_provider::{MockOidcServer, discovery_document},
    test_server_url, within_test_timeout,
};

/// The fast test retry strategy: one retry, without delay.
const TEST_RETRY: (usize, u64) = (1, 0);

/// Discovery data for the fixture realm, trusting [`RSA_KEY_A`] under [`TEST_KID`].
pub(crate) fn static_discovered_data() -> DiscoveredData {
    discovered_data_at(
        &test_server_url(),
        TEST_REALM,
        vec![RSA_KEY_A.jwk(Some(TEST_KID), Algorithm::RS256)],
    )
}

/// Discovery data for `realm` on `server`, trusting exactly `keys`.
pub(crate) fn discovered_data_at(server: &Url, realm: &str, keys: Vec<Jwk>) -> DiscoveredData {
    let issuer = server
        .join(&format!("realms/{realm}"))
        .expect("the static issuer URL must join");
    let jwks_url = server.join("jwks").expect("the static JWKS URL must join");
    let oidc_config = serde_json::from_value::<OidcConfig>(discovery_document(&issuer, &jwks_url))
        .expect("the static discovery document must deserialize");
    DiscoveredData::new(oidc_config, &JwkSet { keys })
}

/// An instance for the fixture realm whose discovery already resolved to
/// [`static_discovered_data`]. It performs no I/O.
pub(crate) fn offline_instance() -> KeycloakAuthInstance {
    offline_instance_at(test_server_url(), TEST_REALM)
}

/// An instance for `realm` on `server` whose discovery already resolved, trusting [`RSA_KEY_A`]
/// under [`TEST_KID`]. It performs no I/O, so pointing it at a [`MockOidcServer`] proves that
/// nothing is fetched.
pub(crate) fn offline_instance_at(server: Url, realm: &str) -> KeycloakAuthInstance {
    let data = discovered_data_at(
        &server,
        realm,
        vec![RSA_KEY_A.jwk(Some(TEST_KID), Algorithm::RS256)],
    );
    let config = KeycloakConfig::builder()
        .server(server)
        .realm(realm.to_owned())
        .retry(TEST_RETRY)
        .build();
    KeycloakAuthInstance::resolved_for_test(config, data)
}

/// A configuration for `provider`'s realm, using the fast test retry strategy.
pub(crate) fn config_for(provider: &MockOidcServer) -> KeycloakConfig {
    KeycloakConfig::builder()
        .server(provider.server_url())
        .realm(provider.realm().to_owned())
        .retry(TEST_RETRY)
        .build()
}

/// The production refresh policy with jitter disabled, for tests asserting exact deadlines.
pub(crate) fn refresh_policy_without_jitter() -> RefreshPolicy {
    RefreshPolicy {
        jitter_basis_points: 0,
        ..RefreshPolicy::default()
    }
}

/// An instance that completed its initial discovery against `provider` and is operational.
pub(crate) async fn discovered_instance(provider: &MockOidcServer) -> Arc<KeycloakAuthInstance> {
    let instance = Arc::new(KeycloakAuthInstance::new(config_for(provider)));
    wait_for_discovery_completion(&instance, 1).await;
    assert_that!(instance.is_operational().await).is_true();
    instance
}

/// Waits until `instance` has terminated at least `expected_completion` discoveries.
pub(crate) async fn wait_for_discovery_completion(
    instance: &KeycloakAuthInstance,
    expected_completion: usize,
) {
    within_test_timeout(
        &format!("discovery must reach completion {expected_completion}"),
        instance.wait_for_discovery_completion(expected_completion),
    )
    .await;
}
