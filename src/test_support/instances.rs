//! Ready-made [`KeycloakAuthInstance`]s and their discovery data: offline instances that never
//! perform I/O, and instances discovering against the [`MockOidcServer`].

use std::{sync::Arc, time::Duration};

use assertr::prelude::*;
use jsonwebtoken::{
    Algorithm,
    jwk::{Jwk, JwkSet},
};

use crate::{
    discovery::{DiscoveredData, DiscoveryConfig},
    instance::{KeycloakAuthInstance, KeycloakConfig, ServerUrl},
    oidc::OidcConfig,
};

use super::{
    RSA_KEY_A, TEST_KID, TEST_REALM,
    mock_provider::{MockOidcServer, discovery_document},
    test_server_url, within_test_timeout,
};

/// Discovery data for the fixture realm, trusting [`RSA_KEY_A`] under [`TEST_KID`].
pub(crate) fn static_discovered_data() -> DiscoveredData {
    discovered_data_at(
        &test_server_url(),
        TEST_REALM,
        vec![RSA_KEY_A.jwk(Some(TEST_KID), Algorithm::RS256)],
    )
}

/// Discovery data for `realm` on `server`, trusting exactly `keys`.
pub(crate) fn discovered_data_at(
    server: &ServerUrl,
    realm: &str,
    keys: Vec<Jwk>,
) -> DiscoveredData {
    let issuer = server.realm_url(realm);
    let jwks_url = server
        .as_url()
        .join("jwks")
        .expect("the static JWKS URL must join");
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
pub(crate) fn offline_instance_at(server: ServerUrl, realm: &str) -> KeycloakAuthInstance {
    let data = discovered_data_at(
        &server,
        realm,
        vec![RSA_KEY_A.jwk(Some(TEST_KID), Algorithm::RS256)],
    );
    let config = KeycloakConfig::builder()
        .server(server)
        .realm(realm.to_owned())
        .build();
    KeycloakAuthInstance::resolved(&config, data)
}

/// A configuration for `provider`'s realm.
pub(crate) fn config_for(provider: &MockOidcServer) -> KeycloakConfig {
    KeycloakConfig::builder()
        .server(provider.server_url())
        .realm(provider.realm().to_owned())
        .build()
}

/// The production discovery configuration with the fast test retry strategy (one retry, without
/// delay) and without the background refresh task, so that tests control every refresh.
pub(crate) fn test_discovery_config() -> DiscoveryConfig {
    DiscoveryConfig {
        background_refresh: false,
        ..DiscoveryConfig::builder()
            .request_retries(1)
            .request_retry_delay(Duration::ZERO)
            .build()
            .expect("the test discovery configuration must build")
    }
}

/// The HTTP client used to reach the [`MockOidcServer`], with a 10-second connect timeout and a
/// 30-second total-request timeout.
pub(crate) fn test_http_client() -> reqwest::Client {
    reqwest::Client::builder()
        .connect_timeout(Duration::from_secs(10))
        .timeout(Duration::from_secs(30))
        .build()
        .expect("the test HTTP client must build")
}

/// An instance discovering against `provider` with [`config_for`], [`test_http_client`], and
/// [`test_discovery_config`]. It starts discovery and returns immediately.
pub(crate) fn instance_for(provider: &MockOidcServer) -> KeycloakAuthInstance {
    KeycloakAuthInstance::builder()
        .config(config_for(provider))
        .http_client(test_http_client())
        .discovery_config(test_discovery_config())
        .build()
}

/// [`test_discovery_config`] with jitter disabled, for tests asserting exact deadlines.
pub(crate) fn discovery_config_without_jitter() -> DiscoveryConfig {
    DiscoveryConfig {
        jitter_basis_points: 0,
        ..test_discovery_config()
    }
}

/// An instance that completed its initial discovery against `provider` and is operational.
pub(crate) async fn discovered_instance(provider: &MockOidcServer) -> Arc<KeycloakAuthInstance> {
    let instance = Arc::new(instance_for(provider));
    wait_for_discovery_completion(&instance, 1).await;
    assert_that!(instance.is_operational()).is_true();
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
