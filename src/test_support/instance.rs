use std::sync::Arc;

use assertr::prelude::*;
use jsonwebtoken::{Algorithm, jwk::JwkSet};
use time::{Date, Month, OffsetDateTime};
use url::Url;

use crate::{
    discovery::{DiscoveredData, RefreshPolicy},
    instance::{KeycloakAuthInstance, KeycloakConfig},
    oidc::OidcConfig,
};

use super::{
    jwt::{KeyFixture, RSA_KEY_A, keycloak_claims},
    oidc::{MockOidcServer, discovery_document},
};

pub(crate) async fn wait_for_discovery_completion(
    instance: &KeycloakAuthInstance,
    expected_completion: usize,
) {
    tokio::time::timeout(
        std::time::Duration::from_secs(2),
        instance.wait_for_discovery_completion(expected_completion),
    )
    .await
    .unwrap_or_else(|_elapsed| {
        panic!("discovery did not reach completion {expected_completion} within the test timeout")
    });
}

/// A `KeycloakConfig` against the mock provider, with the fast test retry strategy (one retry,
/// no delay).
pub(crate) fn config_for(provider: &MockOidcServer) -> KeycloakConfig {
    KeycloakConfig::builder()
        .server(provider.server_url())
        .realm(provider.realm().to_owned())
        .retry((1, 0))
        .build()
}

/// The production refresh policy with jitter disabled, for tests asserting exact deadlines.
pub(crate) fn refresh_policy_without_jitter() -> RefreshPolicy {
    RefreshPolicy {
        jitter_basis_points: 0,
        ..RefreshPolicy::default()
    }
}

/// Statically resolved discovery data for `server`/`realm`, trusting the given key set.
pub(crate) fn static_discovered_data_with_keys(
    server: &Url,
    realm: &str,
    jwk_set: &JwkSet,
) -> DiscoveredData {
    let issuer = server
        .join(&format!("realms/{realm}"))
        .unwrap_or_else(|err| panic!("static issuer URL must join: {err}"));
    let jwks_url = server
        .join("jwks")
        .unwrap_or_else(|err| panic!("static JWKS URL must join: {err}"));
    let oidc_config = serde_json::from_value::<OidcConfig>(discovery_document(&issuer, &jwks_url))
        .unwrap_or_else(|err| panic!("the static discovery document must deserialize: {err}"));
    DiscoveredData::new(oidc_config, jwk_set)
}

/// Statically resolved discovery data for `server`/`realm`, trusting key A under kid "key-a".
pub(crate) fn static_discovered_data(server: &Url, realm: &str) -> DiscoveredData {
    let jwk = RSA_KEY_A.jwk(Some("key-a"), Algorithm::RS256);
    static_discovered_data_with_keys(server, realm, &JwkSet { keys: vec![jwk] })
}

/// An instance whose discovery already resolved to [`static_discovered_data`] and which performs
/// no I/O.
pub(crate) fn offline_instance(server: Url, realm: String) -> KeycloakAuthInstance {
    let data = static_discovered_data(&server, &realm);
    let config = KeycloakConfig::builder()
        .server(server)
        .realm(realm)
        .retry((1, 0))
        .build();
    KeycloakAuthInstance::resolved_for_test(config, data)
}

/// An instance that completed its initial discovery against the mock provider.
pub(crate) async fn discovered_instance(provider: &MockOidcServer) -> Arc<KeycloakAuthInstance> {
    let instance = Arc::new(KeycloakAuthInstance::new(config_for(provider)));
    wait_for_discovery_completion(&instance, 1).await;
    assert_that!(instance.is_operational().await).is_true();
    instance
}

pub(crate) fn validation_time() -> OffsetDateTime {
    Date::from_calendar_date(2030, Month::March, 17)
        .expect("test date must be valid")
        .with_hms(17, 46, 40)
        .expect("test time must be valid")
        .assume_utc()
}

/// The fixture claims of [`keycloak_claims`] at [`validation_time`], signed as RS256 by `key`.
pub(crate) fn signed_token(key: &KeyFixture, kid: Option<&str>) -> String {
    key.sign(&keycloak_claims(validation_time()), Algorithm::RS256, kid)
        .expect("test key must sign")
}
