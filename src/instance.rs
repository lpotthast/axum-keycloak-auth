//! Keycloak realm configuration, OIDC discovery lifecycle, and operational status.

use std::sync::Arc;

use typed_builder::TypedBuilder;
use url::Url;

use crate::{
    clock::{Clock, SystemClock},
    discovery::{
        DecodingKeys, Discovery, OidcDiscoveryEndpoint, RefreshPolicy, default_discovery_op,
    },
    error::{AuthError, ConnectError},
    http::default_http_client,
    validation::KeySource,
};

pub use crate::discovery::OperationalStatus;

/// Configuration used to derive a realm's OIDC discovery endpoint.
#[derive(Debug, TypedBuilder)]
pub struct KeycloakConfig {
    /// Base URL of the Keycloak server.
    ///
    /// The realm discovery path is appended to this URL. Both
    /// `https://keycloak.example` and `https://keycloak.example/auth/` are supported.
    pub server: Url,

    /// Keycloak realm name.
    pub realm: String,

    /// Retry count and fixed delay in seconds for OIDC discovery and JWKS requests.
    ///
    /// The first value is the number of retries after the initial attempt. The default `(5, 1)`
    /// permits up to six attempts per endpoint with a one-second delay.
    #[builder(default = (5, 1))]
    pub retry: (usize, u64),
}

/// Discovers and caches the OIDC discovery document and decoding keys for one Keycloak realm.
///
/// Validation may request one shared on-demand refresh when no usable keys are cached or when no
/// cached key verifies a token with an unknown `kid` (key ID). The last successful key set remains
/// available when a refresh fails. Cooldown and backoff limit repeated provider requests.
///
/// Share one instance across layers that use the same realm. This avoids duplicate caches and
/// provider requests.
#[derive(Debug)]
pub struct KeycloakAuthInstance {
    discovery: Discovery,
}

impl KeycloakAuthInstance {
    /// Starts OIDC discovery in a background task and returns immediately.
    ///
    /// Until discovery succeeds, authentication fails because no decoding keys are available.
    /// [`Self::operational_status`] retains the discovery error. Use [`Self::connect`] when startup
    /// should fail if initial discovery fails.
    ///
    /// # Panics
    ///
    /// Panics if called outside a Tokio runtime, if [`KeycloakConfig::server`] cannot serve as a
    /// base URL, or if the default HTTP client cannot initialize. Use [`Self::connect`] to receive
    /// [`ConnectError::InvalidServerUrl`] for an unusable URL.
    #[must_use]
    // The configuration is taken by value to keep the public signature stable; nothing of it
    // needs to outlive construction today.
    #[allow(clippy::needless_pass_by_value)]
    pub fn new(kc_config: KeycloakConfig) -> Self {
        Self::with_components(
            &kc_config,
            default_http_client(),
            uuid::Uuid::now_v7(),
            Arc::new(SystemClock),
            RefreshPolicy::default(),
        )
    }

    /// Creates an instance and waits for initial OIDC discovery.
    ///
    /// Provider requests use one shared HTTP client with bounded connect and total-request
    /// deadlines. Use [`Self::connect_with_client`] to customize deadlines, proxies, trust roots,
    /// or mTLS through your own [`reqwest::Client`].
    ///
    /// # Errors
    ///
    /// Returns a [`ConnectError`] when the server URL cannot serve as a base URL or the initial
    /// discovery fails.
    ///
    /// Cancelling this future aborts its in-flight discovery because no instance is returned to
    /// own the background operation.
    ///
    /// # Panics
    ///
    /// Panics if polled outside a Tokio runtime or if the default HTTP client cannot initialize.
    pub async fn connect(kc_config: KeycloakConfig) -> Result<Self, ConnectError> {
        Self::connect_with_client(kc_config, default_http_client()).await
    }

    /// Creates an instance with a caller-supplied HTTP client and waits for initial discovery.
    ///
    /// The client is reused for initial discovery and later key refreshes. The crate does not add
    /// timeouts to a supplied client. Configure them on the client when discovery and refresh
    /// requests need bounded latency.
    ///
    /// # Errors
    ///
    /// Returns a [`ConnectError`] when the server URL cannot serve as a base URL or the initial
    /// discovery fails.
    ///
    /// Cancelling this future aborts its in-flight discovery because no instance is returned to
    /// own the background operation.
    ///
    /// # Panics
    ///
    /// Panics if polled outside a Tokio runtime.
    pub async fn connect_with_client(
        kc_config: KeycloakConfig,
        client: reqwest::Client,
    ) -> Result<Self, ConnectError> {
        if kc_config.server.cannot_be_a_base() {
            return Err(ConnectError::InvalidServerUrl);
        }
        let instance = Self::with_components(
            &kc_config,
            client,
            uuid::Uuid::now_v7(),
            Arc::new(SystemClock),
            RefreshPolicy::default(),
        );
        instance.ready().await;
        if instance.is_operational().await {
            Ok(instance)
        } else {
            Err(ConnectError::InitialDiscovery {
                source: instance
                    .discovery
                    .last_discovery_error()
                    .unwrap_or(AuthError::NoOidcDiscovery),
            })
        }
    }

    fn with_components(
        kc_config: &KeycloakConfig,
        client: reqwest::Client,
        id: uuid::Uuid,
        clock: Arc<dyn Clock>,
        refresh_policy: RefreshPolicy,
    ) -> Self {
        let endpoint = OidcDiscoveryEndpoint::from_server_and_realm(
            kc_config.server.clone(),
            &kc_config.realm,
        );
        let op = default_discovery_op(
            client,
            id,
            kc_config.server.to_string(),
            kc_config.realm.clone(),
            kc_config.retry,
        );
        Self {
            discovery: Discovery::new(endpoint, op, id, clock, refresh_policy),
        }
    }

    /// Waits until initial OIDC discovery terminates, successfully or not.
    ///
    /// Call [`Self::is_operational`] or [`Self::operational_status`] afterward to inspect the
    /// outcome. This method adds no timeout beyond those configured on the HTTP client.
    pub async fn ready(&self) {
        self.discovery.wait_for_completion(1).await;
    }

    /// Returns whether the instance currently has at least one usable decoding key.
    ///
    /// A failed refresh does not make an instance non-operational while a previously discovered
    /// key set remains usable.
    // Keep the public async API stable even though the published snapshot is now synchronous.
    #[allow(clippy::unused_async, clippy::unused_async_trait_impl)]
    pub async fn is_operational(&self) -> bool {
        self.discovery.is_operational()
    }

    /// Returns a point-in-time view of discovery and refresh state for health reporting.
    // Keep the public async API stable even though refresh bookkeeping now uses a plain mutex.
    #[allow(clippy::unused_async, clippy::unused_async_trait_impl)]
    pub async fn operational_status(&self) -> OperationalStatus {
        self.discovery.operational_status()
    }

    #[cfg(test)]
    pub(crate) fn new_with_refresh_policy(
        kc_config: &KeycloakConfig,
        id: uuid::Uuid,
        clock: Arc<dyn Clock>,
        refresh_policy: RefreshPolicy,
    ) -> Self {
        Self::with_components(kc_config, default_http_client(), id, clock, refresh_policy)
    }

    #[cfg(test)]
    pub(crate) async fn wait_for_discovery_completion(&self, expected_completion: usize) {
        self.discovery
            .wait_for_completion(expected_completion)
            .await;
    }

    #[cfg(test)]
    pub(crate) fn refresh_state_snapshot(&self) -> crate::discovery::RefreshStateSnapshot {
        self.discovery.snapshot()
    }

    #[cfg(test)]
    pub(crate) fn resolved_for_test(
        config: KeycloakConfig,
        data: crate::discovery::DiscoveredData,
    ) -> Self {
        let endpoint = OidcDiscoveryEndpoint::from_server_and_realm(config.server, &config.realm);
        Self {
            discovery: Discovery::resolved(endpoint, data),
        }
    }
}

impl KeySource for KeycloakAuthInstance {
    fn decoding_keys(&self) -> DecodingKeys {
        self.discovery.decoding_keys()
    }

    async fn refresh_if_needed(&self, observed_generation: usize) -> bool {
        self.discovery.refresh_if_needed(observed_generation).await
    }
}

#[cfg(test)]
mod tests {
    use assertr::{
        matchers::{IsFalse, IsNone, IsSome, IsTrue, eq},
        prelude::*,
    };
    use jsonwebtoken::Algorithm;

    use crate::{
        error::{AuthError, ConnectError},
        test_support::{MockOidcServer, MockResponse, RSA_KEY_A, config_for},
    };

    use super::{KeycloakAuthInstance, KeycloakConfig, OperationalStatus};

    #[tokio::test]
    async fn connect_succeeds_and_reports_an_operational_status() {
        let provider = MockOidcServer::start().await;
        provider
            .set_jwks(vec![RSA_KEY_A.jwk(Some("key-a"), Algorithm::RS256)])
            .await;

        let instance = KeycloakAuthInstance::connect(config_for(&provider))
            .await
            .expect("connect must succeed against a healthy provider");

        assert_that!(instance.is_operational().await).is_true();
        assert_that!(instance.operational_status().await).matches(partial!(OperationalStatus {
            is_operational: IsTrue,
            time_since_last_success: IsSome,
            time_since_last_attempt: IsSome,
            last_error: IsNone,
            consecutive_failures: eq(0),
            ..
        }));
    }

    #[tokio::test]
    async fn connect_rejects_a_server_url_that_cannot_be_a_base() {
        let config = KeycloakConfig::builder()
            .server(url::Url::parse("mailto:admin@example.com").expect("mailto URL must parse"))
            .realm(String::from("test-realm"))
            .build();

        assert_that!(KeycloakAuthInstance::connect(config).await)
            .is_matching(pattern!(Err(ConnectError::InvalidServerUrl)));
    }

    #[tokio::test]
    async fn connect_reports_the_initial_discovery_error() {
        let provider = MockOidcServer::start().await;
        provider.make_discovery_unavailable().await;

        assert_that!(KeycloakAuthInstance::connect(config_for(&provider)).await)
            .err()
            .is_matching(pattern!(ConnectError::InitialDiscovery {
                source: AuthError::OidcDiscovery { .. }
            }));
    }

    #[tokio::test]
    async fn connect_rejects_initial_jwks_without_usable_keys() {
        let unusable_jwk = serde_json::from_value(serde_json::json!({
            "kty": "RSA",
            "n": "not-valid-base64url!",
            "e": "AQAB",
            "kid": "broken",
            "alg": "RS256",
            "use": "sig"
        }))
        .expect("syntactically valid JWK fixture must deserialize");

        for jwks in [Vec::new(), vec![unusable_jwk]] {
            let provider = MockOidcServer::start().await;
            provider.set_jwks(jwks).await;

            assert_that!(KeycloakAuthInstance::connect(config_for(&provider)).await).is_matching(
                pattern!(Err(ConnectError::InitialDiscovery {
                    source: AuthError::NoDecodingKeys
                })),
            );
        }
    }

    #[tokio::test]
    async fn connect_rejects_a_discovery_document_missing_required_oidc_metadata() {
        let provider = MockOidcServer::start().await;
        provider
            .set_discovery_response(MockResponse::json(&serde_json::json!({
                "issuer": provider
                    .server_url()
                    .join("realms/test-realm")
                    .expect("issuer URL must join"),
                "jwks_uri": provider.jwks_url(),
            })))
            .await;

        assert_that!(KeycloakAuthInstance::connect(config_for(&provider)).await)
            .err()
            .is_matching(pattern!(ConnectError::InitialDiscovery {
                source: AuthError::OidcDiscovery { .. }
            }));
    }

    #[tokio::test]
    async fn ready_returns_once_the_initial_attempt_terminated() {
        let provider = MockOidcServer::start().await;
        provider.make_discovery_unavailable().await;
        let instance = KeycloakAuthInstance::new(config_for(&provider));

        tokio::time::timeout(std::time::Duration::from_secs(2), instance.ready())
            .await
            .expect("ready must return after the initial discovery attempt terminated");

        assert_that!(instance.is_operational().await).is_false();
        assert_that!(instance.operational_status().await).matches(partial!(OperationalStatus {
            is_operational: IsFalse,
            time_since_last_success: IsNone,
            last_error: IsSome,
            consecutive_failures: eq(1),
            ..
        }));
    }

    #[tokio::test]
    async fn empty_initial_jwks_is_non_operational_and_backed_off() {
        let provider = MockOidcServer::start().await;
        let instance = KeycloakAuthInstance::new(config_for(&provider));

        instance.ready().await;

        assert_that!(instance.is_operational().await).is_false();
        assert_that!(instance.operational_status().await).matches(partial!(OperationalStatus {
            is_operational: IsFalse,
            time_since_last_success: IsNone,
            last_error: partial!(variant Some(eq("The provider returned no usable decoding keys"))),
            consecutive_failures: eq(1),
            ..
        }));
        assert_that!(instance.refresh_state_snapshot().next_refresh_at).is_some();
    }
}
