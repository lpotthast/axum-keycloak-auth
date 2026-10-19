//! Keycloak realm configuration, OIDC discovery lifecycle, and operational status.

use std::sync::Arc;

use typed_builder::TypedBuilder;
use url::Url;

use crate::{
    clock::{Clock, SystemClock},
    discovery::{
        DecodingKeys, Discovery, OidcDiscoveryEndpoint, RefreshPolicy, default_discovery_op,
    },
    error::{AuthError, InvalidServerUrlError},
    http::default_http_client,
    server_url::ServerUrl,
    validation::KeySource,
};

pub use crate::discovery::{DiscoveryFailure, OperationalStatus};

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
    /// permits up to six attempts per endpoint with a one-second delay. Every failed request is
    /// retried, including non-success HTTP responses.
    ///
    /// Retries apply to the initial discovery and to every on-demand refresh. Requests wait at most
    /// five seconds for a shared refresh and then continue with the cached keys while the refresh
    /// keeps retrying in the background. Lower these values if a refresh should give up sooner.
    #[builder(default = (5, 1))]
    pub retry: (usize, u64),
}

impl KeycloakConfig {
    /// The issuer that Keycloak puts into this realm's tokens, `<server>/realms/<realm>`.
    ///
    /// Pass it to [`ValidationPolicyBuilder::expected_issuers`] instead of assembling the URL by
    /// hand. A trailing slash on [`Self::server`] is handled the same way as for OIDC discovery.
    ///
    /// Keycloak derives the issuer from the URL its clients use. If Keycloak is configured with a
    /// different frontend hostname than [`Self::server`], tokens carry that hostname instead, and
    /// the expected issuer must be configured explicitly.
    ///
    /// # Panics
    ///
    /// Panics if [`Self::server`] cannot serve as a base URL, such as a `mailto:` URL.
    ///
    /// [`ValidationPolicyBuilder::expected_issuers`]: crate::validation::ValidationPolicyBuilder::expected_issuers
    #[must_use]
    pub fn issuer(&self) -> String {
        self.server_url()
            .unwrap_or_else(|err| panic!("{err}"))
            .realm_url(&self.realm)
            .into()
    }

    fn server_url(&self) -> Result<ServerUrl, InvalidServerUrlError> {
        ServerUrl::new(self.server.clone())
    }
}

/// Discovers and caches the OIDC discovery document and decoding keys for one Keycloak realm.
///
/// Validation may request one shared on-demand refresh when no usable keys are cached or when no
/// cached key verifies a token with an unknown `kid` (key ID). The last successful key set remains
/// available when a refresh fails. Cooldown and backoff limit repeated provider requests.
///
/// Create one with [`Self::builder`], supplying your own `reqwest::Client`. Share one instance
/// across layers that use the same realm. This avoids duplicate caches and provider requests.
#[derive(Debug)]
pub struct KeycloakAuthInstance {
    discovery: Discovery,
}

impl KeycloakAuthInstance {
    /// Starts OIDC discovery in a background task with a default HTTP client and returns
    /// immediately.
    ///
    /// Prefer [`Self::builder`] with your own `reqwest::Client`. The default client has a
    /// 10-second connect timeout and a 30-second total-request timeout, and a future release will
    /// no longer provide it.
    ///
    /// Until discovery succeeds, authentication fails because no decoding keys are available.
    /// Report readiness through [`Self::operational_status`], which also retains the discovery
    /// error.
    ///
    /// # Panics
    ///
    /// Panics if called outside a Tokio runtime, if [`KeycloakConfig::server`] cannot serve as a
    /// base URL, or if the default HTTP client cannot initialize. Use
    /// [`KeycloakAuthInstanceBuilder::build`] to receive an [`InvalidServerUrlError`] instead.
    #[must_use]
    pub fn new(kc_config: KeycloakConfig) -> Self {
        Self::builder(kc_config)
            .build()
            .unwrap_or_else(|err| panic!("{err}"))
    }

    /// Configures an instance before creating it. This is the recommended way to create one.
    ///
    /// Supply your `reqwest::Client` through [`KeycloakAuthInstanceBuilder::http_client`]. A future
    /// release will require it. [`KeycloakAuthInstanceBuilder::build`] starts discovery and returns
    /// immediately.
    pub fn builder(kc_config: KeycloakConfig) -> KeycloakAuthInstanceBuilder {
        KeycloakAuthInstanceBuilder {
            config: kc_config,
            http_client: None,
        }
    }

    fn with_components(
        kc_config: &KeycloakConfig,
        server: &ServerUrl,
        client: reqwest::Client,
        id: uuid::Uuid,
        clock: Arc<dyn Clock>,
        refresh_policy: RefreshPolicy,
    ) -> Self {
        let endpoint = OidcDiscoveryEndpoint::new(server, &kc_config.realm);
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

    /// Waits until initial OIDC discovery has terminated and reports whether the instance is
    /// operational.
    ///
    /// This is an advanced option for applications that must not run at all without Keycloak, so
    /// that a misconfiguration or unreachable provider stops them at startup. Most applications
    /// should not block startup on discovery. They should instead report readiness through
    /// [`Self::operational_status`], so that schedulers only route traffic to them once requests
    /// can be authenticated. The crate documentation shows such a readiness check.
    ///
    /// Once initial discovery has terminated, this returns immediately and reports the current
    /// state. A failed later refresh does not produce an error while previously discovered keys
    /// remain usable.
    ///
    /// This method adds no deadline of its own. Each endpoint is attempted up to `retry.0 + 1`
    /// times (see [`KeycloakConfig::retry`]), so an unreachable provider can delay it for several
    /// minutes with the default HTTP client and retry settings. Wrap it in `tokio::time::timeout`
    /// when startup needs a hard deadline.
    ///
    /// # Errors
    ///
    /// Returns the error of the failed discovery when no usable decoding keys are available.
    pub async fn wait_for_discovery(&self) -> Result<(), AuthError> {
        self.discovery.wait_for_completion(1).await;
        if self.discovery.is_operational() {
            Ok(())
        } else {
            Err(self
                .discovery
                .last_discovery_error()
                .unwrap_or(AuthError::NoOidcDiscovery))
        }
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

    /// Returns a point-in-time view of discovery and refresh state for readiness and health
    /// reporting.
    ///
    /// This only reads in-memory state and never waits for a running discovery.
    #[must_use]
    pub fn operational_status(&self) -> OperationalStatus {
        self.discovery.operational_status()
    }

    #[cfg(test)]
    pub(crate) fn new_with_refresh_policy(
        kc_config: &KeycloakConfig,
        id: uuid::Uuid,
        clock: Arc<dyn Clock>,
        refresh_policy: RefreshPolicy,
    ) -> Self {
        let server = kc_config
            .server_url()
            .expect("the test server URL must serve as a base URL");
        Self::with_components(
            kc_config,
            &server,
            default_http_client(),
            id,
            clock,
            refresh_policy,
        )
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
        config: &KeycloakConfig,
        data: crate::discovery::DiscoveredData,
    ) -> Self {
        let server = config
            .server_url()
            .expect("the test server URL must serve as a base URL");
        let endpoint = OidcDiscoveryEndpoint::new(&server, &config.realm);
        Self {
            discovery: Discovery::resolved(endpoint, data),
        }
    }
}

/// Configures and creates a [`KeycloakAuthInstance`].
///
/// Create one with [`KeycloakAuthInstance::builder`]. [`Self::build`] starts discovery and returns
/// immediately. Report readiness through [`KeycloakAuthInstance::operational_status`] until it
/// succeeds.
///
/// ```no_run
/// use std::time::Duration;
///
/// use axum_keycloak_auth::{
///     Url,
///     instance::{KeycloakAuthInstance, KeycloakConfig},
/// };
///
/// # fn run() -> Result<(), Box<dyn std::error::Error>> {
/// let config = KeycloakConfig::builder()
///     .server(Url::parse("https://keycloak.example/")?)
///     .realm(String::from("my-realm"))
///     .build();
/// let http_client = reqwest::Client::builder()
///     .connect_timeout(Duration::from_secs(10))
///     .timeout(Duration::from_secs(30))
///     .build()?;
///
/// let instance = KeycloakAuthInstance::builder(config)
///     .http_client(http_client)
///     .build()?;
/// # Ok(())
/// # }
/// ```
#[derive(Debug)]
#[must_use]
pub struct KeycloakAuthInstanceBuilder {
    config: KeycloakConfig,
    http_client: Option<reqwest::Client>,
}

impl KeycloakAuthInstanceBuilder {
    /// Uses `client` for initial discovery and every later key refresh.
    ///
    /// Always supply a client. A future release will require it. The client controls timeouts,
    /// proxies, trust roots, and mTLS. The crate does not add timeouts to a supplied client, so
    /// configure them on the client, for example a 10-second connect timeout and a 30-second
    /// total-request timeout. Build the client with the same `reqwest` major version as this
    /// crate.
    ///
    /// Without a client, provider requests use a default client with exactly those timeouts.
    pub fn http_client(mut self, client: reqwest::Client) -> Self {
        self.http_client = Some(client);
        self
    }

    /// Creates the instance, starts OIDC discovery in a background task, and returns immediately.
    ///
    /// Until discovery succeeds, authentication fails because no decoding keys are available.
    ///
    /// # Errors
    ///
    /// Returns an [`InvalidServerUrlError`] if [`KeycloakConfig::server`] cannot serve as a base
    /// URL.
    ///
    /// # Panics
    ///
    /// Panics if called outside a Tokio runtime, or if no client was supplied and the default HTTP
    /// client cannot initialize.
    pub fn build(self) -> Result<KeycloakAuthInstance, InvalidServerUrlError> {
        let server = self.config.server_url()?;
        Ok(KeycloakAuthInstance::with_components(
            &self.config,
            &server,
            self.http_client.unwrap_or_else(default_http_client),
            uuid::Uuid::now_v7(),
            Arc::new(SystemClock),
            RefreshPolicy::default(),
        ))
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
        error::AuthError,
        test_support::{
            MockOidcServer, MockResponse, RSA_KEY_A, TEST_KID, TEST_REALM, config_for,
            within_test_timeout,
        },
    };

    use super::{DiscoveryFailure, KeycloakAuthInstance, KeycloakConfig, OperationalStatus};

    /// Creates an instance for `provider` and waits for its initial discovery.
    async fn discover(provider: &MockOidcServer) -> Result<(), AuthError> {
        KeycloakAuthInstance::new(config_for(provider))
            .wait_for_discovery()
            .await
    }

    #[tokio::test]
    async fn wait_for_discovery_succeeds_and_reports_an_operational_status() {
        let provider = MockOidcServer::start().await;
        provider
            .set_jwks(vec![RSA_KEY_A.jwk(Some(TEST_KID), Algorithm::RS256)])
            .await;

        let instance = KeycloakAuthInstance::new(config_for(&provider));
        instance
            .wait_for_discovery()
            .await
            .expect("discovery must succeed against a healthy provider");

        assert_that!(instance.is_operational().await).is_true();
        assert_that!(instance.operational_status()).matches(partial!(OperationalStatus {
            is_operational: IsTrue,
            time_since_last_success: IsSome,
            time_since_last_attempt: IsSome,
            last_error: IsNone,
            consecutive_failures: eq(0),
            ..
        }));
    }

    #[test]
    fn issuer_is_derived_from_server_url_with_or_without_trailing_slash() {
        for (server, expected_issuer) in [
            ("https://host", "https://host/realms/my-realm"),
            ("https://host/", "https://host/realms/my-realm"),
            ("https://host/auth", "https://host/auth/realms/my-realm"),
            ("https://host/auth/", "https://host/auth/realms/my-realm"),
        ] {
            let config = KeycloakConfig::builder()
                .server(url::Url::parse(server).expect("test URL must parse"))
                .realm(String::from("my-realm"))
                .build();

            assert_that!(config.issuer())
                .with_subject_name(server)
                .is_equal_to(expected_issuer);
        }
    }

    #[test]
    fn builder_rejects_a_server_url_that_cannot_be_a_base() {
        let server = url::Url::parse("mailto:admin@example.com").expect("mailto URL must parse");
        let config = KeycloakConfig::builder()
            .server(server.clone())
            .realm(String::from(TEST_REALM))
            .build();

        let error = KeycloakAuthInstance::builder(config)
            .build()
            .expect_err("a mailto URL must be rejected");

        assert_that!(error.url()).is_equal_to(&server);
    }

    #[tokio::test]
    async fn builder_with_a_custom_client_returns_before_discovery_completes() {
        let provider = MockOidcServer::start().await;
        let gate = provider
            .set_gated_jwks(vec![RSA_KEY_A.jwk(Some(TEST_KID), Algorithm::RS256)])
            .await;

        let instance = KeycloakAuthInstance::builder(config_for(&provider))
            .http_client(reqwest::Client::new())
            .build()
            .expect("the mock provider URL must be accepted");

        assert_that!(instance.is_operational().await).is_false();
        gate.release();
        within_test_timeout(
            "discovery must complete after the gate opens",
            instance.wait_for_discovery(),
        )
        .await
        .expect("discovery through the custom client must succeed");
    }

    #[tokio::test]
    async fn wait_for_discovery_reports_the_initial_discovery_error() {
        let provider = MockOidcServer::start().await;
        provider.make_discovery_unavailable().await;

        assert_that!(discover(&provider).await)
            .err()
            .is_matching(pattern!(AuthError::OidcDiscovery { .. }));
    }

    #[tokio::test]
    async fn wait_for_discovery_rejects_initial_jwks_without_usable_keys() {
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

            assert_that!(discover(&provider).await)
                .is_matching(pattern!(Err(AuthError::NoDecodingKeys)));
        }
    }

    #[tokio::test]
    async fn wait_for_discovery_rejects_a_discovery_document_missing_required_oidc_metadata() {
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

        assert_that!(discover(&provider).await)
            .err()
            .is_matching(pattern!(AuthError::OidcDiscovery { .. }));
    }

    #[tokio::test]
    async fn wait_for_discovery_returns_once_the_initial_attempt_terminated() {
        let provider = MockOidcServer::start().await;
        provider.make_discovery_unavailable().await;
        let instance = KeycloakAuthInstance::new(config_for(&provider));

        let result = within_test_timeout(
            "waiting must end after the initial discovery attempt terminated",
            instance.wait_for_discovery(),
        )
        .await;

        assert_that!(result).is_err();
        assert_that!(instance.is_operational().await).is_false();
        assert_that!(instance.operational_status()).matches(partial!(OperationalStatus {
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

        assert_that!(instance.wait_for_discovery().await)
            .is_matching(pattern!(Err(AuthError::NoDecodingKeys)));
        assert_that!(instance.is_operational().await).is_false();
        assert_that!(instance.operational_status()).matches(partial!(OperationalStatus {
            is_operational: IsFalse,
            time_since_last_success: IsNone,
            last_error: partial!(variant Some(partial!(DiscoveryFailure {
                message: eq("The provider returned no usable decoding keys"),
                ..
            }))),
            consecutive_failures: eq(1),
            ..
        }));
        assert_that!(instance.refresh_state_snapshot().next_refresh_at).is_some();
    }
}
