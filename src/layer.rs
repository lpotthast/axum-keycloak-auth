//! Axum and Tower layer configuration for token extraction, validation, and role enforcement.

use nonempty::NonEmpty;
use serde::de::DeserializeOwned;
use std::collections::HashMap;
use std::marker::PhantomData;
use std::sync::Once;
use std::{fmt::Debug, sync::Arc};
use tower::Layer;
use typed_builder::TypedBuilder;

use crate::clock::{Clock, SystemClock};
use crate::error::AuthError;
use crate::extract::{AuthHeaderTokenExtractor, TokenExtractionErrorPolicy, TokenExtractor};
use crate::token::{KeycloakToken, ProfileAndEmail};
use crate::validation::{ValidationPolicy, Validator};
use crate::{instance::KeycloakAuthInstance, role::Role, service::KeycloakAuthService};

use super::PassthroughMode;

/// Controls how unverified JWT headers are logged.
///
/// JWT headers are decoded before signature verification, so every value is attacker-controlled.
/// [`Self::Metadata`] logs only `alg`, `kid`, and `typ`. [`Self::Complete`] logs the complete header
/// and should be used only for short-lived debugging in a controlled environment. Neither variant
/// logs the bearer token.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum UnverifiedJwtHeaderLogging {
    /// Log only `alg`, `kid`, and `typ` at the selected severity.
    Metadata(tracing::Level),

    /// Log the complete attacker-controlled header at the selected severity.
    Complete(tracing::Level),
}

/// Protects an Axum router or Tower service with Keycloak token validation.
///
/// The default extractor reads `Authorization: Bearer <token>`. Configure [`Self::token_extractors`]
/// to use other credential sources.
///
/// Use `String` for untyped role names, or implement [`Role`] for an application-specific type.
/// `Extra` controls additional claims and defaults to [`ProfileAndEmail`].
///
/// Each call to [`Layer::layer`] snapshots the layer's configuration for the service it creates.
/// Mutating the layer afterward affects only services created later. [`Self::validate_raw_token`]
/// always uses the layer's current configuration.
#[derive(Clone, TypedBuilder)]
pub struct KeycloakAuthLayer<R, Extra = ProfileAndEmail>
where
    R: Role,
    Extra: DeserializeOwned + Clone,
{
    /// Shared OIDC discovery and key cache used to verify tokens.
    #[builder(setter(into))]
    pub instance: Arc<KeycloakAuthInstance>,

    /// Whether failed authentication rejects the request or is passed to the inner service.
    ///
    /// Defaults to [`PassthroughMode::Block`].
    #[builder(default = PassthroughMode::Block)]
    pub passthrough_mode: PassthroughMode,

    /// Retains the complete claims map after successful validation.
    ///
    /// When enabled, every successfully authenticated middleware request receives a
    /// [`crate::token::RawClaims`] request extension. In [`PassthroughMode::Block`], extract it with
    /// Axum's [`axum::Extension`]:
    ///
    /// ```
    /// use axum::Extension;
    /// use axum_keycloak_auth::token::RawClaims;
    ///
    /// async fn handler(Extension(raw_claims): Extension<RawClaims>) {
    ///     let subject = raw_claims.get("sub");
    ///     // Use the claims as needed.
    /// }
    /// ```
    ///
    /// In [`PassthroughMode::Pass`], failed authentication still reaches the inner service, and
    /// this layer does not insert the extension. Use `Option<Extension<RawClaims>>` when handling
    /// both outcomes. For [`Self::validate_raw_token`], enabling this option makes the first tuple
    /// item `Some(RawClaims)`.
    ///
    /// This setting does not log claims. See [`Self::dangerously_log_raw_claims`] for the separate,
    /// security-sensitive logging option. Defaults to `false`.
    #[builder(default = false)]
    pub persist_raw_claims: bool,

    /// Severity for logging the complete raw JWT claims map after signature and policy checks.
    ///
    /// Typed-claim parsing and required-role checks happen afterward, so a request that ultimately
    /// fails authentication may still produce this event.
    ///
    /// # Security warning
    ///
    /// Raw claims commonly contain names, email addresses, and other personal data. Selecting a
    /// level writes them to logs. Never enable this setting in production.
    ///
    /// `None` disables raw-claims logging, which is the default. Supplying a level enables it.
    #[builder(default, setter(strip_option))]
    pub dangerously_log_raw_claims: Option<tracing::Level>,

    /// Controls whether an unverified JWT header is logged as limited metadata or in full, and
    /// selects the event severity.
    ///
    /// `None` disables unverified-header logging, which is the default. Supplying a configuration
    /// enables it.
    #[builder(default, setter(strip_option))]
    pub dangerously_log_unverified_jwt_header: Option<UnverifiedJwtHeaderLogging>,

    /// Severity for logging the final authentication error emitted by the middleware.
    ///
    /// # Security warning
    ///
    /// Authentication failures can be generated at high volume by remote callers. Their detailed
    /// errors may also contain attacker-controlled or claim-derived text. Selecting a level can
    /// therefore create log storms or write sensitive data to logs. Keep this disabled unless
    /// those diagnostics are required and the log sink is appropriately protected.
    ///
    /// When enabled, a missing required role is included in the event's structured `missing_role`
    /// field. The client-visible `403 Forbidden` response omits the role.
    ///
    /// This setting affects logs only. It does not change the HTTP response. `None` disables
    /// detailed error logging, which is the default. Supplying a level enables it.
    #[builder(default, setter(strip_option))]
    pub dangerously_log_authentication_errors: Option<tracing::Level>,

    /// Severity for logging every error returned by a configured token extractor.
    ///
    /// These events are independent of the final authentication outcome. They include absent
    /// credential sources and errors ignored by [`TokenExtractionErrorPolicy::Fallback`], even if
    /// a later extractor succeeds and the request is authenticated.
    ///
    /// # Security warning
    ///
    /// Each event includes the extractor's [`Debug`] output and its detailed error. Custom
    /// extractors can expose arbitrary attacker-controlled or sensitive data through either value.
    /// Errors can also occur at high volume during ordinary requests. Keep this disabled unless
    /// those diagnostics are required and the log sink is appropriately protected.
    ///
    /// This setting affects logs only. It does not change extraction policy or the HTTP response.
    /// `None` disables token-extraction error logging, which is the default. Supplying a level
    /// enables it.
    #[builder(default, setter(strip_option))]
    pub dangerously_log_token_extraction_errors: Option<tracing::Level>,

    /// Accepted values of the JWT `aud` claim.
    ///
    /// Under the default legacy validation policy, a present string or string-array `aud` claim
    /// must match one of these values, while a missing claim is accepted. Malformed claims fail
    /// typed-token parsing. Use [`ValidationPolicy::strict`] to require an audience.
    ///
    /// A policy that defines its own audiences takes precedence. Pass an empty vector here in that
    /// case. A differing non-empty value is ignored and logged as a warning when the first service
    /// or direct validation is created from this layer or one of its clones.
    pub expected_audiences: Vec<String>,

    /// Validation requirements applied to every presented token.
    ///
    /// Defaults to [`ValidationPolicy::legacy`]. When the policy does not define audiences, it
    /// inherits [`Self::expected_audiences`]. Use [`ValidationPolicy::strict`] for new deployments.
    #[builder(default)]
    pub validation_policy: ValidationPolicy,

    /// Roles required by every route protected by this layer.
    ///
    /// Checks compare role values without distinguishing realm and client scope. Leave this empty
    /// for per-handler or scope-aware checks.
    #[builder(default = vec![], setter(into))]
    pub required_roles: Vec<R>,

    /// Ordered, non-empty set of token extractors.
    ///
    /// The first extracted token is validated. Defaults to one
    /// [`AuthHeaderTokenExtractor`].
    #[builder(default = NonEmpty::new(Arc::new(AuthHeaderTokenExtractor::default()) as _))]
    pub token_extractors: NonEmpty<Arc<dyn TokenExtractor>>,

    /// Controls whether an unusable credential source falls back to the next configured extractor
    /// or rejects authentication immediately. An absent source always falls through.
    ///
    /// Defaults to [`TokenExtractionErrorPolicy::Fallback`] to preserve earlier behavior.
    /// [`TokenExtractionErrorPolicy::Reject`] prevents a malformed higher-priority source from
    /// falling through to a lower-priority credential.
    #[builder(default)]
    pub token_extraction_error_policy: TokenExtractionErrorPolicy,

    #[builder(default = uuid::Uuid::now_v7(), setter(skip))]
    id: uuid::Uuid,

    /// Ensures configuration warnings are logged once per layer, not once per direct validation.
    #[builder(default = Arc::new(Once::new()), setter(skip))]
    configuration_warnings: Arc<Once>,

    #[builder(default = Arc::new(SystemClock), setter(skip))]
    pub(crate) clock: Arc<dyn Clock>,

    #[builder(default=PhantomData, setter(skip))]
    phantom: PhantomData<Extra>,
}

impl<R, Extra> KeycloakAuthLayer<R, Extra>
where
    R: Role,
    Extra: DeserializeOwned + Clone,
{
    /// Validates a compact JWT outside the middleware.
    ///
    /// Pass only the token, without the `Bearer ` scheme. This uses the same key discovery,
    /// refresh, policy, and role checks as middleware requests. The optional first tuple item is a
    /// [`crate::token::RawClaims`] map and is present only when [`Self::persist_raw_claims`] is
    /// enabled.
    ///
    /// # Errors
    ///
    /// Returns an [`AuthError`] if the token cannot be decoded or does not satisfy the configured
    /// validation requirements.
    ///
    /// # Panics
    ///
    /// Panics if validation needs an on-demand key refresh while this future is polled outside a
    /// Tokio runtime with time enabled.
    pub async fn validate_raw_token(
        &self,
        raw_token: &str,
    ) -> Result<
        (
            Option<HashMap<String, serde_json::Value>>,
            KeycloakToken<R, Extra>,
        ),
        AuthError,
    > {
        self.validator()
            .validate(raw_token)
            .await
            .map(|validated| (validated.raw_claims, validated.token))
    }

    /// A validator snapshotting the layer's current validation configuration. Built once per
    /// service created from this layer and once per direct [`Self::validate_raw_token`] call.
    /// Configuration warnings are logged only for the first validator.
    pub(crate) fn validator(&self) -> Validator<R, Extra> {
        let policy = self
            .validation_policy
            .clone()
            .with_inherited_audiences(&self.expected_audiences);
        self.configuration_warnings.call_once(|| {
            if let Some(policy_audiences) = self
                .validation_policy
                .audiences_conflicting_with(&self.expected_audiences)
            {
                tracing::warn!(
                    layer_audiences = ?self.expected_audiences,
                    ?policy_audiences,
                    "The validation policy defines its own expected audiences, which differ from \
                     the layer's `expected_audiences`. Only the policy's audiences are enforced."
                );
            }
            if policy.requires_audience_but_has_none() {
                // Fail-closed misconfiguration: turning this into a construction error is planned
                // together with fallible layer configuration.
                tracing::warn!(
                    "The validation policy requires a matching audience, but no expected \
                     audiences are configured. Every token will be rejected."
                );
            }
        });
        Validator::builder()
            .key_source(self.instance.clone())
            .policy(policy)
            .required_roles(self.required_roles.clone())
            .persist_raw_claims(self.persist_raw_claims)
            .raw_claims_log_level(self.dangerously_log_raw_claims)
            .unverified_jwt_header_logging(self.dangerously_log_unverified_jwt_header)
            .clock(self.clock.clone())
            .build()
    }

    #[cfg(test)]
    pub(crate) fn with_clock(mut self, clock: Arc<dyn Clock>) -> Self {
        self.clock = clock;
        self
    }
}

impl<R, Extra> Debug for KeycloakAuthLayer<R, Extra>
where
    R: Role,
    Extra: DeserializeOwned + Clone,
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("KeycloakAuthLayer")
            .field("mode", &self.passthrough_mode)
            .field("persist_raw_claims", &self.persist_raw_claims)
            .field(
                "dangerously_log_raw_claims",
                &self.dangerously_log_raw_claims,
            )
            .field(
                "dangerously_log_unverified_jwt_header",
                &self.dangerously_log_unverified_jwt_header,
            )
            .field(
                "dangerously_log_authentication_errors",
                &self.dangerously_log_authentication_errors,
            )
            .field(
                "dangerously_log_token_extraction_errors",
                &self.dangerously_log_token_extraction_errors,
            )
            .finish_non_exhaustive()
    }
}

impl<S, R, Extra> Layer<S> for KeycloakAuthLayer<R, Extra>
where
    R: Role,
    Extra: DeserializeOwned + Clone,
{
    type Service = KeycloakAuthService<S, R, Extra>;

    #[tracing::instrument(level="info", skip_all, fields(id = ?self.id))]
    fn layer(&self, inner: S) -> Self::Service {
        KeycloakAuthService::new(inner, self)
    }
}

#[cfg(test)]
mod test {
    use std::{
        panic::{AssertUnwindSafe, catch_unwind},
        sync::{Arc, mpsc},
    };

    use assertr::{
        matchers::{IsNone, eq},
        prelude::*,
    };
    use jsonwebtoken::{Algorithm, errors::ErrorKind};
    use nonempty::NonEmpty;
    use serde_json::{Value, json};

    use crate::{
        PassthroughMode,
        error::AuthError,
        extract::{
            AuthHeaderTokenExtractor, QueryParamTokenExtractor, TokenExtractionErrorPolicy,
            TokenExtractor,
        },
        layer::{KeycloakAuthLayer, UnverifiedJwtHeaderLogging},
        test_support::{
            ManualClock, MockOidcServer, RSA_KEY_A, RSA_KEY_B, TEST_AUDIENCE, TEST_ISSUER,
            TEST_KID, TEST_TIMEOUT, discovered_instance, keycloak_claims, offline_instance_at,
            offline_layer, signed_token, validation_time,
        },
    };

    #[tokio::test]
    async fn build_basic_layer() {
        let provider = MockOidcServer::start().await;
        let instance = offline_instance_at(provider.server_url(), provider.realm());

        let layer = KeycloakAuthLayer::<String>::builder()
            .instance(instance)
            .passthrough_mode(PassthroughMode::Block)
            .expected_audiences(vec![String::from(TEST_AUDIENCE)])
            .build();

        assert_that!(layer).matches(partial!(KeycloakAuthLayer {
            dangerously_log_raw_claims: IsNone,
            dangerously_log_unverified_jwt_header: IsNone,
            dangerously_log_authentication_errors: IsNone,
            dangerously_log_token_extraction_errors: IsNone,
            token_extraction_error_policy: eq(TokenExtractionErrorPolicy::Fallback),
            ..
        }));
        assert_that!(provider.discovery_requests()).is_equal_to(0);
        assert_that!(provider.jwks_requests()).is_equal_to(0);
    }

    #[tokio::test]
    async fn build_full_layer() {
        let provider = MockOidcServer::start().await;
        let instance = offline_instance_at(provider.server_url(), provider.realm());

        let layer = KeycloakAuthLayer::<String>::builder()
            .instance(instance)
            .passthrough_mode(PassthroughMode::Block)
            .persist_raw_claims(false)
            .dangerously_log_raw_claims(tracing::Level::INFO)
            .dangerously_log_unverified_jwt_header(UnverifiedJwtHeaderLogging::Complete(
                tracing::Level::TRACE,
            ))
            .dangerously_log_authentication_errors(tracing::Level::INFO)
            .dangerously_log_token_extraction_errors(tracing::Level::DEBUG)
            .expected_audiences(vec![String::from(TEST_AUDIENCE)])
            .required_roles(vec![String::from("administrator")])
            .token_extraction_error_policy(TokenExtractionErrorPolicy::Reject)
            .token_extractors(NonEmpty::<Arc<dyn TokenExtractor>> {
                head: Arc::new(AuthHeaderTokenExtractor::default()),
                tail: vec![
                    Arc::new(QueryParamTokenExtractor::default()),
                    Arc::new(QueryParamTokenExtractor::extracting_key("jwt")),
                ],
            })
            .build();

        assert_that!(layer).matches(partial!(KeycloakAuthLayer {
            token_extraction_error_policy: eq(TokenExtractionErrorPolicy::Reject),
            dangerously_log_raw_claims: eq(Some(tracing::Level::INFO)),
            dangerously_log_unverified_jwt_header: eq(Some(UnverifiedJwtHeaderLogging::Complete(
                tracing::Level::TRACE
            ))),
            dangerously_log_authentication_errors: eq(Some(tracing::Level::INFO)),
            dangerously_log_token_extraction_errors: eq(Some(tracing::Level::DEBUG)),
            ..
        }));

        assert_that!(provider.discovery_requests()).is_equal_to(0);
        assert_that!(provider.jwks_requests()).is_equal_to(0);
    }

    #[tokio::test]
    async fn validates_signed_tokens_with_mock_discovery_and_manual_time() {
        let provider = MockOidcServer::start().await;
        provider
            .set_jwks(vec![RSA_KEY_A.jwk(Some(TEST_KID), Algorithm::RS256)])
            .await;
        let instance = discovered_instance(&provider).await;

        let clock = ManualClock::at_validation_time();
        let layer = KeycloakAuthLayer::<String, Value>::builder()
            .instance(instance)
            .persist_raw_claims(true)
            .expected_audiences(vec![String::from(TEST_AUDIENCE)])
            .build()
            .with_clock(clock.clone());

        let mut claims = keycloak_claims(validation_time());
        claims.insert(
            String::from("exp"),
            json!(validation_time().unix_timestamp()),
        );
        let token = RSA_KEY_A
            .sign(&claims, Algorithm::RS256, Some(TEST_KID))
            .expect("test token must sign");

        let (raw_claims, token_data) = layer
            .validate_raw_token(&token)
            .await
            .expect("token is valid at its expiration timestamp");
        assert_that!(token_data.subject).is_equal_to("test-subject");
        let raw_claims = raw_claims.expect("raw claims were requested");
        assert_that!(raw_claims)
            .contains_entry("iat", json!(validation_time().unix_timestamp()))
            .contains_entry("nbf", json!(validation_time().unix_timestamp()));

        clock.advance(time::Duration::seconds(1));
        assert_that!(layer.validate_raw_token(&token).await)
            .is_matching(pattern!(Err(AuthError::TokenExpired)));

        clock.set(validation_time() - time::Duration::seconds(1));
        assert_that!(layer.validate_raw_token(&token).await).is_ok();
        assert_that!(provider.discovery_requests()).is_equal_to(1);
        assert_that!(provider.jwks_requests()).is_equal_to(1);
    }

    #[tokio::test]
    async fn expired_malformed_claims_preserve_decode_error_ordering() {
        let now = validation_time();
        let layer = offline_layer();
        let mut claims = keycloak_claims(now);
        claims.insert(String::from("exp"), json!(now.unix_timestamp() - 61));
        claims.insert(String::from("iat"), json!({ "malformed": true }));
        let token = RSA_KEY_A
            .sign(&claims, Algorithm::RS256, Some(TEST_KID))
            .expect("test token must sign");

        let error = layer
            .validate_raw_token(&token)
            .await
            .expect_err("expired token must be rejected before typed claim parsing");

        assert_that!(error).is_matching(pattern!(AuthError::Decode { source }
            if matches!(source.kind(), ErrorKind::ExpiredSignature)));
    }

    #[tokio::test]
    async fn expiration_precedes_audience_validation_as_before() {
        let now = validation_time();
        let layer = offline_layer();
        let mut claims = keycloak_claims(now);
        claims.insert(String::from("exp"), json!(now.unix_timestamp() - 61));
        claims.insert(String::from("aud"), json!(["different-audience"]));
        let token = RSA_KEY_A
            .sign(&claims, Algorithm::RS256, Some(TEST_KID))
            .expect("test token must sign");

        assert_that!(layer.validate_raw_token(&token).await).is_matching(pattern!(
            Err(AuthError::Decode { source })
                if matches!(source.kind(), ErrorKind::ExpiredSignature)
        ));
    }

    #[tokio::test]
    async fn refreshed_decode_uses_a_fresh_consistent_validation_time() {
        let provider = MockOidcServer::start().await;
        provider
            .set_jwks(vec![RSA_KEY_A.jwk(Some(TEST_KID), Algorithm::RS256)])
            .await;
        let instance = discovered_instance(&provider).await;
        let gate = provider
            .set_gated_jwks(vec![RSA_KEY_B.jwk(Some("key-b"), Algorithm::RS256)])
            .await;
        let clock = ManualClock::at_validation_time();
        let layer = KeycloakAuthLayer::<String, Value>::builder()
            .instance(instance)
            .expected_audiences(vec![String::from(TEST_AUDIENCE)])
            .build()
            .with_clock(clock.clone());
        let mut claims = keycloak_claims(validation_time());
        claims.insert(
            String::from("exp"),
            json!(validation_time().unix_timestamp() + 1),
        );
        let token = RSA_KEY_B
            .sign(&claims, Algorithm::RS256, Some("key-b"))
            .expect("key B must sign");
        let validation = tokio::spawn(async move { layer.validate_raw_token(&token).await });
        provider.wait_for_jwks_requests(2).await;

        clock.advance(time::Duration::seconds(2));
        gate.release();

        assert_that!(validation.await.expect("validation task must not panic"))
            .is_matching(pattern!(Err(AuthError::TokenExpired)));
    }

    #[test]
    fn on_demand_refresh_outside_tokio_panics_instead_of_deadlocking() {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("the test runtime must build");
        let (layer, token) = runtime.block_on(async {
            let provider = MockOidcServer::start().await;
            provider
                .set_jwks(vec![RSA_KEY_A.jwk(Some(TEST_KID), Algorithm::RS256)])
                .await;
            let instance = discovered_instance(&provider).await;
            let layer = KeycloakAuthLayer::<String, Value>::builder()
                .instance(instance)
                .expected_audiences(vec![String::from(TEST_AUDIENCE)])
                .build()
                .with_clock(ManualClock::at_validation_time());
            let token = signed_token(&RSA_KEY_B, Some("key-b"));
            (layer, token)
        });
        drop(runtime);

        let (result_tx, result_rx) = mpsc::sync_channel(1);
        std::thread::spawn(move || {
            let panic_payload = catch_unwind(AssertUnwindSafe(|| {
                futures::executor::block_on(layer.validate_raw_token(&token))
            }))
            .err();
            let consecutive_failures =
                futures::executor::block_on(layer.instance.operational_status())
                    .consecutive_failures;
            result_tx
                .send((panic_payload, consecutive_failures))
                .expect("the test must still be waiting for validation");
        });

        let (panic_payload, consecutive_failures) = result_rx
            .recv_timeout(TEST_TIMEOUT)
            .expect("validation and its cancellation bookkeeping must not deadlock");
        let panic_payload =
            panic_payload.expect("validation must panic without an active Tokio runtime");
        assert_that!(panic_payload).message().contains("Tokio");
        assert_that!(consecutive_failures).is_equal_to(1);
    }

    #[tokio::test]
    async fn strict_policy_inherits_the_layer_expected_audiences() {
        let provider = MockOidcServer::start().await;
        provider
            .set_jwks(vec![RSA_KEY_A.jwk(Some(TEST_KID), Algorithm::RS256)])
            .await;
        let instance = discovered_instance(&provider).await;
        let layer = KeycloakAuthLayer::<String, Value>::builder()
            .instance(instance)
            .expected_audiences(vec![String::from(TEST_AUDIENCE)])
            .validation_policy(
                crate::validation::ValidationPolicy::strict()
                    .expected_issuers([TEST_ISSUER])
                    .build()
                    .expect("a strict policy naming its issuers must build"),
            )
            .build()
            .with_clock(ManualClock::at_validation_time());

        let token = signed_token(&RSA_KEY_A, Some(TEST_KID));
        layer
            .validate_raw_token(&token)
            .await
            .expect("the strict policy must inherit the layer's expected audiences");

        let mut claims = keycloak_claims(validation_time());
        claims.insert(String::from("aud"), json!(["other-service"]));
        let mismatched = RSA_KEY_A
            .sign(&claims, Algorithm::RS256, Some(TEST_KID))
            .expect("test token must sign");
        assert_that!(layer.validate_raw_token(&mismatched).await).is_matching(pattern!(
            Err(AuthError::Decode { source })
                if matches!(source.kind(), ErrorKind::InvalidAudience)
        ));
    }

    #[tokio::test]
    async fn within_leeway_malformed_claims_still_report_typed_parse_errors() {
        let now = validation_time();
        let layer = offline_layer();
        let mut claims = keycloak_claims(now);
        claims.insert(String::from("exp"), json!(now.unix_timestamp() - 60));
        claims.insert(String::from("iat"), json!({ "malformed": true }));
        let token = RSA_KEY_A
            .sign(&claims, Algorithm::RS256, Some(TEST_KID))
            .expect("test token must sign");

        assert_that!(layer.validate_raw_token(&token).await)
            .is_matching(pattern!(Err(AuthError::JsonParse { .. })));
    }
}
