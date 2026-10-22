//! Header decoding, key selection, signature verification, claim validation, and role checks.
//!
//! The pipeline uses [`KeySource`] for trusted keys and [`ValidationPolicy`] for configurable
//! checks. It can request one rate-limited refresh and retry when a signing key may have rotated.

use std::{marker::PhantomData, sync::Arc};

use jsonwebtoken::Header;
use serde::Deserialize;
use serde::de::{DeserializeOwned, value::MapDeserializer};
use snafu::ResultExt;
use typed_builder::TypedBuilder;

use crate::{
    clock::Clock,
    error::{AuthError, DecodeSnafu},
    instance::KeycloakAuthInstance,
    layer::UnverifiedJwtHeaderLogging,
    logging::event_at_level,
    role::{ExpectRoles, Role},
    token::{KeycloakToken, RawClaims, RawToken, StandardClaims},
};

use super::{KeySource, ValidationPolicy};

/// Result of successful validation.
#[derive(Debug)]
pub(crate) struct ValidatedToken<R, Extra>
where
    R: Role,
    Extra: DeserializeOwned + Clone,
{
    pub(crate) token: KeycloakToken<R, Extra>,
    /// The raw claims map, retained only when `persist_raw_claims` was configured.
    pub(crate) raw_claims: Option<RawClaims>,
}

/// Validates raw JWTs against one [`KeySource`] and a frozen set of validation requirements. The
/// Axum layer delegates to this so the request path shares one immutable configuration snapshot
/// instead of cloning the layer's configuration per request.
#[derive(TypedBuilder)]
pub(crate) struct Validator<R, Extra, K = KeycloakAuthInstance> {
    key_source: Arc<K>,
    policy: ValidationPolicy,
    required_roles: Vec<R>,
    persist_raw_claims: bool,
    #[builder(default)]
    raw_claims_log_level: Option<tracing::Level>,
    #[builder(default)]
    unverified_jwt_header_logging: Option<UnverifiedJwtHeaderLogging>,
    clock: Arc<dyn Clock>,
    #[builder(default = PhantomData, setter(skip))]
    phantom: PhantomData<fn() -> Extra>,
}

struct DecodedRawClaims {
    claims: RawClaims,
    validation_time: time::OffsetDateTime,
}

struct DecodeAttempt {
    result: Result<RawClaims, AuthError>,
    unknown_kid: bool,
    generation: usize,
    validation_time: time::OffsetDateTime,
}

impl<R, Extra, K> Validator<R, Extra, K>
where
    R: Role,
    Extra: DeserializeOwned + Clone,
    K: KeySource,
{
    /// The full validation pipeline: decode the header, verify the signature against the trusted
    /// keys, enforce the validation policy, parse the typed claims, and enforce the required
    /// roles.
    pub(crate) async fn validate(
        &self,
        raw_token: &str,
    ) -> Result<ValidatedToken<R, Extra>, AuthError> {
        let raw_token = RawToken(raw_token);
        let decoded = self.decode_and_validate(&raw_token).await?;
        self.parse_raw_claims(decoded.claims, decoded.validation_time)
    }

    /// Decodes and validates the token against the currently trusted decoding keys, sharing one
    /// rate-limited key refresh and retrying once when the signing key may have rotated.
    async fn decode_and_validate(
        &self,
        raw_token: &RawToken<'_>,
    ) -> Result<DecodedRawClaims, AuthError> {
        let header = raw_token.decode_header()?;
        log_unverified_jwt_header(self.unverified_jwt_header_logging, &header);
        self.policy.check_algorithm(header.alg)?;

        // Signature verification (and the required-claim check for `exp`) stays with
        // jsonwebtoken. All claim-policy checks are enforced by this crate itself, in
        // `try_decode`. Depends only on the token header, so both decode attempts share it.
        //
        // Signature validation stays enabled so that jsonwebtoken applies its algorithm-family
        // guard: a decoding key may only verify a token whose header algorithm belongs to that
        // key's own family. Without that guard, the header algorithm alone would select the
        // verifier, which is the classic algorithm-confusion vector: an `HS*` header would make
        // the HMAC verifier treat published asymmetric key material as a shared secret (forgeable
        // by anyone who can read the JWKS), and a header from a family other than the key's would
        // reach key accessors that the key type does not support. Only `exp` and `aud` are taken
        // away from jsonwebtoken here, because this crate's policy owns them.
        let mut validation = jsonwebtoken::Validation::new(header.alg);
        validation.validate_exp = false;
        validation.validate_aud = false;

        let first = self.try_decode(&header, &validation, raw_token);
        let first_error = match first.result {
            Ok(claims) => {
                return Ok(DecodedRawClaims {
                    claims,
                    validation_time: first.validation_time,
                });
            }
            Err(error) => error,
        };
        let key_may_be_missing =
            first.unknown_kid || matches!(first_error, AuthError::NoDecodingKeys);
        if !key_may_be_missing {
            return Err(first_error);
        }

        // The signing key may have rotated. Share one rate-limited refresh and retry once.
        if !self.key_source.refresh_if_needed(first.generation).await {
            return Err(first_error);
        }
        let second = self.try_decode(&header, &validation, raw_token);
        match second.result {
            Ok(claims) => Ok(DecodedRawClaims {
                claims,
                validation_time: second.validation_time,
            }),
            Err(second_error) => {
                // A token-wide failure means a refreshed key got past candidate-key rejection,
                // so it is the authoritative reason the token is invalid. Otherwise retain the
                // first candidate-key error, except when the first attempt had no keys from which
                // to obtain one.
                if matches!(&first_error, AuthError::NoDecodingKeys)
                    || is_token_wide_rejection(&second_error)
                {
                    Err(second_error)
                } else {
                    Err(first_error)
                }
            }
        }
    }

    fn try_decode(
        &self,
        header: &Header,
        validation: &jsonwebtoken::Validation,
        raw_token: &RawToken<'_>,
    ) -> DecodeAttempt {
        let decoding_keys = self.key_source.decoding_keys();
        let validation_time = self.clock.now_utc();
        let generation = decoding_keys.generation();

        let (signature_result, unknown_kid) = match header.kid.as_deref() {
            Some(kid) => {
                if let Some(exact_keys) = decoding_keys.exact(kid) {
                    // Known kid: try its keys first, then the remaining trusted keys, in one
                    // pass. The kid is a lookup hint, not an acceptance constraint, and the
                    // single pass lets `verify_signature`'s error preference span the whole
                    // trusted set.
                    (
                        verify_signature(
                            raw_token,
                            validation,
                            exact_keys.chain(decoding_keys.all_except(kid)),
                        ),
                        false,
                    )
                } else {
                    // Unknown kid: legacy all-key fallback. Only a candidate-key rejection marks
                    // the kid as unknown (and thereby worth one rate-limited refresh): the signing
                    // key may have rotated, or the realm may have moved to a key family the cached
                    // set does not contain yet. A token-wide decode or claim failure cannot become
                    // valid through a key refresh.
                    let result = verify_signature(raw_token, validation, decoding_keys.all());
                    let unknown_kid = matches!(
                        &result,
                        Err(AuthError::Decode { source }) if is_candidate_key_rejection(source)
                    );
                    (result, unknown_kid)
                }
            }
            // No kid: legacy all-key selection.
            None => (
                verify_signature(raw_token, validation, decoding_keys.all()),
                false,
            ),
        };

        // The policy's claim checks run once against the signature-verified claims, against the
        // single captured validation time instead of separate system-clock reads. Which key
        // verified the signature is irrelevant: every key decodes the same claims.
        let result = signature_result.and_then(|claims| {
            self.policy.check_claims(&claims, validation_time)?;
            log_raw_claims(self.raw_claims_log_level, &claims);
            Ok(claims)
        });

        DecodeAttempt {
            result,
            unknown_kid,
            generation,
            validation_time,
        }
    }

    fn parse_raw_claims(
        &self,
        raw_claims: RawClaims,
        validation_time: time::OffsetDateTime,
    ) -> Result<ValidatedToken<R, Extra>, AuthError> {
        // The typed claims are deserialized straight from the raw claims map; when the raw claims
        // are retained, they are deserialized by reference, so retaining needs no deep clone.
        let (retained_raw_claims, standard_claims) = if self.persist_raw_claims {
            let standard_claims = StandardClaims::<Extra>::deserialize(MapDeserializer::new(
                raw_claims
                    .iter()
                    .map(|(claim, value)| (claim.as_str(), value)),
            ))
            .map_err(json_parse_error)?;
            (Some(raw_claims), standard_claims)
        } else {
            (
                None,
                StandardClaims::<Extra>::deserialize(MapDeserializer::new(raw_claims.into_iter()))
                    .map_err(json_parse_error)?,
            )
        };
        let token = KeycloakToken::<R, Extra>::parse(standard_claims)?;
        if self.policy.wants_legacy_second_expiry_check() {
            token.assert_not_expired_at(validation_time)?;
        }
        token.expect_roles(&self.required_roles)?;
        Ok(ValidatedToken {
            token,
            raw_claims: retained_raw_claims,
        })
    }
}

fn log_raw_claims(level: Option<tracing::Level>, claims: &RawClaims) {
    if let Some(level) = level {
        event_at_level!(
            level,
            ?claims,
            "Decoded JWT raw claims (sensitive data logging explicitly enabled)"
        );
    }
}

fn log_unverified_jwt_header(logging: Option<UnverifiedJwtHeaderLogging>, header: &Header) {
    match logging {
        None => {}
        Some(UnverifiedJwtHeaderLogging::Metadata(level)) => {
            event_at_level!(
                level,
                alg = ?header.alg,
                kid = ?header.kid,
                typ = ?header.typ,
                "Decoded unverified JWT header"
            );
        }
        Some(UnverifiedJwtHeaderLogging::Complete(level)) => {
            event_at_level!(
                level,
                ?header,
                "Decoded complete unverified JWT header (attacker-controlled header logging \
                 explicitly enabled)"
            );
        }
    }
}

/// Verifies the signature against the given keys. Token-wide decoding errors are terminal.
/// Candidate-key failures try the next key, preferring an error from the token's algorithm family
/// over a family mismatch when no key succeeds.
///
/// [`jsonwebtoken::decode`] keeps signature validation enabled, binding the header algorithm to the
/// decoding key's algorithm family. The caller applies the validation policy to the returned
/// claims.
fn verify_signature<'d>(
    raw_token: &RawToken<'_>,
    validation: &jsonwebtoken::Validation,
    decoding_keys: impl Iterator<Item = &'d jsonwebtoken::DecodingKey>,
) -> Result<RawClaims, AuthError> {
    let mut result: Result<RawClaims, AuthError> = Err(AuthError::NoDecodingKeys);
    for key in decoding_keys {
        match jsonwebtoken::decode::<RawClaims>(raw_token.0, key, validation) {
            Ok(token_data) => return Ok(token_data.claims),
            Err(error) => {
                // `decode_and_validate` already accepted the token shape and header, and this
                // validation permits exactly the header algorithm. In this path only a bad
                // signature or a key-family mismatch can be changed by trying another key.
                if !is_candidate_key_rejection(&error) {
                    return Err(error).context(DecodeSnafu {});
                }
                let keep_previous = is_family_mismatch(&error)
                    && matches!(&result, Err(AuthError::Decode { source }) if !is_family_mismatch(source));
                if !keep_previous {
                    result = Err(error).context(DecodeSnafu {});
                }
            }
        }
    }
    result
}

fn is_candidate_key_rejection(error: &jsonwebtoken::errors::Error) -> bool {
    matches!(
        error.kind(),
        jsonwebtoken::errors::ErrorKind::InvalidSignature
            | jsonwebtoken::errors::ErrorKind::InvalidAlgorithm
    )
}

/// Whether an error rejects the token itself after key selection, rather than only rejecting the
/// currently available candidate keys.
fn is_token_wide_rejection(error: &AuthError) -> bool {
    match error {
        AuthError::NoDecodingKeys => false,
        AuthError::Decode { source } => !is_candidate_key_rejection(source),
        _ => true,
    }
}

fn is_family_mismatch(error: &jsonwebtoken::errors::Error) -> bool {
    matches!(
        error.kind(),
        jsonwebtoken::errors::ErrorKind::InvalidAlgorithm
    )
}

fn json_parse_error(err: serde_json::Error) -> AuthError {
    AuthError::JsonParse {
        source: Arc::new(err),
    }
}

#[cfg(test)]
mod tests {
    use std::{marker::PhantomData, rc::Rc, sync::Arc, time::Duration};

    use crate::{
        clock::Clock,
        discovery::{RefreshPolicy, RefreshStateSnapshot},
        error::AuthError,
        instance::KeycloakAuthInstance,
        layer::UnverifiedJwtHeaderLogging,
        test_support::{
            CapturedLogs, Claims, EC_KEY_A, ManualClock, MockOidcServer, RSA_KEY_A, RSA_KEY_B,
            StaticKeySource, assert_logged_iff, claims_with, claims_without, config_for,
            discovered_instance, keycloak_claims, legacy_policy, refresh_policy_without_jitter,
            signed_token, strict_policy, validation_time, wait_for_discovery_completion,
            within_test_timeout,
        },
        token::{ProfileAndEmail, RawClaims, RawToken},
    };
    use assertr::{
        matchers::{IsFalse, IsNone, IsOk, IsSome, each, eq},
        prelude::*,
    };
    use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
    use futures::future::join_all;
    use jsonwebtoken::{Algorithm, Header, errors::ErrorKind, jwk::Jwk};

    use super::{
        super::{KeySource, ValidationPolicy},
        Validator,
    };

    // ----- Shared helpers -------------------------------------------------------------------

    fn validator<K: KeySource>(
        source: Arc<K>,
        policy: ValidationPolicy,
        clock: Arc<dyn Clock>,
    ) -> Validator<String, serde_json::Value, K> {
        Validator::builder()
            .key_source(source)
            .policy(policy)
            .required_roles(Vec::new())
            .persist_raw_claims(false)
            .clock(clock)
            .build()
    }

    /// Runs the decode stage of the pipeline only: key selection, refresh orchestration, and
    /// signature/policy validation.
    async fn decode<K: KeySource>(
        source: &Arc<K>,
        policy: ValidationPolicy,
        clock: Arc<dyn Clock>,
        token: &str,
    ) -> Result<RawClaims, AuthError> {
        validator(source.clone(), policy, clock)
            .decode_and_validate(&RawToken(token))
            .await
            .map(|decoded| decoded.claims)
    }

    /// [`decode`] under the legacy policy and the fixed test clock.
    async fn decode_legacy<K: KeySource>(
        source: &Arc<K>,
        token: &str,
    ) -> Result<RawClaims, AuthError> {
        let policy = legacy_policy().build().expect("the test policy must build");
        decode(source, policy, ManualClock::at_validation_time(), token).await
    }

    /// [`decode`] under the strict policy and the fixed test clock.
    async fn decode_strict<K: KeySource>(
        source: &Arc<K>,
        token: &str,
    ) -> Result<RawClaims, AuthError> {
        let policy = strict_policy()
            .build()
            .expect("the strict policy must build");
        decode(source, policy, ManualClock::at_validation_time(), token).await
    }

    fn key_a(kid: &str) -> Jwk {
        RSA_KEY_A.jwk(Some(kid), Algorithm::RS256)
    }

    fn key_b(kid: &str) -> Jwk {
        RSA_KEY_B.jwk(Some(kid), Algorithm::RS256)
    }

    fn ec_key(kid: &str) -> Jwk {
        EC_KEY_A.jwk(Some(kid), Algorithm::ES256)
    }

    /// An in-memory key source trusting key A under "key-a".
    fn trusting_key_a() -> Arc<StaticKeySource> {
        StaticKeySource::new(vec![key_a("key-a")])
    }

    /// The fixture claims at the test time, signed RS256 by key A under "key-a".
    fn signed_claims_token(claims: &Claims) -> String {
        RSA_KEY_A
            .sign(claims, Algorithm::RS256, Some("key-a"))
            .expect("test token must sign")
    }

    /// A token whose signature part is a well-formed but wrong ES256 signature (64 zero bytes).
    fn with_unverifiable_signature(token: &str) -> String {
        let (message, _signature) = token.rsplit_once('.').expect("a JWT has a signature part");
        format!("{message}.{}", "A".repeat(86))
    }

    fn forged_hs256_token(kid: &str, secret: &[u8]) -> String {
        let mut header = jsonwebtoken::Header::new(Algorithm::HS256);
        header.kid = Some(String::from(kid));
        let mut forged_claims = keycloak_claims(validation_time());
        forged_claims.insert(String::from("sub"), serde_json::json!("attacker"));
        forged_claims.insert(
            String::from("realm_access"),
            serde_json::json!({ "roles": ["administrator"] }),
        );
        jsonwebtoken::encode(
            &header,
            &forged_claims,
            &jsonwebtoken::EncodingKey::from_secret(secret),
        )
        .expect("the forged token must encode")
    }

    #[track_caller]
    fn assert_invalid_signature<T: std::fmt::Debug>(result: &Result<T, AuthError>) {
        assert_that!(result).is_matching(pattern!(
            Err(AuthError::Decode { source })
                if matches!(source.kind(), ErrorKind::InvalidSignature)
        ));
    }

    #[track_caller]
    fn assert_invalid_algorithm<T: std::fmt::Debug>(result: &Result<T, AuthError>) {
        assert_that!(result).is_matching(pattern!(
            Err(AuthError::Decode { source })
                if matches!(source.kind(), ErrorKind::InvalidAlgorithm)
        ));
    }

    #[track_caller]
    fn assert_expired<T: std::fmt::Debug>(result: &Result<T, AuthError>) {
        assert_that!(result).is_matching(pattern!(
            Err(AuthError::Decode { source })
                if matches!(source.kind(), ErrorKind::ExpiredSignature)
        ));
    }

    #[track_caller]
    fn assert_invalid_token<T: std::fmt::Debug>(result: &Result<T, AuthError>) {
        assert_that!(result).is_matching(pattern!(Err(AuthError::InvalidToken { .. })));
    }

    #[track_caller]
    fn assert_invalid_audience<T: std::fmt::Debug>(result: &Result<T, AuthError>) {
        assert_that!(result).is_matching(pattern!(
            Err(AuthError::Decode { source })
                if matches!(source.kind(), ErrorKind::InvalidAudience)
        ));
    }

    #[track_caller]
    fn assert_invalid_issuer<T: std::fmt::Debug>(result: &Result<T, AuthError>) {
        assert_that!(result).is_matching(pattern!(
            Err(AuthError::Decode { source })
                if matches!(source.kind(), ErrorKind::InvalidIssuer)
        ));
    }

    #[track_caller]
    fn assert_immature<T: std::fmt::Debug>(result: &Result<T, AuthError>) {
        assert_that!(result).is_matching(pattern!(
            Err(AuthError::Decode { source })
                if matches!(source.kind(), ErrorKind::ImmatureSignature)
        ));
    }

    // ----- Mock-provider helpers (refresh lifecycle tests) ----------------------------------

    async fn provider_with_key_a() -> MockOidcServer {
        let provider = MockOidcServer::start().await;
        provider.set_jwks(vec![key_a("key-a")]).await;
        provider
    }

    async fn rotate_to_key_b(provider: &MockOidcServer) {
        provider.set_jwks(vec![key_b("key-b")]).await;
    }

    async fn discovered_instance_with_refresh_policy(
        provider: &MockOidcServer,
        clock: Arc<dyn Clock>,
        policy: RefreshPolicy,
    ) -> Arc<KeycloakAuthInstance> {
        let instance = Arc::new(KeycloakAuthInstance::new_with_refresh_policy(
            &config_for(provider),
            uuid::Uuid::from_u128(1),
            clock,
            policy,
        ));
        wait_for_discovery_completion(&instance, 1).await;
        assert_that!(instance.is_operational().await).is_true();
        instance
    }

    // ----- Refresh lifecycle through a real (mock) provider ----------------------------------

    #[tokio::test]
    async fn refreshes_jwks_for_an_unknown_kid() {
        let provider = provider_with_key_a().await;
        let instance = discovered_instance(&provider).await;
        decode_legacy(&instance, &signed_token(&RSA_KEY_A, Some("key-a")))
            .await
            .expect("key A token must validate before rotation");

        rotate_to_key_b(&provider).await;
        decode_legacy(&instance, &signed_token(&RSA_KEY_B, Some("key-b")))
            .await
            .expect("unknown key B must trigger one refresh and then validate");

        assert_that!(provider.discovery_requests()).is_equal_to(2);
        assert_that!(provider.jwks_requests()).is_equal_to(2);
    }

    #[tokio::test]
    async fn concurrent_unknown_kids_share_one_refresh() {
        let provider = provider_with_key_a().await;
        let instance = discovered_instance(&provider).await;
        rotate_to_key_b(&provider).await;
        let token = signed_token(&RSA_KEY_B, Some("key-b"));

        let attempts = join_all((0..16).map(|_| decode_legacy(&instance, &token))).await;

        assert_that!(attempts).matches(each(IsOk));
        assert_that!(provider.discovery_requests()).is_equal_to(2);
        assert_that!(provider.jwks_requests()).is_equal_to(2);
    }

    #[tokio::test]
    async fn concurrent_callers_wait_for_the_shared_refresh_before_retrying() {
        let provider = provider_with_key_a().await;
        let instance = discovered_instance(&provider).await;
        let gate = provider.set_gated_jwks(vec![key_b("key-b")]).await;
        let token = signed_token(&RSA_KEY_B, Some("key-b"));
        let validations = {
            let instance = instance.clone();
            tokio::spawn(async move {
                join_all((0..8).map(|_| {
                    let instance = instance.clone();
                    let token = token.clone();
                    async move { decode_legacy(&instance, &token).await }
                }))
                .await
            })
        };
        provider.wait_for_jwks_requests(2).await;
        assert_that!(provider.discovery_requests()).is_equal_to(2);
        assert_that!(provider.jwks_requests()).is_equal_to(2);

        gate.release();
        let results = within_test_timeout(
            "waiting validations must finish after the shared refresh",
            validations,
        )
        .await
        .expect("validation task must not panic");
        assert_that!(results).matches(each(IsOk));
        assert_that!(provider.discovery_requests()).is_equal_to(2);
        assert_that!(provider.jwks_requests()).is_equal_to(2);
    }

    #[tokio::test]
    async fn initial_failure_has_no_stale_keys_and_is_backed_off() {
        let provider = MockOidcServer::start().await;
        provider.make_discovery_unavailable().await;
        let instance = Arc::new(KeycloakAuthInstance::new(config_for(&provider)));
        wait_for_discovery_completion(&instance, 1).await;
        assert_that!(instance.is_operational().await).is_false();

        let result = decode_legacy(&instance, &signed_token(&RSA_KEY_B, Some("key-b"))).await;

        assert_that!(result).is_matching(pattern!(Err(AuthError::NoDecodingKeys)));
        assert_that!(provider.discovery_requests()).is_equal_to(2);
        assert_that!(provider.jwks_requests()).is_equal_to(0);
    }

    #[tokio::test]
    async fn failed_refresh_keeps_the_last_successful_keys_usable() {
        let provider = provider_with_key_a().await;
        let instance = discovered_instance(&provider).await;
        provider.make_discovery_unavailable().await;

        assert_invalid_signature(
            &decode_legacy(&instance, &signed_token(&RSA_KEY_B, Some("key-b"))).await,
        );

        decode_legacy(&instance, &signed_token(&RSA_KEY_A, Some("key-a")))
            .await
            .expect("the last successful key set must survive a failed refresh");

        assert_that!(instance.is_operational().await).is_true();
        assert_that!(instance.refresh_state_snapshot()).matches(partial!(RefreshStateSnapshot {
            last_successful_at: IsSome,
            last_attempted_at: IsSome,
            last_error_at: IsSome,
            consecutive_failures: eq(1),
            next_refresh_at: IsSome,
            pending: IsFalse,
            generation: eq(2),
        }));
        // `retry((1, 0))` performs the initial failed request plus one retry.
        assert_that!(provider.discovery_requests()).is_equal_to(3);
        assert_that!(provider.jwks_requests()).is_equal_to(1);
    }

    #[tokio::test]
    async fn empty_refresh_keeps_the_last_usable_keys() {
        let provider = provider_with_key_a().await;
        let instance = discovered_instance(&provider).await;
        provider.set_jwks(Vec::new()).await;

        assert_invalid_signature(
            &decode_legacy(&instance, &signed_token(&RSA_KEY_B, Some("key-b"))).await,
        );

        decode_legacy(&instance, &signed_token(&RSA_KEY_A, Some("key-a")))
            .await
            .expect("an empty refresh must not replace usable cached keys");

        assert_that!(instance.refresh_state_snapshot()).matches(partial!(RefreshStateSnapshot {
            last_error_at: IsSome,
            consecutive_failures: eq(1),
            ..
        }));
        assert_that!(provider.discovery_requests()).is_equal_to(2);
        assert_that!(provider.jwks_requests()).is_equal_to(2);
    }

    #[tokio::test]
    async fn entirely_unusable_refresh_keeps_the_last_usable_keys() {
        let provider = provider_with_key_a().await;
        let instance = discovered_instance(&provider).await;
        let unusable_jwk = serde_json::from_value(serde_json::json!({
            "kty": "RSA",
            "n": "not-valid-base64url!",
            "e": "AQAB",
            "kid": "broken",
            "alg": "RS256",
            "use": "sig"
        }))
        .expect("syntactically valid JWK fixture must deserialize");
        provider.set_jwks(vec![unusable_jwk]).await;

        assert_invalid_signature(
            &decode_legacy(&instance, &signed_token(&RSA_KEY_B, Some("key-b"))).await,
        );

        decode_legacy(&instance, &signed_token(&RSA_KEY_A, Some("key-a")))
            .await
            .expect("unusable replacement keys must not evict usable cached keys");

        assert_that!(instance.refresh_state_snapshot()).matches(partial!(RefreshStateSnapshot {
            last_error_at: IsSome,
            consecutive_failures: eq(1),
            ..
        }));
        assert_that!(provider.discovery_requests()).is_equal_to(2);
        assert_that!(provider.jwks_requests()).is_equal_to(2);
    }

    #[tokio::test]
    async fn usable_refresh_recovers_after_an_empty_result() {
        let provider = provider_with_key_a().await;
        let clock = ManualClock::at_validation_time();
        let instance = discovered_instance_with_refresh_policy(
            &provider,
            clock.clone(),
            refresh_policy_without_jitter(),
        )
        .await;
        provider.set_jwks(Vec::new()).await;
        let key_b_token = signed_token(&RSA_KEY_B, Some("key-b"));

        assert_invalid_signature(&decode_legacy(&instance, &key_b_token).await);
        decode_legacy(&instance, &signed_token(&RSA_KEY_A, Some("key-a")))
            .await
            .expect("empty refresh must retain key A during backoff");

        rotate_to_key_b(&provider).await;
        clock.advance(time::Duration::seconds(1));
        decode_legacy(&instance, &key_b_token)
            .await
            .expect("a later usable result must replace retained stale data");

        // The successful refresh ends the failure streak, so health reporting must no longer
        // surface the stale error.
        assert_that!(instance.refresh_state_snapshot()).matches(partial!(RefreshStateSnapshot {
            consecutive_failures: eq(0),
            last_error_at: IsNone,
            ..
        }));
        assert_that!(provider.discovery_requests()).is_equal_to(3);
        assert_that!(provider.jwks_requests()).is_equal_to(3);
    }

    #[tokio::test]
    async fn refreshes_after_initial_jwks_without_usable_keys_reaches_its_retry_deadline() {
        let provider = MockOidcServer::start().await;
        let clock = ManualClock::at_validation_time();
        let instance = Arc::new(KeycloakAuthInstance::new_with_refresh_policy(
            &config_for(&provider),
            uuid::Uuid::from_u128(1),
            clock.clone(),
            refresh_policy_without_jitter(),
        ));
        wait_for_discovery_completion(&instance, 1).await;
        assert_that!(instance.is_operational().await).is_false();

        rotate_to_key_b(&provider).await;
        clock.advance(time::Duration::seconds(1));

        decode_legacy(&instance, &signed_token(&RSA_KEY_B, Some("key-b")))
            .await
            .expect("a usable key set must recover discovery after failure backoff");
        assert_that!(instance.is_operational().await).is_true();
        assert_that!(provider.discovery_requests()).is_equal_to(2);
        assert_that!(provider.jwks_requests()).is_equal_to(2);
    }

    #[tokio::test]
    async fn empty_refresh_without_usable_cache_uses_failure_backoff() {
        let provider = MockOidcServer::start().await;
        let clock = ManualClock::at_validation_time();
        let instance = Arc::new(KeycloakAuthInstance::new_with_refresh_policy(
            &config_for(&provider),
            uuid::Uuid::from_u128(1),
            clock.clone(),
            refresh_policy_without_jitter(),
        ));
        wait_for_discovery_completion(&instance, 1).await;
        let first_unknown = signed_token(&RSA_KEY_B, Some("key-b"));
        let second_unknown = signed_token(&RSA_KEY_B, Some("key-c"));

        assert_that!(decode_legacy(&instance, &first_unknown).await)
            .is_matching(pattern!(Err(AuthError::NoDecodingKeys)));
        assert_that!(instance.refresh_state_snapshot().consecutive_failures).is_equal_to(1);
        assert_that!(provider.discovery_requests()).is_equal_to(1);
        assert_that!(provider.jwks_requests()).is_equal_to(1);

        clock.advance(time::Duration::seconds(1));
        assert_that!(decode_legacy(&instance, &second_unknown).await)
            .is_matching(pattern!(Err(AuthError::NoDecodingKeys)));
        assert_that!(instance.refresh_state_snapshot().consecutive_failures).is_equal_to(2);
        assert_that!(provider.discovery_requests()).is_equal_to(2);
        assert_that!(provider.jwks_requests()).is_equal_to(2);
    }

    // ----- Key selection and refresh decisions (in-memory key source) ------------------------

    #[tokio::test]
    async fn preserves_the_first_error_when_refresh_does_not_validate_the_token() {
        let source = trusting_key_a();
        // The refreshed key is labeled key-b but still has the wrong key material, so both
        // attempts fail with the all-key InvalidSignature result.
        source.rotate_on_next_refresh(vec![key_a("key-b")]);

        let result = decode_legacy(&source, &signed_token(&RSA_KEY_B, Some("key-b"))).await;

        assert_invalid_signature(&result);
        assert_that!(source.refresh_requests()).is_equal_to(1);
    }

    #[tokio::test]
    async fn successful_rotation_reports_the_refreshed_keys_expiry_error() {
        let source = trusting_key_a();
        source.rotate_on_next_refresh(vec![key_b("key-b")]);
        let token = RSA_KEY_B
            .sign(
                &claims_with("exp", serde_json::json!(1_000)),
                Algorithm::RS256,
                Some("key-b"),
            )
            .expect("test token must sign");

        let result = decode_legacy(&source, &token).await;

        assert_expired(&result);
        assert_that!(source.refresh_requests()).is_equal_to(1);
    }

    #[tokio::test]
    async fn successful_rotation_reports_the_refreshed_keys_audience_error() {
        let source = trusting_key_a();
        source.rotate_on_next_refresh(vec![key_b("key-b")]);
        let token = RSA_KEY_B
            .sign(
                &claims_with("aud", serde_json::json!(["different-audience"])),
                Algorithm::RS256,
                Some("key-b"),
            )
            .expect("test token must sign");

        let result = decode_legacy(&source, &token).await;

        assert_invalid_audience(&result);
        assert_that!(source.refresh_requests()).is_equal_to(1);
    }

    #[tokio::test]
    async fn successful_rotation_reports_the_refreshed_keys_malformed_claim_error() {
        let source = trusting_key_a();
        source.rotate_on_next_refresh(vec![key_b("key-b")]);
        let token = RSA_KEY_B
            .sign(
                &claims_with("exp", serde_json::json!(1.5)),
                Algorithm::RS256,
                Some("key-b"),
            )
            .expect("test token must sign");

        let result = decode_legacy(&source, &token).await;

        assert_invalid_token(&result);
        assert_that!(source.refresh_requests()).is_equal_to(1);
    }

    #[tokio::test]
    async fn keys_arriving_with_the_refresh_report_the_actual_validation_error() {
        // No keys at all on the first attempt; the refresh publishes a usable key set.
        let source = StaticKeySource::new(Vec::new());
        source.rotate_on_next_refresh(vec![key_a("key-a")]);

        let result = decode_legacy(&source, &signed_token(&RSA_KEY_B, Some("key-b"))).await;

        // The retry against the refreshed keys must report why the token is rejected;
        // `NoDecodingKeys` would misrepresent an instance that has keys by now (and is planned
        // to map to a 503 eventually, which a bad token must never earn).
        assert_invalid_signature(&result);
        assert_that!(source.refresh_requests()).is_equal_to(1);
    }

    #[tokio::test]
    async fn expired_token_reports_expiry_even_when_other_keys_cannot_verify_it() {
        let source = StaticKeySource::new(vec![key_a("key-a"), key_b("key-b")]);
        let token = signed_claims_token(&claims_with("exp", serde_json::json!(1_000)));

        let result = decode_legacy(&source, &token).await;

        // The former per-key loop kept iterating past the expiry failure and reported key B's
        // InvalidSignature; expiry is now checked once, after signature verification succeeded.
        assert_expired(&result);
        assert_that!(source.refresh_requests()).is_equal_to(0);
    }

    #[tokio::test]
    async fn expired_token_with_unknown_kid_does_not_trigger_a_refresh() {
        let source = trusting_key_a();
        let token = RSA_KEY_A
            .sign(
                &claims_with("exp", serde_json::json!(1_000)),
                Algorithm::RS256,
                Some("stale-provider-label"),
            )
            .expect("test token must sign");

        let result = decode_legacy(&source, &token).await;

        // The signature verified against a cached key, so no key refresh can make this token
        // valid and none must be triggered.
        assert_expired(&result);
        assert_that!(source.refresh_requests()).is_equal_to(0);
    }

    #[tokio::test]
    async fn structural_error_with_unknown_kid_is_preserved_without_refresh() {
        let token = RSA_KEY_A
            .sign(
                &claims_without("exp"),
                Algorithm::RS256,
                Some("stale-provider-label"),
            )
            .expect("test token must sign");

        for keys in [
            vec![key_a("key-a"), key_b("key-b")],
            vec![key_b("key-b"), key_a("key-a")],
        ] {
            let source = StaticKeySource::new(keys);

            let result = decode_legacy(&source, &token).await;

            assert_that!(result).is_matching(pattern!(
                Err(AuthError::Decode { source })
                    if matches!(source.kind(), ErrorKind::MissingRequiredClaim(claim) if claim == "exp")
            ));
            assert_that!(source.refresh_requests()).is_equal_to(0);
        }
    }

    #[tokio::test]
    async fn wrong_audience_with_unknown_kid_does_not_trigger_a_refresh() {
        let source = trusting_key_a();
        let token = RSA_KEY_A
            .sign(
                &claims_with("aud", serde_json::json!(["different-audience"])),
                Algorithm::RS256,
                Some("stale-provider-label"),
            )
            .expect("test token must sign");

        let result = decode_legacy(&source, &token).await;

        assert_invalid_audience(&result);
        assert_that!(source.refresh_requests()).is_equal_to(0);
    }

    #[tokio::test]
    async fn does_not_refresh_for_a_known_kid_with_an_invalid_signature() {
        let source = trusting_key_a();

        let result = decode_legacy(&source, &signed_token(&RSA_KEY_B, Some("key-a"))).await;

        assert_invalid_signature(&result);
        assert_that!(source.refresh_requests()).is_equal_to(0);
    }

    #[tokio::test]
    async fn unknown_kid_uses_legacy_all_key_fallback_without_refreshing() {
        let source = trusting_key_a();

        decode_legacy(
            &source,
            &signed_token(&RSA_KEY_A, Some("stale-provider-label")),
        )
        .await
        .expect("kid must remain a lookup hint, not an acceptance constraint");

        assert_that!(source.refresh_requests()).is_equal_to(0);
    }

    #[tokio::test]
    async fn wrong_known_kid_falls_back_to_other_trusted_keys() {
        let source = StaticKeySource::new(vec![key_a("claimed-kid"), key_b("actual-key")]);

        decode_legacy(&source, &signed_token(&RSA_KEY_B, Some("claimed-kid")))
            .await
            .expect("a misleading kid must not exclude another trusted validating key");

        assert_that!(source.refresh_requests()).is_equal_to(0);
    }

    #[tokio::test]
    async fn token_without_a_kid_tries_all_usable_keys_without_refreshing() {
        let source = StaticKeySource::new(vec![key_a("key-a"), key_b("key-b")]);

        decode_legacy(&source, &signed_token(&RSA_KEY_B, None))
            .await
            .expect("kid-less token must retain legacy all-key selection");

        assert_that!(source.refresh_requests()).is_equal_to(0);
    }

    #[tokio::test]
    async fn duplicate_kid_entries_are_tried_in_jwks_order() {
        let source = StaticKeySource::new(vec![key_a("shared-kid"), key_b("shared-kid")]);

        decode_legacy(&source, &signed_token(&RSA_KEY_B, Some("shared-kid")))
            .await
            .expect("all usable duplicate-kid keys must be tried");

        assert_that!(source.refresh_requests()).is_equal_to(0);
    }

    /// With a mixed-family key set, the error reported for an unverifiable token, and therefore
    /// the decision to refresh, must not depend on the order in which the provider lists its
    /// keys: a key of the token's own family that failed outranks keys that could never have
    /// verified it.
    #[tokio::test]
    async fn the_reported_signature_error_does_not_depend_on_provider_key_order() {
        let token = with_unverifiable_signature(
            &EC_KEY_A
                .sign(
                    &keycloak_claims(validation_time()),
                    Algorithm::ES256,
                    Some("ec-new"),
                )
                .expect("the EC fixture must sign"),
        );

        for keys in [
            vec![ec_key("ec-old"), key_a("rsa")],
            vec![key_a("rsa"), ec_key("ec-old")],
        ] {
            let source = StaticKeySource::new(keys);

            let result = decode_legacy(&source, &token).await;

            assert_invalid_signature(&result);
            assert_that!(source.refresh_requests()).is_equal_to(1);
        }
    }

    /// The same preference must span kid partitions: a same-family failure from the keys sharing
    /// the token's kid must not be shadowed by a family mismatch from the fallback keys.
    #[tokio::test]
    async fn the_reported_signature_error_is_consistent_across_kid_partitions() {
        let token = with_unverifiable_signature(
            &EC_KEY_A
                .sign(
                    &keycloak_claims(validation_time()),
                    Algorithm::ES256,
                    Some("ec-key"),
                )
                .expect("the EC fixture must sign"),
        );
        let source = StaticKeySource::new(vec![ec_key("ec-key"), key_a("rsa")]);

        let result = decode_legacy(&source, &token).await;

        // The EC key matching the kid fails in-family (InvalidSignature); the RSA fallback can
        // only produce a family mismatch, which must not win. A known kid earns no refresh.
        assert_invalid_signature(&result);
        assert_that!(source.refresh_requests()).is_equal_to(0);
    }

    /// A realm moving from RSA to EC signatures issues tokens that no cached key can verify,
    /// because the cached set does not contain the new family yet. The unknown-`kid` refresh must
    /// pick the new key up like any other rotation.
    #[tokio::test]
    async fn a_realm_moving_to_another_key_family_recovers_through_the_unknown_kid_refresh() {
        let source = trusting_key_a();
        source.rotate_on_next_refresh(vec![key_a("key-a"), ec_key("ec-key")]);
        let token = EC_KEY_A
            .sign(
                &keycloak_claims(validation_time()),
                Algorithm::ES256,
                Some("ec-key"),
            )
            .expect("the EC fixture must sign");

        decode_legacy(&source, &token)
            .await
            .expect("the refreshed key set must verify the new family's token");

        assert_that!(source.refresh_requests()).is_equal_to(1);
    }

    // ----- Policies ---------------------------------------------------------------------------

    #[tokio::test]
    async fn legacy_policy_accepts_a_token_without_an_audience() {
        let source = trusting_key_a();

        decode_legacy(&source, &signed_claims_token(&claims_without("aud")))
            .await
            .expect("the legacy policy accepts tokens without an audience claim");
    }

    #[tokio::test]
    async fn legacy_policy_rejects_a_malformed_audience_during_typed_claim_parsing() {
        let source = trusting_key_a();
        let policy = legacy_policy().build().expect("the test policy must build");
        let token = signed_claims_token(&claims_with("aud", serde_json::json!(42)));

        assert_that!(
            validator(source, policy, ManualClock::at_validation_time())
                .validate(&token)
                .await
        )
        .is_matching(pattern!(Err(AuthError::JsonParse { .. })));
    }

    #[tokio::test]
    async fn legacy_policy_accepts_any_algorithm_the_trusted_key_verifies() {
        let source = trusting_key_a();
        // The trusted JWK declares RS256, but the legacy behavior constructs the acceptable
        // algorithm from the token header. Binding keys to their declared algorithm remains a
        // planned opt-in.
        let token = RSA_KEY_A
            .sign(
                &keycloak_claims(validation_time()),
                Algorithm::RS384,
                Some("key-a"),
            )
            .expect("test token must sign");

        decode_legacy(&source, &token)
            .await
            .expect("the legacy policy accepts any algorithm the trusted key verifies");
    }

    #[tokio::test]
    async fn strict_policy_accepts_a_conforming_keycloak_token() {
        let source = trusting_key_a();

        decode_strict(&source, &signed_token(&RSA_KEY_A, Some("key-a")))
            .await
            .expect("a conforming Keycloak access token must pass the strict policy");
    }

    #[tokio::test]
    async fn strict_policy_rejects_a_missing_audience() {
        let source = trusting_key_a();

        let result = decode_strict(&source, &signed_claims_token(&claims_without("aud"))).await;

        assert_invalid_audience(&result);
    }

    #[tokio::test]
    async fn strict_policy_rejects_an_untrusted_or_missing_issuer() {
        let source = trusting_key_a();
        let untrusted = claims_with(
            "iss",
            serde_json::json!("https://attacker.example/realms/test-realm"),
        );

        for claims in [untrusted, claims_without("iss")] {
            assert_invalid_issuer(&decode_strict(&source, &signed_claims_token(&claims)).await);
        }
    }

    #[tokio::test]
    async fn strict_policy_validates_not_before_with_leeway() {
        let source = trusting_key_a();
        let timestamp = validation_time().unix_timestamp();

        let within_leeway = claims_with("nbf", serde_json::json!(timestamp + 60));
        decode_strict(&source, &signed_claims_token(&within_leeway))
            .await
            .expect("an nbf within the clock-skew leeway must be accepted");

        let immature = claims_with("nbf", serde_json::json!(timestamp + 61));
        assert_immature(&decode_strict(&source, &signed_claims_token(&immature)).await);
    }

    #[tokio::test]
    async fn strict_policy_owns_expiry_leeway_without_changing_legacy_behavior() {
        let source = trusting_key_a();
        let timestamp = validation_time().unix_timestamp();
        let strict_validator = validator(
            source.clone(),
            strict_policy().build().expect("strict policy must build"),
            ManualClock::at_validation_time(),
        );

        let within_leeway = claims_with("exp", serde_json::json!(timestamp - 60));
        strict_validator
            .validate(&signed_claims_token(&within_leeway))
            .await
            .expect("strict expiry validation must accept the exact leeway boundary");

        let beyond_leeway = claims_with("exp", serde_json::json!(timestamp - 61));
        assert_expired(
            &strict_validator
                .validate(&signed_claims_token(&beyond_leeway))
                .await,
        );

        let legacy_validator = validator(
            source,
            legacy_policy().build().expect("legacy policy must build"),
            ManualClock::at_validation_time(),
        );
        let legacy_expired = claims_with("exp", serde_json::json!(timestamp - 1));
        let result = legacy_validator
            .validate(&signed_claims_token(&legacy_expired))
            .await;
        assert_that!(result).is_matching(pattern!(Err(AuthError::TokenExpired)));
    }

    #[tokio::test]
    async fn strict_policy_rejects_issued_at_beyond_leeway() {
        let source = trusting_key_a();
        let timestamp = validation_time().unix_timestamp();

        decode_strict(
            &source,
            &signed_claims_token(&claims_with("iat", serde_json::json!(timestamp + 60))),
        )
        .await
        .expect("an iat at the clock-skew boundary must be accepted");

        let result = decode_strict(
            &source,
            &signed_claims_token(&claims_with("iat", serde_json::json!(timestamp + 61))),
        )
        .await;
        assert_invalid_token(&result);
    }

    #[tokio::test]
    async fn issued_at_validation_is_configurable_and_fail_closed() {
        let source = trusting_key_a();

        let result = decode_strict(&source, &signed_claims_token(&claims_without("iat"))).await;
        assert_that!(result).is_matching(pattern!(
            Err(AuthError::Decode { source })
                if matches!(source.kind(), ErrorKind::MissingRequiredClaim(claim) if claim == "iat")
        ));

        let malformed = claims_with("iat", serde_json::json!({ "malformed": true }));
        let result = decode_strict(&source, &signed_claims_token(&malformed)).await;
        assert_invalid_token(&result);

        let future_token = signed_claims_token(&claims_with(
            "iat",
            serde_json::json!(validation_time().unix_timestamp() + 61),
        ));
        decode(
            &source,
            strict_policy()
                .validate_issued_at(false)
                .build()
                .expect("strict policy must build"),
            ManualClock::at_validation_time(),
            &future_token,
        )
        .await
        .expect("disabling issued-at validation must retain the builder's opt-out");

        decode_legacy(&source, &future_token)
            .await
            .expect("the legacy preset must retain its historical lack of issued-at validation");

        let result = decode(
            &source,
            legacy_policy()
                .validate_issued_at(true)
                .build()
                .expect("legacy policy with issued-at validation must build"),
            ManualClock::at_validation_time(),
            &future_token,
        )
        .await;
        assert_invalid_token(&result);
    }

    #[tokio::test]
    async fn a_malformed_not_before_claim_is_rejected() {
        let source = trusting_key_a();

        // jsonwebtoken rejects a non-integer object `nbf` while deserializing its internal
        // validation claims, under every policy.
        let object = claims_with("nbf", serde_json::json!({ "malformed": true }));
        let result = decode_strict(&source, &signed_claims_token(&object)).await;
        assert_that!(result).is_matching(pattern!(
            Err(AuthError::Decode { source })
                if matches!(source.kind(), ErrorKind::Json(_))
        ));

        // A string `nbf` passes jsonwebtoken's lenient claim parsing; the strict policy's own
        // malformed-`nbf` rejection is what fails it closed.
        let string = claims_with("nbf", serde_json::json!("tomorrow"));
        let result = decode_strict(&source, &signed_claims_token(&string)).await;
        assert_invalid_token(&result);
        decode_legacy(&source, &signed_claims_token(&string))
            .await
            .expect("the legacy policy does not validate nbf at all");
    }

    #[tokio::test]
    async fn strict_policy_rejects_a_disallowed_algorithm_without_a_refresh() {
        let source = trusting_key_a();
        let policy = strict_policy()
            .allowed_algorithms([Algorithm::RS256])
            .build()
            .expect("strict policy must build");
        // The unknown kid must not matter: the algorithm is rejected before any key material is
        // consulted, and no key refresh can make a disallowed algorithm acceptable.
        let token = RSA_KEY_A
            .sign(
                &keycloak_claims(validation_time()),
                Algorithm::RS384,
                Some("unknown-kid"),
            )
            .expect("test token must sign");

        let result = decode(&source, policy, ManualClock::at_validation_time(), &token).await;

        assert_invalid_algorithm(&result);
        assert_that!(source.refresh_requests()).is_equal_to(0);
    }

    // ----- Algorithm confusion (key-family binding) ------------------------------------------

    /// A realm serving an EC key, and a token forged with nothing but that realm's public JWKS
    /// data. The published curve point is exactly the byte string a `DecodingKey` built from the
    /// JWK holds, so an `HS256` header asks for it to be used as an HMAC secret: the "signature"
    /// then verifies against key material anyone can fetch. The default policy must reject this,
    /// or any reader of the JWKS could mint tokens with arbitrary claims and roles.
    #[tokio::test]
    async fn default_policy_rejects_hs256_forged_with_the_public_ec_point() {
        let source = StaticKeySource::new(vec![ec_key("ec-key")]);
        let forged = forged_hs256_token("ec-key", &EC_KEY_A.public_point());

        // The forgery is genuinely dangerous: HMAC-verified against the realm's own published key
        // material, this signature checks out. Asserting that here keeps the rejection below
        // meaningful; without it, a fixture or helper that stopped producing the real public point
        // would leave a token that every implementation rejects, and the test would pass while
        // proving nothing.
        let (message, signature) = forged.rsplit_once('.').expect("the forgery must be a JWT");
        let published_key = jsonwebtoken::DecodingKey::from_jwk(&ec_key("ec-key"))
            .expect("the published EC JWK must decode");
        assert_that!(jsonwebtoken::crypto::verify(
            signature,
            message.as_bytes(),
            &published_key,
            Algorithm::HS256,
        ))
        .ok()
        .is_true();

        let result = decode_legacy(&source, &forged).await;

        assert_invalid_algorithm(&result);
        // The key the forgery names exists and is trusted; it is the algorithm binding that
        // refuses it, and a known kid earns no refresh.
        assert_that!(source.refresh_requests()).is_equal_to(0);
    }

    /// The same forgery, against the far more common RSA realm. Here the verifier cannot even be
    /// reached: an `HS256` header against RSA key material used to reach an accessor that the key
    /// type does not support, which panicked inside `jsonwebtoken` on the request future rather
    /// than returning an error. This asserts a rejection, and thereby also that it returns at all.
    #[tokio::test]
    async fn default_policy_rejects_hs256_against_an_rsa_realm_without_panicking() {
        let source = trusting_key_a();
        let forged = forged_hs256_token("key-a", b"attacker-chosen-secret");

        let result = decode_legacy(&source, &forged).await;

        assert_invalid_algorithm(&result);
        assert_that!(source.refresh_requests()).is_equal_to(0);
    }

    /// Cross-family confusion is not limited to symmetric algorithms: an `ES256` header against an
    /// RSA realm names an algorithm the trusted key may not verify, and reached the same
    /// unsupported accessor. Since `ES256` is asymmetric, no algorithm allowlist of asymmetric
    /// families would catch it. Only binding the algorithm to the verifying key's family does.
    #[tokio::test]
    async fn default_policy_rejects_a_cross_family_asymmetric_algorithm_without_panicking() {
        let source = trusting_key_a();
        // Signed with a real EC key, so only the key family mismatch can reject it.
        let token = EC_KEY_A
            .sign(
                &keycloak_claims(validation_time()),
                Algorithm::ES256,
                Some("key-a"),
            )
            .expect("the EC fixture must sign");

        let result = decode_legacy(&source, &token).await;

        assert_invalid_algorithm(&result);
        assert_that!(source.refresh_requests()).is_equal_to(0);
    }

    /// An unknown `kid` earns one rate-limited refresh, whatever family the token names: the
    /// realm may have rotated to a key family the cached set does not contain yet. When the
    /// refresh does not help, the family mismatch is still what rejects the token.
    #[tokio::test]
    async fn a_cross_family_algorithm_with_an_unknown_kid_is_rejected_after_its_refresh() {
        let source = trusting_key_a();
        let token = EC_KEY_A
            .sign(
                &keycloak_claims(validation_time()),
                Algorithm::ES256,
                Some("unknown-kid"),
            )
            .expect("the EC fixture must sign");

        let result = decode_legacy(&source, &token).await;

        assert_invalid_algorithm(&result);
        assert_that!(source.refresh_requests()).is_equal_to(1);
    }

    /// The forged-HMAC case with an unknown `kid`, which takes the all-keys path instead of an
    /// exact `kid` match. The algorithm binding must still refuse it against every trusted key,
    /// before and after the one refresh the unknown `kid` earns.
    #[tokio::test]
    async fn an_hmac_forgery_with_an_unknown_kid_is_rejected_after_its_refresh() {
        let source = StaticKeySource::new(vec![ec_key("ec-key")]);
        let forged = forged_hs256_token("unknown-kid", &EC_KEY_A.public_point());

        let result = decode_legacy(&source, &forged).await;

        assert_invalid_algorithm(&result);
        assert_that!(source.refresh_requests()).is_equal_to(1);
    }

    /// The guard rejects only what it must: a realm serving an EC key still validates the genuine
    /// `ES256` tokens that realm signs.
    #[tokio::test]
    async fn default_policy_accepts_a_genuine_es256_token_from_an_ec_realm() {
        let source = StaticKeySource::new(vec![ec_key("ec-key")]);
        let token = EC_KEY_A
            .sign(
                &keycloak_claims(validation_time()),
                Algorithm::ES256,
                Some("ec-key"),
            )
            .expect("the EC fixture must sign");

        let claims = decode_legacy(&source, &token)
            .await
            .expect("a genuine ES256 token from the realm's own key must validate");

        assert_that!(claims).contains_entry("sub", serde_json::json!("test-subject"));
    }

    // ----- Further policy requirements --------------------------------------------------------

    #[tokio::test]
    async fn strict_policy_rejects_non_access_token_types() {
        let source = trusting_key_a();
        let mut substitutions = ["ID", "Refresh", "Offline", "Logout", "Serialized-ID"]
            .map(|token_type| claims_with("typ", serde_json::json!(token_type)))
            .to_vec();
        substitutions.push(claims_without("typ"));

        for claims in substitutions {
            let result = decode_strict(&source, &signed_claims_token(&claims)).await;
            assert_invalid_token(&result);
        }
    }

    #[tokio::test]
    async fn allowed_authorized_parties_are_enforced_when_configured() {
        let source = trusting_key_a();
        let token = signed_token(&RSA_KEY_A, Some("key-a"));

        let allowing = strict_policy()
            .allowed_authorized_parties(["test-client"])
            .build()
            .expect("policy must build");
        decode(&source, allowing, ManualClock::at_validation_time(), &token)
            .await
            .expect("the fixture azp must be accepted when listed");

        let rejecting = strict_policy()
            .allowed_authorized_parties(["other-client"])
            .build()
            .expect("policy must build");
        let result = decode(
            &source,
            rejecting,
            ManualClock::at_validation_time(),
            &token,
        )
        .await;
        assert_invalid_token(&result);
    }

    #[tokio::test]
    async fn required_claims_are_enforced_by_name() {
        let source = trusting_key_a();
        let policy = legacy_policy()
            .required_claims(["sid"])
            .build()
            .expect("policy must build");

        let result = decode(
            &source,
            policy.clone(),
            ManualClock::at_validation_time(),
            &signed_token(&RSA_KEY_A, Some("key-a")),
        )
        .await;
        assert_that!(result).is_matching(pattern!(
            Err(AuthError::Decode { source })
                if matches!(source.kind(), ErrorKind::MissingRequiredClaim(claim) if claim == "sid")
        ));

        decode(
            &source,
            policy,
            ManualClock::at_validation_time(),
            &signed_claims_token(&claims_with("sid", serde_json::json!("test-session"))),
        )
        .await
        .expect("a present required claim must be accepted");
    }

    #[tokio::test]
    async fn expiry_transit_margin_rejects_tokens_expiring_too_soon() {
        let source = trusting_key_a();
        // Keep the margin below the default 60-second leeway to prove the two checks are
        // independent: the margin requires `exp >= now + margin` regardless of leeway.
        let policy = legacy_policy()
            .expiry_transit_margin(Duration::from_secs(30))
            .build()
            .expect("policy must build");
        let validator = validator(source, policy, ManualClock::at_validation_time());
        let timestamp = validation_time().unix_timestamp();

        validator
            .validate(&signed_claims_token(&claims_with(
                "exp",
                serde_json::json!(timestamp + 30),
            )))
            .await
            .expect("a token expiring exactly at the transit boundary must be accepted");

        assert_expired(
            &validator
                .validate(&signed_claims_token(&claims_with(
                    "exp",
                    serde_json::json!(timestamp + 29),
                )))
                .await,
        );
    }

    #[tokio::test]
    async fn leeway_is_configurable() {
        let source = trusting_key_a();
        let token = signed_claims_token(&claims_with(
            "exp",
            serde_json::json!(validation_time().unix_timestamp() - 1),
        ));

        let default_leeway = legacy_policy().build().expect("policy must build");
        decode(
            &source,
            default_leeway,
            ManualClock::at_validation_time(),
            &token,
        )
        .await
        .expect("the default 60 second leeway must pass this decode stage");

        let no_leeway = legacy_policy()
            .leeway(Duration::ZERO)
            .build()
            .expect("policy must build");
        let result = decode(
            &source,
            no_leeway,
            ManualClock::at_validation_time(),
            &token,
        )
        .await;
        assert_expired(&result);
    }

    #[tokio::test]
    async fn a_malformed_exp_claim_is_rejected_as_unauthorized() {
        let source = trusting_key_a();

        // A float `exp` passes jsonwebtoken's required-claim presence check, so the policy's own
        // expiry check must fail closed here; reaching the typed claim model instead would report
        // an internal error (500) rather than an unauthorized token (401).
        let float_exp = signed_claims_token(&claims_with("exp", serde_json::json!(1.5)));
        assert_invalid_token(&decode_legacy(&source, &float_exp).await);
        assert_invalid_token(&decode_strict(&source, &float_exp).await);

        // A string `exp` never reaches the policy: jsonwebtoken treats it as absent.
        let string_exp = signed_claims_token(&claims_with("exp", serde_json::json!("tomorrow")));
        assert_that!(decode_legacy(&source, &string_exp).await).is_matching(pattern!(
            Err(AuthError::Decode { source })
                if matches!(source.kind(), ErrorKind::MissingRequiredClaim(claim) if claim == "exp")
        ));
    }

    #[tokio::test]
    async fn sub_second_durations_are_rounded_up_to_whole_seconds() {
        let source = trusting_key_a();
        let timestamp = validation_time().unix_timestamp();

        // A sub-second transit margin must behave as one whole second, not silently disable the
        // check (JWT time claims have whole-second resolution).
        let margin = legacy_policy()
            .expiry_transit_margin(Duration::from_millis(900))
            .build()
            .expect("policy must build");
        let margin_validator = validator(source.clone(), margin, ManualClock::at_validation_time());
        margin_validator
            .validate(&signed_claims_token(&claims_with(
                "exp",
                serde_json::json!(timestamp + 1),
            )))
            .await
            .expect("one whole second of remaining lifetime must satisfy a 900ms margin");
        assert_expired(
            &margin_validator
                .validate(&signed_claims_token(&claims_with(
                    "exp",
                    serde_json::json!(timestamp),
                )))
                .await,
        );

        // A sub-second leeway must behave as one whole second rather than as zero.
        let leeway = legacy_policy()
            .leeway(Duration::from_millis(500))
            .build()
            .expect("policy must build");
        decode(
            &source,
            leeway.clone(),
            ManualClock::at_validation_time(),
            &signed_claims_token(&claims_with("exp", serde_json::json!(timestamp - 1))),
        )
        .await
        .expect("an exp one second in the past must pass a 500ms leeway rounded up");
        assert_expired(
            &decode(
                &source,
                leeway,
                ManualClock::at_validation_time(),
                &signed_claims_token(&claims_with("exp", serde_json::json!(timestamp - 2))),
            )
            .await,
        );
    }

    // ----- Typed claims, roles, logging, auto traits ------------------------------------------

    #[tokio::test]
    async fn typed_extra_claims_parse_with_and_without_raw_claim_persistence() {
        let source = trusting_key_a();
        let token = signed_token(&RSA_KEY_A, Some("key-a"));

        for persist_raw_claims in [false, true] {
            let validator: Validator<String, ProfileAndEmail, StaticKeySource> =
                Validator::builder()
                    .key_source(source.clone())
                    .policy(legacy_policy().build().expect("the test policy must build"))
                    .required_roles(vec![String::from("developer"), String::from("reader")])
                    .persist_raw_claims(persist_raw_claims)
                    .clock(ManualClock::at_validation_time())
                    .build();

            let validated = validator
                .validate(&token)
                .await
                .expect("the fixture token must satisfy the typed claim model and both roles");
            let validated = assert_that!(validated);
            let raw_claims = validated.derive(|it| &it.raw_claims);
            if persist_raw_claims {
                raw_claims.is_some();
            } else {
                raw_claims.is_none();
            }
            validated
                .derive(|it| &it.token.extra.profile.preferred_username)
                .is_equal_to("test-user");
            validated
                .derive(|it| &it.token.extra.email.email)
                .is_equal_to("test@example.com");
        }

        let rejecting = Validator::<String, ProfileAndEmail, StaticKeySource>::builder()
            .key_source(source)
            .policy(legacy_policy().build().expect("the test policy must build"))
            .required_roles(vec![String::from("missing-role")])
            .persist_raw_claims(false)
            .clock(ManualClock::at_validation_time())
            .build();
        assert_that!(rejecting.validate(&token).await).is_matching(pattern!(
            Err(AuthError::MissingExpectedRole { role }) if role == "missing-role"
        ));
    }

    /// A complete validation, under the most verbose log level, writes neither the token nor any
    /// claim value to the logs unless raw-claim logging was explicitly opted into.
    #[tokio::test]
    async fn validation_logs_no_token_or_claims_without_the_explicit_sensitive_data_opt_in() {
        let source = trusting_key_a();
        let token = signed_token(&RSA_KEY_A, Some("key-a"));

        for raw_claims_log_level in [
            None,
            Some(tracing::Level::DEBUG),
            Some(tracing::Level::INFO),
        ] {
            let logs = CapturedLogs::default();
            let validator = Validator::<String, ProfileAndEmail, StaticKeySource>::builder()
                .key_source(source.clone())
                .policy(legacy_policy().build().expect("the test policy must build"))
                .required_roles(Vec::new())
                .persist_raw_claims(true)
                .raw_claims_log_level(raw_claims_log_level)
                .unverified_jwt_header_logging(Some(UnverifiedJwtHeaderLogging::Metadata(
                    tracing::Level::DEBUG,
                )))
                .clock(ManualClock::at_validation_time())
                .build();

            let validated = {
                let _capture = logs.capture();
                validator.validate(&token).await
            };
            validated.expect("the fixture token must validate");

            let contents = logs.contents();
            let log_raw_claims = raw_claims_log_level.is_some();
            assert_that!(contents)
                .with_subject_name("logs are captured at all")
                .contains("Decoded unverified JWT header");
            assert_that!(contents)
                .with_subject_name("the raw token never appears in logs")
                .does_not_contain(&token);
            assert_logged_iff(
                &contents,
                "test@example.com",
                log_raw_claims,
                format!("claims logged with opt-in = {log_raw_claims}"),
            );
            assert_logged_iff(
                &contents,
                "sensitive data logging explicitly enabled",
                log_raw_claims,
                format!("raw-claims opt-in notice logged with opt-in = {log_raw_claims}"),
            );
            if let Some(level) = raw_claims_log_level {
                assert_that!(
                    logs.event_containing("sensitive data logging explicitly enabled")
                        .level()
                )
                .with_subject_name("configured raw-claims log level")
                .is_equal_to(level);
            }
        }
    }

    #[tokio::test]
    async fn unverified_jwt_header_logging_controls_content_and_level() {
        let source = trusting_key_a();
        let signed_token = signed_token(&RSA_KEY_A, Some("key-a"));
        let mut attacker_controlled_header = Header::new(Algorithm::RS256);
        attacker_controlled_header.kid = Some(String::from("key-a"));
        attacker_controlled_header.typ = Some(String::from("selected-typ-marker"));
        attacker_controlled_header.jku = Some(String::from("suppressed-jku-marker"));
        attacker_controlled_header.x5c = Some(vec![String::from("suppressed-x5c-marker")]);
        let (_, claims_and_signature) = signed_token
            .split_once('.')
            .expect("the signed fixture token must have a header segment");
        let encoded_header = URL_SAFE_NO_PAD.encode(
            serde_json::to_vec(&attacker_controlled_header)
                .expect("the attacker-controlled header must serialize"),
        );
        let token = format!("{encoded_header}.{claims_and_signature}");

        for logging in [
            None,
            Some(UnverifiedJwtHeaderLogging::Metadata(tracing::Level::INFO)),
            Some(UnverifiedJwtHeaderLogging::Complete(tracing::Level::DEBUG)),
            Some(UnverifiedJwtHeaderLogging::Complete(tracing::Level::INFO)),
        ] {
            let logs = CapturedLogs::default();
            let validator = Validator::<String, ProfileAndEmail, StaticKeySource>::builder()
                .key_source(source.clone())
                .policy(legacy_policy().build().expect("the test policy must build"))
                .required_roles(Vec::new())
                .persist_raw_claims(false)
                .unverified_jwt_header_logging(logging)
                .clock(ManualClock::at_validation_time())
                .build();

            let result = {
                let _capture = logs.capture();
                validator.validate(&token).await
            };
            assert_that!(result).is_matching(pattern!(Err(AuthError::Decode { source }) if
                matches!(source.kind(), ErrorKind::InvalidSignature)
            ));

            let contents = logs.contents();
            let log_complete_header =
                matches!(logging, Some(UnverifiedJwtHeaderLogging::Complete(_)));
            assert_that!(contents)
                .with_subject_name("the raw token never appears in logs")
                .does_not_contain(&token);
            assert_logged_iff(
                &contents,
                "suppressed-jku-marker",
                log_complete_header,
                "the attacker-controlled jku is logged only with opt-in",
            );
            assert_logged_iff(
                &contents,
                "suppressed-x5c-marker",
                log_complete_header,
                "the attacker-controlled x5c is logged only with opt-in",
            );
            assert_logged_iff(
                &contents,
                "attacker-controlled header logging explicitly enabled",
                log_complete_header,
                "the complete-header opt-in notice is logged only with opt-in",
            );
            match logging {
                None => {
                    assert_that!(contents).does_not_contain("unverified JWT header");
                }
                Some(UnverifiedJwtHeaderLogging::Metadata(level)) => {
                    assert_header_event_level(&logs, level);
                    let event = logs.event_containing("Decoded unverified JWT header");
                    assert_that!(event.field("alg")).is_equal_to(Some("RS256"));
                    assert_that!(event.field("kid")).is_equal_to(Some("Some(\"key-a\")"));
                    assert_that!(event.field("typ"))
                        .is_equal_to(Some("Some(\"selected-typ-marker\")"));
                }
                Some(UnverifiedJwtHeaderLogging::Complete(level)) => {
                    assert_header_event_level(&logs, level);
                }
            }
        }
    }

    #[track_caller]
    fn assert_header_event_level(logs: &CapturedLogs, level: tracing::Level) {
        assert_that!(logs.event_containing("unverified JWT header").level())
            .with_subject_name("configured unverified-header log level")
            .is_equal_to(level);
    }

    #[derive(Clone, serde::Deserialize)]
    struct NonSendExtra(PhantomData<Rc<()>>);

    #[test]
    fn validator_auto_traits_do_not_depend_on_extra() {
        fn assert_send_and_sync<T: Send + Sync>() {}

        assert_send_and_sync::<Validator<String, NonSendExtra>>();
    }
}
