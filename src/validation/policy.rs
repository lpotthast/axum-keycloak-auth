//! Validation policy presets, builder configuration, and claim checks.

use std::time::Duration;

use jsonwebtoken::Algorithm;

use crate::{
    error::{AuthError, ValidationPolicyError},
    token::RawClaims,
};

use super::decode_error;

/// Requirements applied to every presented token.
///
/// Create a policy from one of the presets, adjust it with [`ValidationPolicyBuilder`], and attach
/// it to a [`crate::layer::KeycloakAuthLayer`]:
///
/// - [`ValidationPolicy::legacy`] preserves historical behavior and is the default.
/// - [`ValidationPolicy::strict`] enables stricter issuer, audience, algorithm, token-type, and
///   time checks.
///
/// The policy is enforced identically by the Axum middleware and by
/// [`crate::layer::KeycloakAuthLayer::validate_raw_token`].
#[derive(Debug, Clone)]
pub struct ValidationPolicy {
    /// The audiences accepted by the `aud` check. `None` inherits the `expected_audiences`
    /// configured on the layer, which is where audiences have historically been configured.
    expected_audiences: Option<Vec<String>>,
    require_audience: bool,
    expected_issuers: Vec<String>,
    allowed_algorithms: Option<Vec<Algorithm>>,
    required_claims: Vec<String>,
    accepted_token_types: Option<Vec<String>>,
    validate_not_before: bool,
    validate_issued_at: bool,
    leeway: Duration,
    expiry_transit_margin: Duration,
    allowed_authorized_parties: Option<Vec<String>>,
    expiry_semantics: ExpirySemantics,
}

/// Whether expiry uses the two-stage legacy behavior or only the policy's leeway-aware check.
#[derive(Debug, Clone, Copy)]
enum ExpirySemantics {
    LegacySecondCheck,
    PolicyOwned,
}

impl ValidationPolicy {
    /// Preserves this crate's historical validation behavior.
    ///
    /// Tokens are signature-verified against discovered keys and must contain `exp`. A present
    /// string or string-array `aud` claim must match a configured audience. A missing `aud` is
    /// accepted, while a malformed one fails typed-claim parsing. The preset does not restrict
    /// `iss`, payload `typ`, or algorithms, and does not validate `nbf` or future `iat`. Signature
    /// verification still requires a key from the algorithm's family. The built-in token model
    /// requires `exp`, `iat`, `jti`, `iss`, `sub`, `typ`, and `azp`.
    ///
    /// The historical pipeline applies 60 seconds of leeway during claim validation and then
    /// checks the typed token's expiry without leeway. The final acceptance boundary therefore
    /// rejects a token once its `exp` is in the past. Use [`Self::strict`] to apply leeway to the
    /// final expiry decision.
    ///
    /// This is the default preset. It fails to build only when the builder adds inconsistent
    /// requirements.
    pub fn legacy() -> ValidationPolicyBuilder {
        ValidationPolicyBuilder {
            policy: Self {
                expected_audiences: None,
                require_audience: false,
                expected_issuers: Vec::new(),
                allowed_algorithms: None,
                required_claims: Vec::new(),
                accepted_token_types: None,
                validate_not_before: false,
                validate_issued_at: false,
                leeway: Duration::from_secs(60),
                expiry_transit_margin: Duration::ZERO,
                allowed_authorized_parties: None,
                expiry_semantics: ExpirySemantics::LegacySecondCheck,
            },
            require_issuer: false,
        }
    }

    /// Stricter defaults for deployments that can state their expectations explicitly.
    ///
    /// Compared to [`ValidationPolicy::legacy`], this preset:
    ///
    /// - Validates the `iss` claim. [`ValidationPolicyBuilder::expected_issuers`] must name at
    ///   least one exact realm issuer, commonly `https://host/realms/<realm>`. Otherwise,
    ///   [`ValidationPolicyBuilder::build`] fails.
    /// - Requires a matching audience. A token with a missing, malformed, or unlisted `aud` claim
    ///   is rejected. Configure an audience protocol mapper on your Keycloak client if its tokens
    ///   do not carry the expected audience.
    /// - Allows `RS256`, `RS384`, `RS512`, `PS256`, `PS384`, `PS512`, `ES256`, `ES384`, and `EdDSA`.
    ///   Narrow this with [`ValidationPolicyBuilder::allowed_algorithms`] when the realm uses fewer
    ///   algorithms.
    /// - Requires the payload `typ` claim to be exactly `Bearer`. This is distinct from the JWT
    ///   header parameter of the same name.
    /// - Validates the optional `nbf` (not before) claim and requires `iat` (issued at) not to lie
    ///   further in the future than the clock-skew leeway allows.
    /// - Applies `exp`, `nbf`, and `iat` checks against one captured time and one leeway.
    ///
    /// Expected audiences may stay unset so the policy inherits the layer's `expected_audiences`.
    /// The 60-second clock-skew leeway of the legacy preset is retained and can be tuned
    /// with [`ValidationPolicyBuilder::leeway`].
    ///
    /// The built-in token model requires `exp`, `iat`, `jti`, `iss`, `sub`, `typ`, and `azp`. This
    /// preset does not provide `jti` replay detection and leaves the `azp` allowlist unset.
    pub fn strict() -> ValidationPolicyBuilder {
        ValidationPolicyBuilder {
            policy: Self {
                expected_audiences: None,
                require_audience: true,
                expected_issuers: Vec::new(),
                allowed_algorithms: Some(vec![
                    Algorithm::RS256,
                    Algorithm::RS384,
                    Algorithm::RS512,
                    Algorithm::PS256,
                    Algorithm::PS384,
                    Algorithm::PS512,
                    Algorithm::ES256,
                    Algorithm::ES384,
                    Algorithm::EdDSA,
                ]),
                required_claims: Vec::new(),
                accepted_token_types: Some(vec![String::from("Bearer")]),
                validate_not_before: true,
                validate_issued_at: true,
                leeway: Duration::from_secs(60),
                expiry_transit_margin: Duration::ZERO,
                allowed_authorized_parties: None,
                expiry_semantics: ExpirySemantics::PolicyOwned,
            },
            require_issuer: true,
        }
    }

    /// Binds the layer's `expected_audiences` as this policy's audiences when the policy does not
    /// define its own. Audiences have historically been configured on the layer.
    pub(crate) fn with_inherited_audiences(mut self, expected_audiences: &[String]) -> Self {
        if self.expected_audiences.is_none() {
            self.expected_audiences = Some(expected_audiences.to_vec());
        }
        self
    }

    /// Returns this policy's audiences when they differ as a set from the layer's non-empty
    /// `expected_audiences`. The layer uses this to warn about ignored configuration.
    pub(crate) fn audiences_conflicting_with(
        &self,
        layer_audiences: &[String],
    ) -> Option<&[String]> {
        if layer_audiences.is_empty() {
            return None;
        }
        self.expected_audiences.as_deref().filter(|own| {
            !(own
                .iter()
                .all(|audience| layer_audiences.contains(audience))
                && layer_audiences
                    .iter()
                    .all(|audience| own.contains(audience)))
        })
    }

    /// Rejects header algorithms outside the configured allowlist. Checked before any key material
    /// is consulted. No key refresh can make a disallowed algorithm acceptable.
    ///
    /// This is a configurable narrowing, not the crate's safety boundary. What a token's header
    /// algorithm may never do is choose the verifier. Signature verification binds the algorithm
    /// to the family of the key that verifies it, so a token cannot have published asymmetric key
    /// material treated as a shared HMAC secret regardless of what any allowlist permits.
    pub(crate) fn check_algorithm(&self, algorithm: Algorithm) -> Result<(), AuthError> {
        match &self.allowed_algorithms {
            Some(allowed) if !allowed.contains(&algorithm) => Err(decode_error(
                jsonwebtoken::errors::ErrorKind::InvalidAlgorithm,
            )),
            _ => Ok(()),
        }
    }

    /// Runs every claim-based check of this policy against the signature-verified claims,
    /// measured against the single captured validation time. Expiry runs before the audience
    /// check to preserve the historical error identity of expired tokens. All further checks can
    /// only reject what the plain legacy preset never rejected.
    pub(crate) fn check_claims(
        &self,
        claims: &RawClaims,
        validation_time: time::OffsetDateTime,
    ) -> Result<(), AuthError> {
        check_expiration(
            claims,
            validation_time,
            self.leeway,
            self.expiry_transit_margin,
        )?;
        if self.validate_not_before {
            check_not_before(claims, validation_time, self.leeway)?;
        }
        if self.validate_issued_at {
            check_issued_at(claims, validation_time, self.leeway)?;
        }
        if !self.token_has_expected_audience(claims) {
            return Err(decode_error(
                jsonwebtoken::errors::ErrorKind::InvalidAudience,
            ));
        }
        if !self.token_has_expected_issuer(claims) {
            return Err(decode_error(jsonwebtoken::errors::ErrorKind::InvalidIssuer));
        }
        if !self.token_has_accepted_type(claims) {
            return Err(AuthError::InvalidToken {
                reason: String::from("The token's 'typ' claim is not an accepted token type."),
            });
        }
        if !self.token_has_allowed_authorized_party(claims) {
            return Err(AuthError::InvalidToken {
                reason: String::from("The token's 'azp' claim is not an allowed authorized party."),
            });
        }
        if let Some(missing) = self.first_missing_required_claim(claims) {
            return Err(decode_error(
                jsonwebtoken::errors::ErrorKind::MissingRequiredClaim(missing),
            ));
        }
        Ok(())
    }

    /// Whether the typed token needs the legacy second expiry check without leeway.
    pub(super) fn wants_legacy_second_expiry_check(&self) -> bool {
        matches!(self.expiry_semantics, ExpirySemantics::LegacySecondCheck)
    }

    pub(crate) fn requires_audience_but_has_none(&self) -> bool {
        self.require_audience
            && self
                .expected_audiences
                .as_deref()
                .is_none_or(<[String]>::is_empty)
    }

    fn token_has_expected_audience(&self, claims: &RawClaims) -> bool {
        let expected_audiences = self.expected_audiences.as_deref().unwrap_or(&[]);
        match claims.get("aud") {
            Some(serde_json::Value::String(audience)) => expected_audiences
                .iter()
                .any(|expected| expected == audience),
            Some(serde_json::Value::Array(audiences))
                if audiences.iter().all(serde_json::Value::is_string) =>
            {
                audiences.iter().any(|audience| {
                    audience.as_str().is_some_and(|audience| {
                        expected_audiences
                            .iter()
                            .any(|expected| expected == audience)
                    })
                })
            }
            // A missing or malformed audience passes the legacy raw-claim check (matching
            // jsonwebtoken). Typed parsing later rejects malformed values. A policy that requires
            // an audience rejects both cases here.
            _ => !self.require_audience,
        }
    }

    fn token_has_expected_issuer(&self, claims: &RawClaims) -> bool {
        if self.expected_issuers.is_empty() {
            return true;
        }
        claims
            .get("iss")
            .and_then(serde_json::Value::as_str)
            .is_some_and(|issuer| {
                self.expected_issuers
                    .iter()
                    .any(|expected| expected == issuer)
            })
    }

    fn token_has_accepted_type(&self, claims: &RawClaims) -> bool {
        let Some(accepted_token_types) = &self.accepted_token_types else {
            return true;
        };
        claims
            .get("typ")
            .and_then(serde_json::Value::as_str)
            .is_some_and(|token_type| {
                accepted_token_types
                    .iter()
                    .any(|accepted| accepted == token_type)
            })
    }

    fn token_has_allowed_authorized_party(&self, claims: &RawClaims) -> bool {
        let Some(allowed_authorized_parties) = &self.allowed_authorized_parties else {
            return true;
        };
        claims
            .get("azp")
            .and_then(serde_json::Value::as_str)
            .is_some_and(|authorized_party| {
                allowed_authorized_parties
                    .iter()
                    .any(|allowed| allowed == authorized_party)
            })
    }

    fn first_missing_required_claim(&self, claims: &RawClaims) -> Option<String> {
        self.required_claims
            .iter()
            .find(|claim| !claims.contains_key(claim.as_str()))
            .cloned()
    }
}

impl Default for ValidationPolicy {
    fn default() -> Self {
        Self::legacy()
            .build()
            .expect("the plain legacy validation policy preset must always build")
    }
}

/// Builds a [`ValidationPolicy`] and checks its requirements for consistency.
///
/// Create one through [`ValidationPolicy::legacy`] or [`ValidationPolicy::strict`].
#[must_use]
#[derive(Debug, Clone)]
pub struct ValidationPolicyBuilder {
    policy: ValidationPolicy,
    require_issuer: bool,
}

impl ValidationPolicyBuilder {
    /// Audiences accepted by exact string match. If unset, the policy inherits the layer's
    /// `expected_audiences`.
    pub fn expected_audiences(mut self, expected_audiences: Vec<String>) -> Self {
        self.policy.expected_audiences = Some(expected_audiences);
        self
    }

    /// Whether a token must carry a matching `aud` claim. When disabled, a missing claim is
    /// accepted. A present string or string-array claim must still match, and the built-in token
    /// model rejects other value types during typed-claim parsing.
    pub fn require_audience(mut self, require_audience: bool) -> Self {
        self.policy.require_audience = require_audience;
        self
    }

    /// The issuers accepted by the `iss` claim check, compared by exact string match. For a
    /// Keycloak realm this is commonly `https://host/realms/<realm>`. An empty list disables the
    /// allowlist, except under [`ValidationPolicy::strict`], where at least one issuer must be
    /// named. The built-in token model always requires `iss` to be a string.
    pub fn expected_issuers(mut self, expected_issuers: Vec<String>) -> Self {
        self.policy.expected_issuers = expected_issuers;
        self
    }

    /// Restricts the accepted token signature algorithms. A token whose header names an
    /// algorithm outside this list is rejected before any key material is consulted.
    pub fn allowed_algorithms(mut self, allowed_algorithms: Vec<Algorithm>) -> Self {
        self.policy.allowed_algorithms = Some(allowed_algorithms);
        self
    }

    /// Removes the policy-level algorithm allowlist, matching legacy behavior.
    ///
    /// Signature verification still requires a discovered key from the algorithm's key family.
    /// Published asymmetric key material cannot be used as an HMAC secret.
    pub fn allow_any_algorithm(mut self) -> Self {
        self.policy.allowed_algorithms = None;
        self
    }

    /// Claims that must be present in the token payload after signature verification.
    ///
    /// This checks keys, not value types, so a `null` value counts as present. `exp` is always
    /// required independently of this list.
    pub fn required_claims(mut self, required_claims: Vec<String>) -> Self {
        self.policy.required_claims = required_claims;
        self
    }

    /// Values accepted by exact, case-sensitive match for the payload `typ` claim. This is not the
    /// JWT header parameter of the same name. A missing, non-string, or unlisted value is rejected.
    pub fn accepted_token_types(mut self, accepted_token_types: Vec<String>) -> Self {
        self.policy.accepted_token_types = Some(accepted_token_types);
        self
    }

    /// Removes the policy-level token-type restriction.
    ///
    /// The built-in token model still requires the payload `typ` claim to be a string.
    pub fn allow_any_token_type(mut self) -> Self {
        self.policy.accepted_token_types = None;
        self
    }

    /// Whether the `nbf` (not before) claim is validated when present. A non-integer value or a
    /// timestamp further in the future than the clock-skew leeway allows is rejected.
    pub fn validate_not_before(mut self, validate_not_before: bool) -> Self {
        self.policy.validate_not_before = validate_not_before;
        self
    }

    /// Whether the `iat` (issued at) claim is required and validated. When enabled, a token whose
    /// `iat` lies further in the future than the clock-skew leeway allows is rejected. Enabled by
    /// [`ValidationPolicy::strict`] and disabled by [`ValidationPolicy::legacy`]. Disabling this
    /// time check does not make `iat` optional in the typed Keycloak token model.
    pub fn validate_issued_at(mut self, validate_issued_at: bool) -> Self {
        self.policy.validate_issued_at = validate_issued_at;
        self
    }

    /// Clock-skew leeway for the `exp`, `nbf`, and `iat` checks. Use
    /// [`Self::expiry_transit_margin`] when a token must remain valid after acceptance.
    ///
    /// A token is expired only when `exp` is more than this duration in the past. Enabled `nbf` and
    /// `iat` checks allow the same duration into the future. The default is 60 seconds. A
    /// sub-second component is rounded up because JWT time claims use whole seconds.
    ///
    /// Under [`ValidationPolicy::strict`], the policy owns expiry validation and applies this
    /// leeway end to end. [`ValidationPolicy::legacy`] preserves the historical second expiry
    /// check without leeway, so there this setting changes the expiry error rather than the final
    /// acceptance boundary.
    pub fn leeway(mut self, leeway: Duration) -> Self {
        self.policy.leeway = leeway;
        self
    }

    /// Minimum remaining token lifetime required when validation starts.
    ///
    /// A nonzero margin requires `exp >= now + margin`, so it intentionally dominates expiry
    /// leeway. Leeway still applies independently to `nbf` and `iat`. A zero margin disables this
    /// additional check and is the default. A sub-second component is rounded up to the next whole
    /// second because JWT time claims have whole-second resolution.
    pub fn expiry_transit_margin(mut self, expiry_transit_margin: Duration) -> Self {
        self.policy.expiry_transit_margin = expiry_transit_margin;
        self
    }

    /// Client IDs accepted by exact, case-sensitive match for the token's `azp` (authorized party)
    /// claim. A missing, non-string, or unlisted `azp` is rejected. The allowlist is unset by
    /// default, but the built-in token model always requires `azp` to be a string.
    pub fn allowed_authorized_parties(mut self, allowed_authorized_parties: Vec<String>) -> Self {
        self.policy.allowed_authorized_parties = Some(allowed_authorized_parties);
        self
    }

    /// Validates the configured requirements and builds the policy.
    ///
    /// # Errors
    ///
    /// Returns a [`ValidationPolicyError`] when the requirements are inconsistent: an
    /// issuer-validating policy without expected issuers, a required audience with explicitly
    /// empty expected audiences, or an explicitly empty algorithm, token-type, or
    /// authorized-party allowlist, each of which would reject every token.
    pub fn build(self) -> Result<ValidationPolicy, ValidationPolicyError> {
        if self.require_issuer && self.policy.expected_issuers.is_empty() {
            return Err(ValidationPolicyError::MissingExpectedIssuers);
        }
        if self.policy.require_audience
            && self
                .policy
                .expected_audiences
                .as_deref()
                .is_some_and(<[String]>::is_empty)
        {
            return Err(ValidationPolicyError::MissingExpectedAudiences);
        }
        if self
            .policy
            .allowed_algorithms
            .as_deref()
            .is_some_and(<[Algorithm]>::is_empty)
        {
            return Err(ValidationPolicyError::MissingAllowedAlgorithms);
        }
        if self
            .policy
            .accepted_token_types
            .as_deref()
            .is_some_and(<[String]>::is_empty)
        {
            return Err(ValidationPolicyError::MissingAcceptedTokenTypes);
        }
        if self
            .policy
            .allowed_authorized_parties
            .as_deref()
            .is_some_and(<[String]>::is_empty)
        {
            return Err(ValidationPolicyError::MissingAllowedAuthorizedParties);
        }
        Ok(self.policy)
    }
}

/// Checks an integer `exp` against the configured leeway and minimum remaining lifetime. A missing
/// claim is handled by `jsonwebtoken`'s required-claim check. A non-integer value is rejected here.
fn check_expiration(
    claims: &RawClaims,
    validation_time: time::OffsetDateTime,
    leeway: Duration,
    expiry_transit_margin: Duration,
) -> Result<(), AuthError> {
    let Some(expiration) = claims.get("exp") else {
        return Ok(());
    };
    let Some(expiration) = expiration.as_i64() else {
        return Err(AuthError::InvalidToken {
            reason: String::from("The token's 'exp' (expiration) claim is malformed."),
        });
    };
    let expiration = i128::from(expiration);
    let now = i128::from(validation_time.unix_timestamp());
    let leeway = whole_seconds_rounding_up(leeway);
    let transit_margin = whole_seconds_rounding_up(expiry_transit_margin);
    if expiration < now - leeway || (transit_margin != 0 && expiration < now + transit_margin) {
        return Err(decode_error(
            jsonwebtoken::errors::ErrorKind::ExpiredSignature,
        ));
    }
    Ok(())
}

/// Rounds a duration up to whole seconds so a nonzero sub-second setting remains effective.
fn whole_seconds_rounding_up(duration: Duration) -> i128 {
    i128::from(duration.as_secs()) + i128::from(duration.subsec_nanos() != 0)
}

/// Checks an optional integer `nbf` against the captured time and leeway.
fn check_not_before(
    claims: &RawClaims,
    validation_time: time::OffsetDateTime,
    leeway: Duration,
) -> Result<(), AuthError> {
    let Some(not_before) = claims.get("nbf") else {
        return Ok(());
    };
    let Some(not_before) = not_before.as_i64() else {
        return Err(AuthError::InvalidToken {
            reason: String::from("The token's 'nbf' (not before) claim is malformed."),
        });
    };
    let now = i128::from(validation_time.unix_timestamp());
    if i128::from(not_before) > now + whole_seconds_rounding_up(leeway) {
        return Err(decode_error(
            jsonwebtoken::errors::ErrorKind::ImmatureSignature,
        ));
    }
    Ok(())
}

/// Checks a required integer `iat` against the captured time and leeway. This does not impose a
/// maximum token age.
fn check_issued_at(
    claims: &RawClaims,
    validation_time: time::OffsetDateTime,
    leeway: Duration,
) -> Result<(), AuthError> {
    let Some(issued_at) = claims.get("iat") else {
        return Err(decode_error(
            jsonwebtoken::errors::ErrorKind::MissingRequiredClaim(String::from("iat")),
        ));
    };
    let Some(issued_at) = issued_at.as_i64() else {
        return Err(AuthError::InvalidToken {
            reason: String::from("The token's 'iat' (issued at) claim is malformed."),
        });
    };
    let now = i128::from(validation_time.unix_timestamp());
    if i128::from(issued_at) > now + whole_seconds_rounding_up(leeway) {
        return Err(AuthError::InvalidToken {
            reason: String::from("The token's 'iat' (issued at) claim lies too far in the future."),
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use assertr::prelude::*;

    use crate::{
        error::{AuthError, ValidationPolicyError},
        test_support::strict_policy,
    };

    use super::ValidationPolicy;

    #[test]
    fn policy_reports_only_audiences_conflicting_with_the_layer() {
        let layer_audiences = [String::from("account"), String::from("api")];

        let inheriting = ValidationPolicy::legacy()
            .build()
            .expect("the legacy preset must build");
        assert_that!(inheriting.audiences_conflicting_with(&layer_audiences)).is_none();

        let agreeing = ValidationPolicy::legacy()
            .expected_audiences(vec![String::from("api"), String::from("account")])
            .build()
            .expect("a legacy policy with audiences must build");
        assert_that!(agreeing.audiences_conflicting_with(&layer_audiences)).is_none();

        let overriding = ValidationPolicy::legacy()
            .expected_audiences(vec![String::from("other-service")])
            .build()
            .expect("a legacy policy with audiences must build");
        assert_that!(overriding.audiences_conflicting_with(&layer_audiences))
            .some()
            .contains_exactly(["other-service"]);

        // An empty layer value is not configuration being ignored: a policy-first setup has to
        // leave the required layer field empty, and must not be warned about.
        assert_that!(overriding.audiences_conflicting_with(&[])).is_none();
    }

    /// The algorithm allowlist is the policy's only algorithm control, and it is a narrowing
    /// knob rather than a safety boundary: `strict()` excludes the symmetric algorithms, an
    /// explicit list admits exactly what it names, and a policy with no list admits anything.
    /// What stops a token from choosing its own verifier is the key-family binding applied during
    /// signature verification, covered by the pipeline's algorithm-confusion regression tests.
    #[test]
    fn the_algorithm_allowlist_governs_which_algorithms_a_policy_admits() {
        use jsonwebtoken::{Algorithm, errors::ErrorKind};

        let rejects_invalid_algorithm = |result: Result<(), AuthError>| {
            assert_that!(result).is_matching(pattern!(
                Err(AuthError::Decode { source })
                    if matches!(source.kind(), ErrorKind::InvalidAlgorithm)
            ));
        };

        let strict = strict_policy()
            .build()
            .expect("the strict preset must build");
        rejects_invalid_algorithm(strict.check_algorithm(Algorithm::HS256));
        assert_that!(strict.check_algorithm(Algorithm::RS256)).is_ok();

        let explicit = ValidationPolicy::legacy()
            .allowed_algorithms(vec![Algorithm::RS256])
            .build()
            .expect("an explicit-allowlist policy must build");
        rejects_invalid_algorithm(explicit.check_algorithm(Algorithm::ES256));
        assert_that!(explicit.check_algorithm(Algorithm::RS256)).is_ok();

        // No allowlist admits every algorithm at this layer; the family binding rejects the ones
        // no trusted key may verify, which is what the pipeline tests assert end to end.
        let unrestricted = ValidationPolicy::legacy()
            .allow_any_algorithm()
            .build()
            .expect("an any-algorithm policy must build");
        assert_that!(unrestricted.check_algorithm(Algorithm::RS256)).is_ok();
        assert_that!(unrestricted.check_algorithm(Algorithm::ES256)).is_ok();
    }

    #[test]
    fn policy_construction_rejects_inconsistent_requirements() {
        assert_that!(ValidationPolicy::strict().build())
            .err()
            .is_equal_to(ValidationPolicyError::MissingExpectedIssuers);
        assert_that!(strict_policy().expected_audiences(Vec::new()).build())
            .err()
            .is_equal_to(ValidationPolicyError::MissingExpectedAudiences);
        assert_that!(
            ValidationPolicy::legacy()
                .allowed_algorithms(Vec::new())
                .build()
        )
        .err()
        .is_equal_to(ValidationPolicyError::MissingAllowedAlgorithms);
        assert_that!(
            ValidationPolicy::legacy()
                .accepted_token_types(Vec::new())
                .build()
        )
        .err()
        .is_equal_to(ValidationPolicyError::MissingAcceptedTokenTypes);
        assert_that!(
            ValidationPolicy::legacy()
                .allowed_authorized_parties(Vec::new())
                .build()
        )
        .err()
        .is_equal_to(ValidationPolicyError::MissingAllowedAuthorizedParties);
        assert_that!(ValidationPolicy::legacy().build()).is_ok();
        assert_that!(strict_policy().build()).is_ok();
    }
}
