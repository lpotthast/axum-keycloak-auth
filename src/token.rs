//! Raw and typed token claim representations.

use std::collections::HashMap;

use jsonwebtoken::Header;
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use serde_with::{OneOrMany, serde_as};
use snafu::ResultExt;

use crate::error::{AuthError, DecodeHeaderSnafu};
use crate::role::{ExpectRoles, ExtractRoles, KeycloakRole, NumRoles, Role};

/// JWT payload claims keyed by claim name.
///
/// When exposed by the middleware or [`crate::layer::KeycloakAuthLayer::validate_raw_token`], the
/// map has passed signature, policy, typed-claim, and required-role validation. Its individual
/// values remain untyped.
pub type RawClaims = HashMap<String, serde_json::Value>;

/// An unverified compact JWT extracted from a request.
pub(crate) struct RawToken<'a>(pub(crate) &'a str);

impl RawToken<'_> {
    /// Returns the **untrusted** token header. Assume that an attacker might have modified these
    /// values.
    ///
    /// Returns an error if the token is not a valid compact JWT.
    pub(crate) fn decode_header(&self) -> Result<Header, AuthError> {
        jsonwebtoken::decode_header(self.0).context(DecodeHeaderSnafu {})
    }
}

/// Claims required by the built-in [`KeycloakToken`] model before they are converted to
/// application-facing types.
///
/// `exp`, `iat`, `jti`, `iss`, `sub`, `typ`, and `azp` are required. `aud` defaults to an empty
/// list, realm and client access are optional, and `Extra` determines any additional claim
/// requirements.
#[serde_as]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StandardClaims<Extra> {
    /// Expiration time (`exp`) as a Unix timestamp.
    pub exp: i64,
    /// Issued-at time (`iat`) as a Unix timestamp.
    pub iat: i64,
    /// Issuer-assigned JWT ID (`jti`). The crate does not perform replay detection.
    pub jti: String,
    /// Issuer identifier (`iss`).
    pub iss: String,
    /// Intended audiences (`aud`). A single string and an array are accepted. A missing claim
    /// becomes an empty vector.
    #[serde_as(deserialize_as = "OneOrMany<_>")]
    #[serde(default)]
    pub aud: Vec<String>,
    /// Subject identifier (`sub`).
    pub sub: String,
    /// Keycloak payload token type (`typ`), not the JWT header parameter of the same name.
    pub typ: String,
    /// Authorized party (`azp`), normally the Keycloak client ID.
    pub azp: String,

    /// Optional realm roles from Keycloak's `realm_access` claim.
    pub realm_access: Option<RealmAccess>,
    /// Optional client roles from Keycloak's `resource_access` claim.
    pub resource_access: Option<ResourceAccess>,

    /// Additional claims deserialized into the application-selected type.
    #[serde(flatten)]
    pub extra: Extra,
}

/// Role names within a Keycloak realm or client access claim.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Access {
    /// Role names.
    pub roles: Vec<String>,
}

/// Keycloak realm access claim.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RealmAccess(pub Access);

/// Keycloak client access claims keyed by client ID.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResourceAccess(pub HashMap<String, Access>);

impl NumRoles for RealmAccess {
    fn num_roles(&self) -> usize {
        self.0.roles.len()
    }
}

impl NumRoles for ResourceAccess {
    fn num_roles(&self) -> usize {
        self.0.values().map(|access| access.roles.len()).sum()
    }
}

impl<R: Role> ExtractRoles<R> for RealmAccess {
    fn extract_roles(self, target: &mut Vec<KeycloakRole<R>>) {
        for role in self.0.roles {
            target.push(KeycloakRole::Realm { role: role.into() });
        }
    }
}

impl<R: Role> ExtractRoles<R> for ResourceAccess {
    fn extract_roles(self, target: &mut Vec<KeycloakRole<R>>) {
        for (client, access) in self.0 {
            for role in access.roles {
                target.push(KeycloakRole::Client {
                    client: client.clone(),
                    role: role.into(),
                });
            }
        }
    }
}

/// Typed claims from a signature-verified and policy-validated Keycloak token.
///
/// [`crate::PassthroughMode::Block`] inserts this type as a request extension after successful
/// authentication. [`crate::PassthroughMode::Pass`] instead inserts a
/// [`crate::KeycloakAuthStatus`] containing either this token or the authentication error.
/// `R` controls the role value type. `Extra` controls additional claims and defaults to
/// [`ProfileAndEmail`].
///
/// Extract a token in block mode with Axum's [`axum::Extension`]:
///
/// ```
/// use axum::Extension;
/// use axum_keycloak_auth::token::KeycloakToken;
///
/// pub async fn subject(Extension(token): Extension<KeycloakToken<String>>) -> String {
///     token.subject
/// }
/// ```
#[derive(Debug, PartialEq, Clone)]
pub struct KeycloakToken<R, Extra = ProfileAndEmail>
where
    R: Role,
    Extra: DeserializeOwned + Clone,
{
    /// Expiration time in UTC.
    pub expires_at: time::OffsetDateTime,
    /// Issued-at time in UTC.
    pub issued_at: time::OffsetDateTime,
    /// Issuer-assigned JWT ID. The crate does not perform replay detection.
    pub jwt_id: String,
    /// Issuer identifier.
    pub issuer: String,
    /// Intended audiences.
    pub audience: Vec<String>,
    /// Subject identifier. Treat it as opaque. The crate does not require a UUID format.
    pub subject: String,
    /// Authorized party, normally the Keycloak client ID. It can be constrained with
    /// [`crate::validation::ValidationPolicyBuilder::allowed_authorized_parties`].
    pub authorized_party: String,

    /// Realm and client roles carried by the token.
    pub roles: Vec<KeycloakRole<R>>,

    /// Additional claims deserialized into the application-selected type.
    pub extra: Extra,
}

impl<R, Extra> KeycloakToken<R, Extra>
where
    R: Role,
    Extra: DeserializeOwned + Clone,
{
    pub(crate) fn parse(raw: StandardClaims<Extra>) -> Result<Self, AuthError> {
        Ok(Self {
            expires_at: time::OffsetDateTime::from_unix_timestamp(raw.exp).map_err(|err| {
                AuthError::InvalidToken {
                    reason: format!(
                        "Could not parse 'exp' (expires_at) field as unix timestamp: {err}"
                    ),
                }
            })?,
            issued_at: time::OffsetDateTime::from_unix_timestamp(raw.iat).map_err(|err| {
                AuthError::InvalidToken {
                    reason: format!(
                        "Could not parse 'iat' (issued_at) field as unix timestamp: {err}"
                    ),
                }
            })?,
            jwt_id: raw.jti,
            issuer: raw.iss,
            audience: raw.aud,
            subject: raw.sub,
            authorized_party: raw.azp,
            roles: {
                let mut roles = Vec::new();
                (raw.realm_access, raw.resource_access).extract_roles(&mut roles);
                roles
            },
            extra: raw.extra,
        })
    }

    /// Whether this token's expiration time has passed, measured against the system clock.
    ///
    /// The exact expiration timestamp is accepted. This reads the system clock independently and
    /// does not apply the validation policy's leeway or transit margin.
    pub fn is_expired(&self) -> bool {
        self.is_expired_at(time::OffsetDateTime::now_utc())
    }

    pub(crate) fn is_expired_at(&self, validation_time: time::OffsetDateTime) -> bool {
        validation_time > self.expires_at
    }

    /// Verifies that the token has not expired, measured against the system clock.
    ///
    /// The exact expiration timestamp is accepted. This reads the system clock independently and
    /// does not apply the validation policy's leeway or transit margin.
    ///
    /// # Errors
    ///
    /// Returns [`AuthError::TokenExpired`] if the token's expiration time has passed.
    pub fn assert_not_expired(&self) -> Result<(), AuthError> {
        self.assert_not_expired_at(time::OffsetDateTime::now_utc())
    }

    pub(crate) fn assert_not_expired_at(
        &self,
        validation_time: time::OffsetDateTime,
    ) -> Result<(), AuthError> {
        if self.is_expired_at(validation_time) {
            Err(AuthError::TokenExpired)
        } else {
            Ok(())
        }
    }
}

impl<R, Extra> ExpectRoles<R> for KeycloakToken<R, Extra>
where
    R: Role,
    Extra: DeserializeOwned + Clone,
{
    type Rejection = AuthError;

    fn expect_roles<I: Into<R> + Clone>(
        &self,
        expected_roles: &[I],
    ) -> Result<(), Self::Rejection> {
        for expected_role in expected_roles {
            let expected: R = expected_role.clone().into();
            if !self.roles.iter().any(|role| role.role() == &expected) {
                return Err(AuthError::MissingExpectedRole {
                    role: expected.to_string(),
                });
            }
        }
        Ok(())
    }

    fn not_expect_roles<I: Into<R> + Clone>(&self, roles: &[I]) -> Result<(), Self::Rejection> {
        for expected in roles {
            let expected: R = expected.clone().into();
            if self.roles.iter().any(|role| role.role() == &expected) {
                return Err(AuthError::UnexpectedRole);
            }
        }
        Ok(())
    }
}

/// Keycloak's standard user profile claims.
#[derive(serde::Deserialize, Debug, Clone)]
#[serde(from = "ProfileClaims")]
pub struct Profile {
    /// Given name (`given_name`), if included in the token.
    pub given_name: Option<String>,
    /// Display name, read from the `full_name` claim or, if that is absent, from Keycloak's
    /// standard `name` claim.
    ///
    /// `full_name` takes precedence because earlier releases read only that claim, so tokens
    /// carrying a custom `full_name` mapper keep their established value.
    pub full_name: Option<String>,
    /// Family name (`family_name`), if included in the token.
    pub family_name: Option<String>,
    /// Preferred username (`preferred_username`).
    pub preferred_username: String,
}

/// Wire representation of [`Profile`], accepting both display-name claims at once.
#[derive(serde::Deserialize)]
struct ProfileClaims {
    given_name: Option<String>,
    name: Option<String>,
    full_name: Option<String>,
    family_name: Option<String>,
    preferred_username: String,
}

impl From<ProfileClaims> for Profile {
    fn from(claims: ProfileClaims) -> Self {
        Self {
            given_name: claims.given_name,
            full_name: claims.full_name.or(claims.name),
            family_name: claims.family_name,
            preferred_username: claims.preferred_username,
        }
    }
}

/// Keycloak's standard email claims.
#[derive(serde::Deserialize, Debug, Clone)]
pub struct Email {
    /// Email address (`email`).
    pub email: String,
    /// Whether Keycloak has verified the email address (`email_verified`).
    pub email_verified: bool,
}

/// Default additional-claims type combining [`Profile`] and [`Email`].
///
/// `preferred_username`, `email`, and `email_verified` must be present. Choose a custom `Extra`
/// type on [`KeycloakToken`] and [`crate::layer::KeycloakAuthLayer`] when those claims are optional
/// or when the token carries application-specific claims.
#[derive(serde::Deserialize, Debug, Clone)]
pub struct ProfileAndEmail {
    /// Profile claims flattened into the JWT payload.
    #[serde(flatten)]
    pub profile: Profile,
    /// Email claims flattened into the JWT payload.
    #[serde(flatten)]
    pub email: Email,
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use assertr::prelude::*;

    use crate::{
        error::AuthError,
        role::{ExpectRoles, KeycloakRole},
    };

    use super::{
        Access, KeycloakToken, Profile, ProfileAndEmail, RealmAccess, ResourceAccess,
        StandardClaims,
    };

    fn token_with_realm_and_client_roles() -> KeycloakToken<String, ()> {
        KeycloakToken::parse(StandardClaims {
            exp: 1_700_000_100,
            iat: 1_700_000_000,
            jti: String::from("test-token"),
            iss: String::from("https://keycloak.example/realms/test"),
            aud: vec![String::from("account")],
            sub: String::from("test-user"),
            typ: String::from("Bearer"),
            azp: String::from("account"),
            realm_access: Some(RealmAccess(Access {
                roles: vec![String::from("realm-role")],
            })),
            resource_access: Some(ResourceAccess(HashMap::from([(
                String::from("account"),
                Access {
                    roles: vec![String::from("client-role")],
                },
            )]))),
            extra: (),
        })
        .expect("the test claims must form a token")
    }

    #[test]
    fn parsing_preserves_the_realm_and_client_scope_of_roles() {
        assert_that!(token_with_realm_and_client_roles().roles).is_equal_to(vec![
            KeycloakRole::Realm {
                role: String::from("realm-role"),
            },
            KeycloakRole::Client {
                client: String::from("account"),
                role: String::from("client-role"),
            },
        ]);
    }

    #[test]
    fn required_and_forbidden_role_checks_search_both_scopes() {
        let token = token_with_realm_and_client_roles();

        assert_that!(token.expect_roles(&["realm-role", "client-role"])).is_ok();
        assert_that!(token.not_expect_roles(&["absent-role"])).is_ok();
        assert_that!(token.expect_roles(&["missing-role"])).is_matching(pattern!(
            Err(AuthError::MissingExpectedRole { role }) if role == "missing-role"
        ));
        for role in ["realm-role", "client-role"] {
            assert_that!(token.not_expect_roles(&[role]))
                .with_subject_name(role)
                .is_matching(pattern!(Err(AuthError::UnexpectedRole)));
        }
    }

    #[test]
    fn profile_full_name_reads_the_standard_name_claim_and_legacy_alias() {
        for claim in ["name", "full_name"] {
            let profile = serde_json::from_value::<Profile>(serde_json::json!({
                (claim): "Test User",
                "preferred_username": "test-user",
            }))
            .expect("profile claims must deserialize");

            assert_that!(profile.full_name)
                .with_subject_name(claim)
                .some()
                .is_equal_to("Test User");
        }
    }

    /// Keycloak's default `profile` scope emits `name`, so tokens of deployments that also map a
    /// `full_name` claim carry both. Earlier releases accepted these tokens and read `full_name`.
    #[test]
    fn profile_accepts_both_name_claims_and_prefers_full_name() {
        let claims = serde_json::from_value::<StandardClaims<ProfileAndEmail>>(serde_json::json!({
            "exp": 2_000_000_000,
            "iat": 1_900_000_000,
            "jti": "0b6f1f4e-0000-4000-8000-000000000000",
            "iss": "https://keycloak.example/realms/test",
            "sub": "a7060488-c80b-40c5-83e2-d7000bf9738e",
            "typ": "Bearer",
            "azp": "test-client",
            "name": "Standard Name",
            "full_name": "Mapped Full Name",
            "preferred_username": "test-user",
            "email": "test-user@example.com",
            "email_verified": true,
        }))
        .expect("tokens carrying both name claims must deserialize");

        assert_that!(claims.extra.profile.full_name)
            .some()
            .is_equal_to("Mapped Full Name");
    }

    /// The deprecated `decode` module alias must keep exposing the public token types until the
    /// next breaking release.
    #[test]
    #[allow(deprecated)]
    fn deprecated_decode_alias_still_exposes_the_token_types() {
        let _: Option<crate::decode::KeycloakToken<String>> = None;
        let _: Option<crate::decode::StandardClaims<crate::decode::ProfileAndEmail>> = None;
        let _: Option<crate::decode::RawClaims> = None;
    }
}
