//! The fixture realm and its tokens: the realm's identity, a fixed validation time, and the claims
//! of an access token that every built-in policy accepts at that time.

use jsonwebtoken::Algorithm;
use serde_json::{Map, Value, json};
use time::{Date, Month, OffsetDateTime};
use url::Url;

use super::keys::KeyFixture;

/// Base URL of the fixture Keycloak server. Offline fixtures never contact it.
pub(crate) const TEST_SERVER_URL: &str = "https://issuer.example/";

/// Name of the fixture realm.
pub(crate) const TEST_REALM: &str = "test-realm";

/// Issuer (`iss`) of the fixture realm's tokens.
pub(crate) const TEST_ISSUER: &str = "https://issuer.example/realms/test-realm";

/// Audience (`aud`) carried by [`keycloak_claims`] and expected by the fixture policies.
pub(crate) const TEST_AUDIENCE: &str = "account";

/// Key ID under which offline fixtures publish [`super::RSA_KEY_A`].
pub(crate) const TEST_KID: &str = "key-a";

/// A JWT payload, keyed by claim name.
pub(crate) type Claims = Map<String, Value>;

/// [`TEST_SERVER_URL`], parsed.
pub(crate) fn test_server_url() -> Url {
    Url::parse(TEST_SERVER_URL).expect("the fixture server URL must parse")
}

/// The fixed instant at which tests validate tokens. Pair it with a
/// [`ManualClock`](super::ManualClock) so token lifetimes never depend on the wall clock.
pub(crate) fn validation_time() -> OffsetDateTime {
    Date::from_calendar_date(2030, Month::March, 17)
        .expect("the fixture date must be valid")
        .with_hms(17, 46, 40)
        .expect("the fixture time must be valid")
        .assume_utc()
}

/// The claims of a Keycloak access token issued at `now` and valid for five minutes.
///
/// The token belongs to the fixture realm, targets [`TEST_AUDIENCE`], grants the realm role
/// `developer` and the client role `reader`, and carries the profile and email claims of
/// [`crate::token::ProfileAndEmail`].
pub(crate) fn keycloak_claims(now: OffsetDateTime) -> Claims {
    let timestamp = now.unix_timestamp();
    let Value::Object(claims) = json!({
        "exp": timestamp + 300,
        "iat": timestamp,
        "nbf": timestamp,
        "jti": "test-jwt-id",
        "iss": TEST_ISSUER,
        "aud": [TEST_AUDIENCE],
        "sub": "test-subject",
        "typ": "Bearer",
        "azp": "test-client",
        "realm_access": { "roles": ["developer"] },
        "resource_access": {
            "test-client": { "roles": ["reader"] }
        },
        "given_name": "Test",
        "name": "Test User",
        "family_name": "User",
        "preferred_username": "test-user",
        "email": "test@example.com",
        "email_verified": true
    }) else {
        unreachable!("a JSON object literal must produce an object");
    };
    claims
}

/// [`keycloak_claims`] at [`validation_time`], with `claim` set to `value`.
pub(crate) fn claims_with(claim: &str, value: Value) -> Claims {
    let mut claims = keycloak_claims(validation_time());
    claims.insert(String::from(claim), value);
    claims
}

/// [`keycloak_claims`] at [`validation_time`], without `claim`.
pub(crate) fn claims_without(claim: &str) -> Claims {
    let mut claims = keycloak_claims(validation_time());
    claims.remove(claim);
    claims
}

/// [`keycloak_claims`] at [`validation_time`], signed as RS256 by `key` under `kid`.
pub(crate) fn signed_token(key: &KeyFixture, kid: Option<&str>) -> String {
    key.sign(&keycloak_claims(validation_time()), Algorithm::RS256, kid)
        .expect("the fixture key must sign")
}
