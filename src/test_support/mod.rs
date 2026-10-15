//! Hermetic test infrastructure: throwaway signing keys, Keycloak-shaped claims, a controllable
//! clock, an in-memory key source, a resolved offline instance, and an in-process mock provider.

mod clock;
mod instance;
mod jwt;
mod keys;
mod logs;
mod oidc;
mod policy;

pub(crate) use clock::ManualClock;
pub(crate) use instance::{
    config_for, discovered_instance, offline_instance, refresh_policy_without_jitter, signed_token,
    static_discovered_data, validation_time, wait_for_discovery_completion,
};
pub(crate) use jwt::{EC_KEY_A, RSA_KEY_A, RSA_KEY_B, keycloak_claims};
pub(crate) use keys::StaticKeySource;
pub(crate) use logs::{CapturedLogs, assert_logged_iff};
pub(crate) use oidc::{MockOidcServer, MockResponse, ResponseGate};
pub(crate) use policy::{legacy_policy, strict_policy};

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use assertr::prelude::*;
    use axum::http::StatusCode;
    use jsonwebtoken::{Algorithm, DecodingKey, Validation};
    use serde_json::{Value, json};

    use crate::clock::Clock;

    use super::{
        EC_KEY_A, ManualClock, MockOidcServer, MockResponse, RSA_KEY_A, RSA_KEY_B, ResponseGate,
        keycloak_claims, validation_time,
    };

    fn signature_only_validation(algorithm: Algorithm) -> Validation {
        let mut validation = Validation::new(algorithm);
        validation.validate_exp = false;
        validation.validate_aud = false;
        validation.required_spec_claims.clear();
        validation
    }

    #[test]
    fn jwt_helpers_control_claims_algorithm_kid_and_key() {
        let mut claims = keycloak_claims(validation_time());
        claims.insert(String::from("custom"), json!({ "enabled": true }));
        claims.insert(String::from("iat"), json!(1_899_999_000_i64));
        claims.insert(String::from("nbf"), json!(1_899_999_500_i64));
        let token = RSA_KEY_A
            .sign(&claims, Algorithm::RS384, Some("custom-kid"))
            .expect("RSA fixture must sign");

        let header = assert_that_owned!(jsonwebtoken::decode_header(&token)).ok();
        header.derive(|it| &it.alg).is_equal_to(Algorithm::RS384);
        header.derive(|it| &it.kid).some().is_equal_to("custom-kid");
        let token_without_kid = RSA_KEY_A
            .sign(&claims, Algorithm::RS256, None)
            .expect("RSA fixture must sign without a kid");
        assert_that!(jsonwebtoken::decode_header(&token_without_kid))
            .ok()
            .derive(|it| &it.kid)
            .is_none();

        let validation = signature_only_validation(Algorithm::RS384);
        let key_a = DecodingKey::from_jwk(&RSA_KEY_A.jwk(Some("custom-kid"), Algorithm::RS384))
            .expect("key A JWK must decode");
        let decoded = jsonwebtoken::decode::<Value>(&token, &key_a, &validation)
            .expect("matching key must validate");
        let payload = assert_that!(decoded.claims);
        payload.pointer("/custom/enabled").bool().is_true();
        payload.pointer("/iat").is_equal_to(1_899_999_000_i64);
        payload.pointer("/nbf").is_equal_to(1_899_999_500_i64);

        let key_b = DecodingKey::from_jwk(&RSA_KEY_B.jwk(Some("other-kid"), Algorithm::RS384))
            .expect("key B JWK must decode");
        assert_that!(jsonwebtoken::decode::<Value>(&token, &key_b, &validation)).is_err();

        let token_b = RSA_KEY_B
            .sign(&claims, Algorithm::RS384, Some("other-kid"))
            .expect("RSA fixture B must sign");
        jsonwebtoken::decode::<Value>(&token_b, &key_b, &validation)
            .expect("fixture B's generated public JWK must match its private key");
    }

    /// The EC fixture's published JWK must belong to its private key, and its public point must
    /// be the exact byte string a `DecodingKey` built from that JWK holds (which is what the
    /// algorithm-confusion regression tests forge against).
    #[test]
    fn ec_fixture_jwk_matches_its_private_key_and_public_point() {
        let token = EC_KEY_A
            .sign(
                &keycloak_claims(validation_time()),
                Algorithm::ES256,
                Some("ec-kid"),
            )
            .expect("EC fixture must sign");
        let published = DecodingKey::from_jwk(&EC_KEY_A.jwk(Some("ec-kid"), Algorithm::ES256))
            .expect("EC JWK must decode");

        jsonwebtoken::decode::<Value>(
            &token,
            &published,
            &signature_only_validation(Algorithm::ES256),
        )
        .expect("the EC fixture's generated public JWK must match its private key");

        let (message, signature) = token.rsplit_once('.').expect("a JWT has a signature part");
        let hmac_with_public_point = jsonwebtoken::crypto::sign(
            message.as_bytes(),
            &jsonwebtoken::EncodingKey::from_secret(&EC_KEY_A.public_point()),
            Algorithm::HS256,
        )
        .expect("HMAC over the public point must sign");
        assert_that!(jsonwebtoken::crypto::verify(
            &hmac_with_public_point,
            message.as_bytes(),
            &published,
            Algorithm::HS256,
        ))
        .ok()
        .is_true();
        // Sanity: the genuine ES256 signature is not what the HMAC produced.
        assert_that!(hmac_with_public_point.as_str()).is_not_equal_to(signature);
    }

    #[test]
    fn manual_clock_can_be_set_and_advanced() {
        let clock = ManualClock::new(validation_time());
        let initial_monotonic = clock.now_monotonic();
        assert_that!(clock.now_utc()).is_equal_to(validation_time());

        clock.advance(time::Duration::seconds(30));
        assert_that!(clock.now_utc()).is_equal_to(validation_time() + time::Duration::seconds(30));
        assert_that!(clock.now_monotonic().duration_since(initial_monotonic))
            .is_equal_to(Duration::from_secs(30));

        clock.set(validation_time() - time::Duration::seconds(10));
        assert_that!(clock.now_utc()).is_equal_to(validation_time() - time::Duration::seconds(10));
        assert_that!(clock.now_monotonic().duration_since(initial_monotonic))
            .is_equal_to(Duration::from_secs(30));
    }

    #[tokio::test]
    async fn mock_provider_serves_discovery_and_rotating_jwks() {
        let server = MockOidcServer::start().await;
        server
            .set_jwks(vec![RSA_KEY_A.jwk(Some("key-a"), Algorithm::RS256)])
            .await;

        let discovery = reqwest::get(server.discovery_url())
            .await
            .expect("discovery request must succeed")
            .json::<Value>()
            .await
            .expect("discovery response must be JSON");
        assert_that!(discovery)
            .pointer("/jwks_uri")
            .is_equal_to(server.jwks_url().as_str());

        let first_jwks = reqwest::get(server.jwks_url())
            .await
            .expect("first JWKS request must succeed")
            .json::<Value>()
            .await
            .expect("first JWKS response must be JSON");
        assert_that!(first_jwks)
            .pointer("/keys/0/kid")
            .is_equal_to("key-a");

        server
            .set_jwks(vec![RSA_KEY_B.jwk(Some("key-b"), Algorithm::RS512)])
            .await;
        let rotated_jwks = reqwest::get(server.jwks_url())
            .await
            .expect("rotated JWKS request must succeed")
            .json::<Value>()
            .await
            .expect("rotated JWKS response must be JSON");
        assert_that!(rotated_jwks)
            .pointer("/keys/0/kid")
            .is_equal_to("key-b");
        assert_that!(server.discovery_requests()).is_equal_to(1);
        assert_that!(server.jwks_requests()).is_equal_to(2);
    }

    #[tokio::test]
    async fn mock_provider_controls_failures_and_gating() {
        let server = MockOidcServer::start().await;

        server
            .set_discovery_response(MockResponse::text(
                StatusCode::SERVICE_UNAVAILABLE,
                "provider unavailable",
            ))
            .await;
        let failed = reqwest::get(server.discovery_url())
            .await
            .expect("failure response must be received");
        assert_that!(failed.status()).is_equal_to(StatusCode::SERVICE_UNAVAILABLE);
        server.restore_discovery_response().await;
        let recovered = reqwest::get(server.discovery_url())
            .await
            .expect("restored response must be received");
        assert_that!(recovered.status()).is_equal_to(StatusCode::OK);

        // A gated response blocks until released.
        let gate = ResponseGate::closed();
        server
            .set_jwks_response(
                MockResponse::text(StatusCode::OK, "malformed-json").with_gate(gate.clone()),
            )
            .await;
        let jwks_url = server.jwks_url();
        let gated_request = tokio::spawn(async move {
            reqwest::get(jwks_url)
                .await
                .expect("gated request must complete")
        });
        tokio::time::timeout(Duration::from_secs(2), async {
            while server.jwks_requests() < 1 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("gated JWKS request must reach the mock server");
        assert_that!(gated_request.is_finished()).is_false();
        gate.release();
        let gated_response = tokio::time::timeout(Duration::from_secs(2), gated_request)
            .await
            .expect("released JWKS request must finish")
            .expect("gated request task must complete");
        assert_that!(gated_response.text().await)
            .ok()
            .is_equal_to("malformed-json");
    }
}
