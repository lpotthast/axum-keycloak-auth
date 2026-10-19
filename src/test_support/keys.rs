//! Throwaway signing keys: committed private keys for signing test tokens, and the public JWKs a
//! provider would publish for them.
//!
//! The keys are publicly known and must never protect anything. Regenerate them, together with
//! their JWK metadata, with `just regenerate-test-key-fixtures` (see `fixtures/README.md`).

use assertr::prelude::*;
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use jsonwebtoken::{Algorithm, EncodingKey, Header, errors::Error, jwk::Jwk};
use serde::Serialize;
use serde_json::{Value, json};

/// A 2048-bit RSA key. Published under [`super::TEST_KID`] by the offline fixtures.
pub(crate) const RSA_KEY_A: KeyFixture = KeyFixture {
    kind: KeyKind::Rsa,
    private_key: include_bytes!("fixtures/rsa_a.pem"),
    public_jwk: include_str!("fixtures/rsa_a.jwk.json"),
};

/// A second 2048-bit RSA key, for key selection and rotation scenarios.
pub(crate) const RSA_KEY_B: KeyFixture = KeyFixture {
    kind: KeyKind::Rsa,
    private_key: include_bytes!("fixtures/rsa_b.pem"),
    public_jwk: include_str!("fixtures/rsa_b.jwk.json"),
};

/// A P-256 key, for realms whose published key material is a public curve point rather than an
/// RSA modulus.
pub(crate) const EC_KEY_A: KeyFixture = KeyFixture {
    kind: KeyKind::Ec,
    private_key: include_bytes!("fixtures/ec_a.pem"),
    public_jwk: include_str!("fixtures/ec_a.jwk.json"),
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum KeyKind {
    Rsa,
    /// P-256.
    Ec,
}

/// A throwaway, publicly known signing key: its PKCS#8 private key (for signing test tokens) and
/// the public JWK metadata a provider would publish for it.
#[derive(Debug, Clone, Copy)]
pub(crate) struct KeyFixture {
    kind: KeyKind,
    private_key: &'static [u8],
    public_jwk: &'static str,
}

impl KeyFixture {
    /// Signs `claims` with this key, using `algorithm` and `kid` in the JWT header.
    ///
    /// The algorithm must belong to this key's family. Signing with a mismatching algorithm fails,
    /// so forging cross-family tokens needs [`Self::public_point`] instead.
    pub(crate) fn sign<T: Serialize>(
        &self,
        claims: &T,
        algorithm: Algorithm,
        kid: Option<&str>,
    ) -> Result<String, Error> {
        let mut header = Header::new(algorithm);
        header.kid = kid.map(str::to_owned);
        let encoding_key = match self.kind {
            KeyKind::Rsa => EncodingKey::from_rsa_pem(self.private_key)?,
            KeyKind::Ec => EncodingKey::from_ec_pem(self.private_key)?,
        };
        jsonwebtoken::encode(&header, claims, &encoding_key)
    }

    /// The public signing JWK of this key, tagged with the `kid` and algorithm a test wants to
    /// publish it under.
    pub(crate) fn jwk(&self, kid: Option<&str>, algorithm: Algorithm) -> Jwk {
        let mut public_jwk = self.public_jwk();
        let fields = public_jwk
            .as_object_mut()
            .expect("a generated JWK fixture must be a JSON object");
        fields.insert(String::from("kid"), json!(kid));
        fields.insert(String::from("alg"), json!(algorithm));
        fields.insert(String::from("use"), json!("sig"));

        serde_json::from_value(public_jwk).expect("a generated JWK fixture must form a valid JWK")
    }

    /// The uncompressed public curve point (`0x04 || X || Y`) of an EC key's published JWK.
    ///
    /// This is exactly the byte string `jsonwebtoken` keeps inside a `DecodingKey` built from an
    /// EC JWK, and it is derived here only from public JWK fields. Tests use it to forge the
    /// algorithm-confusion token that asks for public key material to be treated as an HMAC
    /// secret.
    ///
    /// # Panics
    ///
    /// Panics for RSA fixtures, which have no curve point.
    pub(crate) fn public_point(&self) -> Vec<u8> {
        assert_that!(self.kind)
            .with_detail_message("only EC fixtures have a public point")
            .is_equal_to(KeyKind::Ec);
        let public_jwk = self.public_jwk();
        let coordinate = |name: &str| -> Vec<u8> {
            let encoded = public_jwk[name]
                .as_str()
                .unwrap_or_else(|| panic!("the EC JWK fixture must carry a string '{name}'"));
            URL_SAFE_NO_PAD
                .decode(encoded)
                .unwrap_or_else(|err| panic!("the EC JWK coordinate '{name}' must decode: {err}"))
        };

        let mut point = vec![0x04];
        point.extend_from_slice(&coordinate("x"));
        point.extend_from_slice(&coordinate("y"));
        point
    }

    fn public_jwk(&self) -> Value {
        serde_json::from_str(self.public_jwk).expect("a generated JWK fixture must be valid JSON")
    }
}

#[cfg(test)]
mod tests {
    use assertr::prelude::*;
    use jsonwebtoken::{Algorithm, DecodingKey, Validation};
    use serde_json::{Value, json};

    use crate::test_support::{keycloak_claims, validation_time};

    use super::{EC_KEY_A, RSA_KEY_A, RSA_KEY_B};

    fn signature_only_validation(algorithm: Algorithm) -> Validation {
        let mut validation = Validation::new(algorithm);
        validation.validate_exp = false;
        validation.validate_aud = false;
        validation.required_spec_claims.clear();
        validation
    }

    /// Also proves that both RSA fixtures publish JWKs matching their private keys.
    #[test]
    fn rsa_fixtures_control_claims_algorithm_kid_and_key() {
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
    fn jwk_without_kid_publishes_a_null_kid() {
        assert_that!(RSA_KEY_A.jwk(None, Algorithm::RS256).common.key_id).is_none();
    }
}
