use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use jsonwebtoken::{Algorithm, EncodingKey, Header, errors::Error, jwk::Jwk};
use serde::Serialize;
use serde_json::{Map, Value, json};
use time::OffsetDateTime;

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
        let mut public_jwk: Value = serde_json::from_str(self.public_jwk)
            .unwrap_or_else(|err| panic!("generated JWK fixture must be valid JSON: {err}"));
        let fields = public_jwk
            .as_object_mut()
            .unwrap_or_else(|| panic!("generated JWK fixture must be a JSON object"));
        fields.insert(
            String::from("kid"),
            kid.map_or(Value::Null, |kid| Value::String(kid.to_owned())),
        );
        fields.insert(String::from("alg"), json!(algorithm));
        fields.insert(String::from("use"), Value::String(String::from("sig")));

        serde_json::from_value(public_jwk)
            .unwrap_or_else(|err| panic!("static fixture must form a valid JWK: {err}"))
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
        assert_eq!(
            self.kind,
            KeyKind::Ec,
            "only EC fixtures have a public point"
        );
        let public_jwk: Value = serde_json::from_str(self.public_jwk)
            .unwrap_or_else(|err| panic!("generated EC JWK fixture must be valid JSON: {err}"));
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
}

// Throwaway, publicly known test keys, not secrets. Regenerate them, together with their JWK
// metadata, with `just regenerate-test-key-fixtures` (see fixtures/README.md).
pub(crate) const RSA_KEY_A: KeyFixture = KeyFixture {
    kind: KeyKind::Rsa,
    private_key: include_bytes!("fixtures/rsa_a.pem"),
    public_jwk: include_str!("fixtures/rsa_a.jwk.json"),
};

pub(crate) const RSA_KEY_B: KeyFixture = KeyFixture {
    kind: KeyKind::Rsa,
    private_key: include_bytes!("fixtures/rsa_b.pem"),
    public_jwk: include_str!("fixtures/rsa_b.jwk.json"),
};

/// A P-256 key, for the realms whose published key material is a public curve point rather than
/// an RSA modulus.
pub(crate) const EC_KEY_A: KeyFixture = KeyFixture {
    kind: KeyKind::Ec,
    private_key: include_bytes!("fixtures/ec_a.pem"),
    public_jwk: include_str!("fixtures/ec_a.jwk.json"),
};

pub(crate) fn keycloak_claims(now: OffsetDateTime) -> Map<String, Value> {
    let timestamp = now.unix_timestamp();
    match json!({
        "exp": timestamp + 300,
        "iat": timestamp,
        "nbf": timestamp,
        "jti": "test-jwt-id",
        "iss": "https://issuer.example/realms/test-realm",
        "aud": ["account"],
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
    }) {
        Value::Object(claims) => claims,
        _ => unreachable!("a JSON object literal must produce an object"),
    }
}
