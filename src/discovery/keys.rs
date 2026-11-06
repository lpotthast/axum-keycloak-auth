//! Immutable data published by a completed discovery and the key view used by token validation.
//!
//! [`DiscoveredData`] is what one successful discovery produced. [`DecodingKeys`] is a cheap
//! snapshot of it, tagged with the generation it was observed at so the validator can tell whether
//! a refresh has since happened.

use std::{fmt::Debug, sync::Arc};

use jsonwebtoken::jwk::{AlgorithmParameters, PublicKeyUse};

use crate::oidc::OidcConfig;

/// Every usable key in provider order, tagged with the provider key ID it was published under.
/// Key sets are small (a handful of keys per realm), so lookups are linear scans over the one
/// `Vec` instead of a maintained index.
#[derive(Default)]
struct IndexedDecodingKeys {
    keys: Vec<(Option<String>, jsonwebtoken::DecodingKey)>,
}

impl IndexedDecodingKeys {
    fn from_jwks(jwk_set: &jsonwebtoken::jwk::JwkSet) -> Self {
        let mut keys = Vec::new();
        for jwk in &jwk_set.keys {
            match &jwk.algorithm {
                AlgorithmParameters::RSA(_)
                | AlgorithmParameters::EllipticCurve(_)
                | AlgorithmParameters::OctetKeyPair(_) => {}
                // A symmetric key in a published JWKS would let anyone who can read the set forge
                // tokens.
                AlgorithmParameters::OctetKey(_) => {
                    tracing::debug!(kid = ?jwk.common.key_id, "Ignoring a symmetric JWK.");
                    continue;
                }
                _ => {
                    tracing::warn!(
                        kid = ?jwk.common.key_id,
                        "Ignoring a JWK with an unsupported key type."
                    );
                    continue;
                }
            }
            if jwk.common.public_key_use == Some(PublicKeyUse::Encryption) {
                tracing::debug!(
                    kid = ?jwk.common.key_id,
                    "Ignoring a JWK published for encryption."
                );
                continue;
            }
            match jsonwebtoken::DecodingKey::from_jwk(jwk) {
                Ok(decoding_key) => keys.push((jwk.common.key_id.clone(), decoding_key)),
                Err(err) => {
                    tracing::error!(
                        ?err,
                        "Received JWK from Keycloak which could not be parsed as a DecodingKey. Ignoring the JWK."
                    );
                }
            }
        }
        Self { keys }
    }

    fn len(&self) -> usize {
        self.keys.len()
    }

    /// Iterate over keys whose provider key ID exactly matches `kid`. Returns `None` if there are
    /// no matches.
    fn exact<'a>(
        &'a self,
        kid: &'a str,
    ) -> Option<impl Iterator<Item = &'a jsonwebtoken::DecodingKey> + 'a> {
        self.keys
            .iter()
            .any(|(key_id, _key)| key_id.as_deref() == Some(kid))
            .then(move || {
                self.keys
                    .iter()
                    .filter(move |(key_id, _key)| key_id.as_deref() == Some(kid))
                    .map(|(_key_id, key)| key)
            })
    }

    fn all(&self) -> impl Iterator<Item = &jsonwebtoken::DecodingKey> {
        self.keys.iter().map(|(_key_id, key)| key)
    }

    fn all_except<'a>(
        &'a self,
        kid: &'a str,
    ) -> impl Iterator<Item = &'a jsonwebtoken::DecodingKey> + 'a {
        self.keys
            .iter()
            .filter(move |(key_id, _key)| key_id.as_deref() != Some(kid))
            .map(|(_key_id, key)| key)
    }
}

pub(crate) struct DiscoveredData {
    /// The provider's OIDC discovery document. Its issuer is included in `Debug` output.
    oidc_config: OidcConfig,
    decoding_keys: IndexedDecodingKeys,
}

impl Debug for DiscoveredData {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DiscoveredData")
            .field("issuer", &self.oidc_config.standard_claims.issuer)
            .field("num_decoding_keys", &self.decoding_keys.len())
            .finish()
    }
}

impl DiscoveredData {
    pub(crate) fn new(oidc_config: OidcConfig, jwk_set: &jsonwebtoken::jwk::JwkSet) -> Self {
        Self {
            oidc_config,
            decoding_keys: IndexedDecodingKeys::from_jwks(jwk_set),
        }
    }

    pub(super) fn has_usable_decoding_keys(&self) -> bool {
        self.decoding_keys.len() > 0
    }
}

pub(crate) struct DecodingKeys {
    data: Option<Arc<DiscoveredData>>,
    generation: usize,
    expired: bool,
}

impl DecodingKeys {
    /// Pairs a published snapshot with the generation it was published at. Constructed only by
    /// the discovery lifecycle (and by in-memory test doubles), so the two can never drift apart.
    pub(crate) fn new(data: Option<Arc<DiscoveredData>>, generation: usize) -> Self {
        Self {
            data,
            generation,
            expired: false,
        }
    }

    /// No usable keys, because the cached ones expired.
    pub(crate) fn expired(generation: usize) -> Self {
        Self {
            data: None,
            generation,
            expired: true,
        }
    }

    /// Whether keys are withheld because the cached ones expired.
    pub(crate) fn is_expired(&self) -> bool {
        self.expired
    }

    /// The discovery generation this key set was observed at.
    pub(crate) fn generation(&self) -> usize {
        self.generation
    }

    /// Iterate over keys whose provider key ID exactly matches the token header.
    pub(crate) fn exact<'a>(
        &'a self,
        kid: &'a str,
    ) -> Option<impl Iterator<Item = &'a jsonwebtoken::DecodingKey> + 'a> {
        self.data
            .as_ref()
            .and_then(|data| data.decoding_keys.exact(kid))
    }

    /// Iterate over every usable trusted key in provider order.
    pub(crate) fn all(&self) -> impl Iterator<Item = &jsonwebtoken::DecodingKey> {
        self.data.iter().flat_map(|data| data.decoding_keys.all())
    }

    /// Iterate over usable trusted keys that were not already selected by an exact `kid` match.
    pub(crate) fn all_except<'a>(
        &'a self,
        kid: &'a str,
    ) -> impl Iterator<Item = &'a jsonwebtoken::DecodingKey> + 'a {
        self.data
            .iter()
            .flat_map(move |data| data.decoding_keys.all_except(kid))
    }
}

#[cfg(test)]
mod tests {
    use assertr::prelude::*;
    use jsonwebtoken::{
        Algorithm,
        jwk::{Jwk, JwkSet, PublicKeyUse},
    };

    use crate::test_support::{CapturedLogs, RSA_KEY_A, RSA_KEY_B};

    use super::IndexedDecodingKeys;

    #[test]
    fn known_kid_fallback_excludes_every_exact_match() {
        let keys = IndexedDecodingKeys::from_jwks(&JwkSet {
            keys: vec![
                RSA_KEY_A.jwk(Some("shared-kid"), Algorithm::RS256),
                RSA_KEY_B.jwk(Some("shared-kid"), Algorithm::RS256),
                RSA_KEY_A.jwk(Some("other-kid"), Algorithm::RS256),
            ],
        });

        assert_that!(keys.exact("shared-kid").map(Iterator::count))
            .some()
            .is_equal_to(2);
        assert_that!(keys.all_except("shared-kid").count()).is_equal_to(1);
    }

    #[test]
    fn symmetric_and_encryption_keys_are_never_used_for_verification() {
        let symmetric: Jwk = serde_json::from_value(serde_json::json!({
            "kty": "oct",
            "kid": "symmetric",
            "k": "c3ltbWV0cmljLXNlY3JldA",
        }))
        .expect("the symmetric JWK must deserialize");
        let mut encryption = RSA_KEY_B.jwk(Some("encryption"), Algorithm::RS256);
        encryption.common.public_key_use = Some(PublicKeyUse::Encryption);

        let keys = IndexedDecodingKeys::from_jwks(&JwkSet {
            keys: vec![
                symmetric,
                encryption,
                RSA_KEY_A.jwk(Some("signature"), Algorithm::RS256),
            ],
        });

        assert_that!(keys.len()).is_equal_to(1);
        assert_that!(keys.exact("signature").map(Iterator::count))
            .some()
            .is_equal_to(1);
    }

    #[test]
    fn keys_of_an_unsupported_type_are_ignored() {
        let unsupported: Jwk = serde_json::from_value(serde_json::json!({
            "kty": "unsupported",
            "kid": "unsupported",
        }))
        .expect("a JWK of an unknown key type must deserialize");

        let logs = CapturedLogs::default();
        let keys = {
            let _capture = logs.capture();
            IndexedDecodingKeys::from_jwks(&JwkSet {
                keys: vec![
                    unsupported,
                    RSA_KEY_A.jwk(Some("signature"), Algorithm::RS256),
                ],
            })
        };

        assert_that!(keys.len()).is_equal_to(1);
        assert_that!(keys.exact("unsupported").map(Iterator::count)).is_none();
        let event = logs.event_containing("Ignoring a JWK with an unsupported key type.");
        assert_that!(event.level()).is_equal_to(tracing::Level::WARN);
        assert_that!(event.field("kid")).is_equal_to(Some("Some(\"unsupported\")"));
    }
}
