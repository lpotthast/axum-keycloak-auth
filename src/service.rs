use std::{
    collections::HashMap,
    marker::PhantomData,
    sync::{atomic::AtomicBool, Arc},
};

use jsonwebtoken::{jwk::JwkSet, DecodingKey};
use snafu::ResultExt;
use tokio::sync::{RwLock, RwLockReadGuard};
use url::Url;

use crate::{
    decode::{extract_jwt_token, KeycloakToken, StandardClaims},
    error::{AuthError, JwkEndpointSnafu, JwkSetDiscoverySnafu, OidcDiscoverySnafu},
    layer::{KeycloakAuthLayer, OidcDiscoveryEndpoint},
    oidc::OidcConfig,
    oidc_discovery,
    role::{ExpectRoles, Role},
    PassthroughMode,
};

pub(crate) struct KeycloakAuthService<R: Role> {
    pub(crate) server: Url,
    pub(crate) realm: String,
    pub(crate) oidc_discovery_endpoint: OidcDiscoveryEndpoint,
    ongoing_kc_request: Arc<AtomicBool>,
    pub(crate) oidc_config: Arc<RwLock<Result<OidcConfig, AuthError>>>,
    pub(crate) jwk_set: Arc<RwLock<Result<JwkSet, AuthError>>>,
    pub(crate) decoding_keys: Arc<RwLock<Vec<DecodingKey>>>,
    pub(crate) mode: PassthroughMode,
    pub(crate) persist_raw_claims: bool,
    pub(crate) expected_audiences: Vec<String>,
    pub(crate) required_roles: Vec<R>,
    pub(crate) phantom_data: PhantomData<R>,
}

impl<R: Role> KeycloakAuthService<R> {
    pub(crate) fn new(layer: &KeycloakAuthLayer<R>) -> Self {
        let mut this = Self {
            server: layer.server.clone(),
            realm: layer.realm.clone(),
            oidc_discovery_endpoint: OidcDiscoveryEndpoint::from_server_and_realm(
                layer.server.clone(),
                &layer.realm,
            ),
            oidc_config: Arc::new(RwLock::new(Err(AuthError::NoOidcDiscovery))),
            jwk_set: Arc::new(RwLock::new(Err(AuthError::NoJwkSetDiscovery))),
            decoding_keys: Arc::new(RwLock::new(Vec::new())),
            ongoing_kc_request: Arc::new(AtomicBool::new(false)),
            mode: layer.passthrough_mode,
            persist_raw_claims: layer.persist_raw_claims,
            expected_audiences: layer.expected_audiences.clone(),
            required_roles: layer.required_roles.clone(),
            phantom_data: PhantomData,
        };
        this.perform_async_oidc_discovery();
        this
    }

    fn perform_async_oidc_discovery(&mut self) {
        let oidc_discovery_endpoint = self.oidc_discovery_endpoint.clone();
        let oidc_config = self.oidc_config.clone();
        let jwk_set = self.jwk_set.clone();
        let decoding_keys = self.decoding_keys.clone();
        let ongoing_kc_request = self.ongoing_kc_request.clone();

        ongoing_kc_request.store(true, std::sync::atomic::Ordering::Release);

        tokio::spawn(async move {
            // Load OIDC config.
            let result = oidc_discovery::retrieve_oidc_config(oidc_discovery_endpoint.0)
                .await
                .context(OidcDiscoverySnafu {});

            // Parse JWK endpoint if OIDC config is available.
            if let Ok(config) = &result {
                let jwk_set_endpoint =
                    Url::parse(&config.standard_claims.jwks_uri).context(JwkEndpointSnafu {});

                // Load JWK set if endpoint was parsable.
                match jwk_set_endpoint {
                    Ok(jwk_set_endpoint) => {
                        let result = oidc_discovery::retrieve_jwk_set(jwk_set_endpoint)
                            .await
                            .context(JwkSetDiscoverySnafu {});

                        match &result {
                            Ok(jwk_set) => {
                                tracing::debug!(
                                    "Received jwk_set containing {} keys.",
                                    jwk_set.keys.len()
                                );

                                // Create DecodingKey instances from received JWKs.
                                *decoding_keys.write().await = parse_jwks(jwk_set);
                            }
                            Err(err) => {
                                tracing::error!(
                                    err = snafu::Report::from_error(err).to_string(),
                                    "Could not retrieve jwk_set."
                                );
                                // TODO: Handle error
                            }
                        }

                        *jwk_set.write().await = result;
                    }
                    Err(err) => *jwk_set.write().await = Err(err),
                }
            }

            *oidc_config.write().await = result;
            ongoing_kc_request.store(false, std::sync::atomic::Ordering::Release);
        });
    }

    pub(crate) fn is_ready(&self) -> bool {
        !self
            .ongoing_kc_request
            .load(std::sync::atomic::Ordering::Acquire)
    }

    async fn provide_decoding_keys<'a>(
        &'a self,
        header: &jsonwebtoken::Header,
    ) -> impl Iterator<Item = jsonwebtoken::DecodingKey> + 'a {
        // TODO: This should return an Iterator over `&'a DecodingKey`!
        let lock = self.decoding_keys.read().await;
        DecodingKeyIter { lock, index: 0 }
    }

    // If known key works, use it.
    // If known key does not work, fetch updated keys.
    // If fetch already happened in interval, reject immediately.
    // Only fetch is async.
    // Operation should not block.
    pub(crate) async fn process_request(
        &self,
        request_headers: http::HeaderMap<http::HeaderValue>,
    ) -> Result<(Option<HashMap<String, serde_json::Value>>, KeycloakToken<R>), AuthError> {
        let raw_token = extract_jwt_token(&request_headers)?;
        let header = raw_token.decode_header()?;
        let decoding_keys = self.provide_decoding_keys(&header).await;
        let raw_claims =
            raw_token.decode(header, self.expected_audiences.as_slice(), decoding_keys)?;
        let raw_claims_clone = match self.persist_raw_claims {
            true => Some(raw_claims.clone()),
            false => None,
        };
        let standard_claims = StandardClaims::parse(raw_claims)?;
        let keycloak_token = KeycloakToken::<R>::parse(standard_claims)?;
        keycloak_token.assert_not_expired()?;
        keycloak_token.expect_roles(&self.required_roles)?;
        Ok((raw_claims_clone, keycloak_token))
    }
}

fn parse_jwks(jwk_set: &JwkSet) -> Vec<DecodingKey> {
    jwk_set.keys.iter().map(|jwk| {
        match jsonwebtoken::DecodingKey::from_jwk(jwk) {
            Ok(decoding_key) => Some(decoding_key),
            Err(err) => {
                tracing::error!(?err, "Received JWK from Keycloak which could not be parsed as a DecodingKey. Ignoring the JWK.");
                None
            },
        }
    }).flatten().collect::<Vec<_>>()
}

struct DecodingKeyIter<'a> {
    lock: RwLockReadGuard<'a, Vec<DecodingKey>>,
    index: usize,
}

impl<'a> Iterator for DecodingKeyIter<'a> {
    type Item = DecodingKey;

    fn next(&mut self) -> Option<Self::Item> {
        // TODO: If none, all known keys did not suffice. Trigger a token refresh and continue trying with new keys. If last refresh was too recent, break immediately.

        let next = self.lock.get(self.index).cloned();
        self.index += 1;
        next
    }
}
