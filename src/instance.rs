use std::{collections::HashMap, marker::PhantomData, ops::Deref, sync::Arc};

use jsonwebtoken::{jwk::JwkSet, DecodingKey};
use snafu::ResultExt;
use tokio::{
    sync::{RwLock, RwLockReadGuard},
    task::JoinHandle,
};
use try_again::Retry;
use typed_builder::TypedBuilder;
use url::Url;

use crate::{
    decode::{extract_jwt_token, KeycloakToken, StandardClaims},
    error::{AuthError, JwkEndpointSnafu, JwkSetDiscoverySnafu, OidcDiscoverySnafu},
    oidc::OidcConfig,
    oidc_discovery,
    role::{ExpectRoles, Role},
};

#[derive(Debug, Clone)]
pub(crate) struct OidcDiscoveryEndpoint(pub(crate) Url);

impl OidcDiscoveryEndpoint {
    pub(crate) fn from_server_and_realm(server: Url, realm: &str) -> Self {
        let mut url = server;
        url.path_segments_mut()
            .expect("to allow path segments on Keycloak server url")
            .extend(&["realms", &realm, ".well-known", "openid-configuration"]);
        Self(url)
    }
}

impl Deref for OidcDiscoveryEndpoint {
    type Target = Url;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

#[derive(TypedBuilder)]
pub struct KeycloakConfig {
    pub server: Url,
    pub realm: String,
}

// TODO: Does this really need to be generic over the role type?
pub struct KeycloakAuthInstance<R: Role> {
    pub(crate) id: uuid::Uuid,
    pub(crate) base: KeycloakConfig,
    pub(crate) oidc_discovery_endpoint: OidcDiscoveryEndpoint,
    pub(crate) oidc_config: Arc<RwLock<Result<OidcConfig, AuthError>>>,
    pub(crate) jwk_set: Arc<RwLock<Result<JwkSet, AuthError>>>,
    pub(crate) decoding_keys: Arc<RwLock<Vec<DecodingKey>>>,
    pub(crate) discovery: Arc<RwLock<Option<JoinHandle<()>>>>,
    pub(crate) last_discovery_start: Arc<RwLock<std::time::Instant>>,
    pub(crate) phantom_data: PhantomData<R>,
}

impl<R: Role> KeycloakAuthInstance<R> {
    pub async fn new(kc_config: KeycloakConfig) -> Self {
        let oidc_discovery_endpoint = OidcDiscoveryEndpoint::from_server_and_realm(
            kc_config.server.clone(),
            &kc_config.realm,
        );

        let first_discovery_start = std::time::Instant::now();
        let this = Self {
            id: uuid::Uuid::now_v7(),
            base: kc_config,
            oidc_discovery_endpoint,
            oidc_config: Arc::new(RwLock::new(Err(AuthError::NoOidcDiscovery))),
            jwk_set: Arc::new(RwLock::new(Err(AuthError::NoJwkSetDiscovery))),
            decoding_keys: Arc::new(RwLock::new(Vec::new())),
            discovery: Arc::new(RwLock::new(None)),
            last_discovery_start: Arc::new(RwLock::new(first_discovery_start)),
            phantom_data: PhantomData,
        };
        let jh = this.perform_async_oidc_discovery();
        *this.discovery.write().await = Some(jh);
        this
    }

    /// Starts the asynchronous OIDC discovery process or returns immediately with the current discovery state
    /// when there still is an ongoing discovery.
    async fn start_async_oidc_discovery(&self) -> JoinHandle<()> {
        let current_discovery = self
            .discovery
            .write()
            .await
            .take()
            .expect("always to have a discovery state");
        if !current_discovery.is_finished() {
            tracing::debug!("Skipping discovery request, as there is still a discovery in flight.");
            return current_discovery;
        }
        let started = std::time::Instant::now();
        *self.last_discovery_start.write().await = started;
        let jh = self.perform_async_oidc_discovery();
        jh
    }

    #[tracing::instrument(level="info", skip_all, fields(id = ?self.id, kc_server = self.base.server.to_string(), kc_realm = self.base.realm))]
    fn perform_async_oidc_discovery(&self) -> JoinHandle<()> {
        let oidc_discovery_endpoint = self.oidc_discovery_endpoint.clone();
        let oidc_config = self.oidc_config.clone();
        let jwk_set = self.jwk_set.clone();
        let decoding_keys = self.decoding_keys.clone();

        tokio::spawn(async move {
            perform_async_oidc_discovery(
                oidc_discovery_endpoint,
                oidc_config,
                jwk_set,
                decoding_keys,
            )
            .await;
        })
    }

    pub fn is_ready(&self) -> bool {
        true
        /*
        // TODO: Cannot block the current thread from within a runtime.
        self.discovery
            .blocking_read()
            .as_ref()
            .map_or(true, |d| d.is_finished())
        */
    }

    pub(crate) async fn decoding_keys_iter<'a>(
        &'a self,
        header: &jsonwebtoken::Header, // TODO: pre-filter based on header?
    ) -> impl Iterator<Item = jsonwebtoken::DecodingKey> + 'a {
        // TODO: This block writers...
        DecodingKeyIter {
            lock: self.decoding_keys.read().await,
            index: 0,
        }
    }

    // If known key works, use it.
    // If known key does not work, fetch updated keys.
    // If fetch already happened in interval, reject immediately.
    // Only fetch is async.
    // Operation should not block.
    pub(crate) async fn process_request(
        &self,
        request_headers: http::HeaderMap<http::HeaderValue>,
        expected_audiences: Vec<String>,
        persist_raw_claims: bool,
        required_roles: Vec<R>,
    ) -> Result<(Option<HashMap<String, serde_json::Value>>, KeycloakToken<R>), AuthError> {
        let raw_token = extract_jwt_token(&request_headers)?;
        let header = raw_token.decode_header()?;

        // First decode. This may fail if known decoding keys are out of date (Keycloak server changed).
        let decoding_keys = self.decoding_keys_iter(&header).await;
        let mut raw_claims =
            raw_token.decode(&header, expected_audiences.as_slice(), decoding_keys);

        if raw_claims.is_err() {
            // Reload decoding keys. Note that this will delay handling of the request in flight by a substantial amount of time
            // but may allow us to acknowledge it in the end without rejecting the call immediately, requiring a retry from our callers!
            // TODO: Make this an optional behavior.
            let _ = self
                .start_async_oidc_discovery()
                .await // Await the start of a new discovery.
                .await // Await the actual discovery being finished.
                .expect("No Join error"); // TODO: Error handling

            // Second decode
            let decoding_keys = self.decoding_keys_iter(&header).await;
            raw_claims = raw_token.decode(&header, expected_audiences.as_slice(), decoding_keys);
        }

        let raw_claims = raw_claims?;

        let raw_claims_clone = match persist_raw_claims {
            true => Some(raw_claims.clone()),
            false => None,
        };
        let standard_claims = StandardClaims::parse(raw_claims)?;
        let keycloak_token = KeycloakToken::<R>::parse(standard_claims)?;
        keycloak_token.assert_not_expired()?;
        keycloak_token.expect_roles(&required_roles)?;
        Ok((raw_claims_clone, keycloak_token))
    }
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

// #[tracing::instrument(level="info", skip_all, fields(id = ?self.id, kc_server = self.base.server.to_string(), kc_realm = self.base.realm))]
async fn perform_async_oidc_discovery(
    oidc_discovery_endpoint: OidcDiscoveryEndpoint,
    oidc_config: Arc<RwLock<Result<OidcConfig, AuthError>>>,
    jwk_set: Arc<RwLock<Result<JwkSet, AuthError>>>,
    decoding_keys: Arc<RwLock<Vec<DecodingKey>>>,
) {
    tracing::info!(
        oidc_discovery_endpoint = oidc_discovery_endpoint.0.to_string(),
        "Performing OIDC discovery.",
    );

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
                let result = try_again::retry_async(
                    Retry {
                        max_tries: 5,
                        delay: Some(try_again::Delay::Static {
                            delay: std::time::Duration::from_secs(1),
                        }),
                    },
                    try_again::TokioSleep {},
                    move || {
                        let url = jwk_set_endpoint.clone();
                        async move {
                            oidc_discovery::retrieve_jwk_set(url.clone())
                                .await
                                .context(JwkSetDiscoverySnafu {})
                        }
                    },
                )
                .await;

                match &result {
                    Ok(jwk_set) => {
                        tracing::debug!("Received jwk_set containing {} keys.", jwk_set.keys.len());

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
            Err(err) => {
                tracing::error!(
                    err = snafu::Report::from_error(err.clone()).to_string(),
                    "Could not retrieve jwk_set_endpoint_url."
                );
                *jwk_set.write().await = Err(err);
            }
        }
    }

    *oidc_config.write().await = result;
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
