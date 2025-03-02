use std::ops::Deref;

use educe::Educe;
use snafu::ResultExt;
use tokio::sync::RwLockReadGuard;
use tracing::Instrument;
use try_again::{StdDuration, delay, retry_async};
use typed_builder::TypedBuilder;
use url::Url;

use crate::{
    action::Action,
    error::{AuthError, JwkEndpointSnafu, JwkSetDiscoverySnafu, OidcDiscoverySnafu},
    oidc::OidcConfig,
    oidc_discovery,
};

#[derive(Debug, Clone)]
pub(crate) struct OidcDiscoveryEndpoint(pub(crate) Url);

impl OidcDiscoveryEndpoint {
    pub(crate) fn from_server_and_realm(server: Url, realm: &str) -> Self {
        let mut url = server;
        url.path_segments_mut()
            .expect("URL not to be a 'cannot-be-a-base' URL. We have to append segments.")
            .extend(&["realms", realm, ".well-known", "openid-configuration"]);
        Self(url)
    }
}

impl Deref for OidcDiscoveryEndpoint {
    type Target = Url;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

#[derive(Debug, TypedBuilder)]
pub struct KeycloakConfig {
    /// Base URL of your Keycloak server. For example: `Url::parse("https://localhost:8443/").unwrap()`.
    pub server: Url,

    /// The realm of you Keycloak server.
    pub realm: String,

    /// The retry strategy to be used: (maximum tries, delay in seconds).
    #[builder(default = (5, 1))]
    pub retry: (usize, u64),
}

fn debug_decoding_keys(
    decoding_keys: &[jsonwebtoken::DecodingKey],
    f: &mut std::fmt::Formatter<'_>,
) -> std::fmt::Result {
    f.write_fmt(format_args!("len: {}", decoding_keys.len()))
}

#[derive(TypedBuilder, Educe)]
#[educe(Debug)]
pub(crate) struct DiscoveredData {
    #[allow(dead_code)]
    pub(crate) oidc_config: OidcConfig,
    #[allow(dead_code)]
    pub(crate) jwk_set: jsonwebtoken::jwk::JwkSet,
    #[educe(Debug(method(debug_decoding_keys)))]
    pub(crate) decoding_keys: Vec<jsonwebtoken::DecodingKey>,
}

/// The KeycloakAuthInstance is responsible for performing OIDC discovery
/// and will hold onto the retrieved OIDC configuration, including the decoding keys
/// used to decode incoming JWTs.
///
/// You may want to create only a single insatnce of this struct
/// to limit the amount of requests made towards your Keycloak server.
#[derive(Debug)]
pub struct KeycloakAuthInstance {
    #[allow(dead_code)]
    pub(crate) id: uuid::Uuid,
    #[allow(dead_code)]
    pub(crate) config: KeycloakConfig,
    pub(crate) oidc_discovery_endpoint: OidcDiscoveryEndpoint,
    pub(crate) discovery: Action<OidcDiscoveryEndpoint, Result<DiscoveredData, AuthError>>,
}

impl KeycloakAuthInstance {
    /// Creates a new KeycloakAuthInstance. This immediately starts an initial OIDC discovery process.
    /// The `is_operational` method will tell you if discovery has taken place.
    /// This may be useful in determining service health.
    pub fn new(kc_config: KeycloakConfig) -> Self {
        let id = uuid::Uuid::now_v7();
        let oidc_discovery_endpoint = OidcDiscoveryEndpoint::from_server_and_realm(
            kc_config.server.clone(),
            &kc_config.realm,
        );

        let kc_server = kc_config.server.to_string();
        let kc_realm = kc_config.realm.clone();

        let discovery = Action::new(move |oidc_discovery_endpoint: &OidcDiscoveryEndpoint| {
            let kc_server = kc_server.clone();
            let kc_realm = kc_realm.clone();
            let oidc_discovery_endpoint = oidc_discovery_endpoint.clone();

            async move {
                let span = tracing::span!(
                    tracing::Level::INFO,
                    "perform_oidc_discovery",
                    kc_instance_id = ?id,
                    kc_server,
                    kc_realm,
                    oidc_discovery_endpoint = ?oidc_discovery_endpoint.0.to_string()
                );
                perform_oidc_discovery(
                    oidc_discovery_endpoint,
                    kc_config.retry.0,
                    std::time::Duration::from_secs(kc_config.retry.1),
                )
                .instrument(span)
                .await
            }
        });

        discovery.dispatch(oidc_discovery_endpoint.clone());

        Self {
            id,
            config: kc_config,
            oidc_discovery_endpoint,
            discovery,
        }
    }

    pub(crate) async fn perform_oidc_discovery(&self) {
        // Wait for an ongoing discovery or dispatch a new discovery process.
        if self.discovery.is_pending() {
            self.discovery.notified().await;
        } else {
            self.discovery
                .dispatch(self.oidc_discovery_endpoint.clone())
                .await
                .expect("No Join error");
        }
    }

    /// Returns true after a successful OIDC discovery.
    pub async fn is_operational(&self) -> bool {
        self.discovery
            .value()
            .await
            .as_ref()
            .is_some_and(|it| it.is_ok())
    }

    pub(crate) async fn decoding_keys(&self) -> DecodingKeys<'_> {
        DecodingKeys {
            // Note: Tokio's RwLock implementation prioritizes write access to prevent starvation. This is fine and will not block writes.
            lock: self.discovery.value().await,
        }
    }
}

pub(crate) struct DecodingKeys<'a> {
    lock: RwLockReadGuard<'a, Option<Result<DiscoveredData, AuthError>>>,
}

impl DecodingKeys<'_> {
    /// Iterate over the currently known decoding keys.
    /// This may return an empty iterator if no keys are known!
    pub(crate) fn iter(&self) -> impl Iterator<Item = &jsonwebtoken::DecodingKey> {
        self.lock
            .as_ref()
            .map(|r| r.as_ref())
            .and_then(|r| r.ok())
            .map(|d| d.decoding_keys.iter())
            .unwrap_or_default()
    }
}

async fn perform_oidc_discovery(
    oidc_discovery_endpoint: OidcDiscoveryEndpoint,
    num_retries: usize,
    fixed_delay: StdDuration,
) -> Result<DiscoveredData, AuthError> {
    tracing::info!("Starting OIDC discovery.");

    // Load OIDC config.
    let oidc_config = retry_async(async move || {
        oidc_discovery::retrieve_oidc_config(oidc_discovery_endpoint.0.clone())
            .await
            .context(OidcDiscoverySnafu {})
    })
    .delayed_by(delay::Fixed::of(fixed_delay).take(num_retries))
    .await
    .inspect_err(|err| {
        tracing::error!(
            err = snafu::Report::from_error(err.clone()).to_string(),
            "Could not retrieve OIDC config."
        );
    })?;

    // Parse JWK endpoint if OIDC config is available.
    let jwk_set_endpoint = Url::parse(&oidc_config.standard_claims.jwks_uri)
        .context(JwkEndpointSnafu {})
        .inspect_err(|err| {
            tracing::error!(
                err = snafu::Report::from_error(err.clone()).to_string(),
                "Could not retrieve jwk_set_endpoint_url."
            );
        })?;

    // Load JWK set if endpoint was parsable.
    let jwk_set = retry_async(async move || {
        oidc_discovery::retrieve_jwk_set(jwk_set_endpoint.clone())
            .await
            .context(JwkSetDiscoverySnafu {})
    })
    .delayed_by(delay::Fixed::of(fixed_delay).take(num_retries))
    .await
    .inspect_err(|err| {
        tracing::error!(
            err = snafu::Report::from_error(err.clone()).to_string(),
            "Could not retrieve jwk_set."
        );
    })?;

    let num_keys = jwk_set.keys.len();
    tracing::info!(
        "Received new jwk_set containing {num_keys} {}.",
        match num_keys {
            1 => "key",
            _ => "keys",
        }
    );

    // Create DecodingKey instances from received JWKs.
    let decoding_keys = parse_jwks(&jwk_set);

    Ok(DiscoveredData {
        oidc_config,
        jwk_set,
        decoding_keys,
    })
}

fn parse_jwks(jwk_set: &jsonwebtoken::jwk::JwkSet) -> Vec<jsonwebtoken::DecodingKey> {
    jwk_set.keys.iter().filter_map(|jwk| {
        match jsonwebtoken::DecodingKey::from_jwk(jwk) {
            Ok(decoding_key) => Some(decoding_key),
            Err(err) => {
                tracing::error!(?err, "Received JWK from Keycloak which could not be parsed as a DecodingKey. Ignoring the JWK.");
                None
            }
        }
    }).collect::<Vec<_>>()
}
