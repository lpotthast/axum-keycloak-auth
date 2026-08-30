//! Fetch an OIDC discovery document and JWKS over HTTP with fixed-delay retries.
//!
//! [`super::lifecycle`] supplies refresh coordination and cache state.

use std::{sync::Arc, time::Duration};

use reqwest::IntoUrl;
use serde::Deserialize;
use snafu::ResultExt;
use tracing::Instrument;
use try_again::{StdDuration, delay, retry_async};
use url::Url;

use crate::{
    error::{AuthError, JwkEndpointSnafu, JwkSetDiscoverySnafu, OidcDiscoverySnafu},
    http::{RequestError, retrieve_json},
    oidc::OidcConfig,
};

use super::{DiscoveredData, DiscoveryOp, DiscoveryRequest, OidcDiscoveryEndpoint};

/// Creates the production discovery operation with fixed-delay retries and request tracing.
pub(crate) fn default_discovery_op(
    client: reqwest::Client,
    instance_id: uuid::Uuid,
    kc_server: String,
    kc_realm: String,
    retry: (usize, u64),
) -> DiscoveryOp {
    Arc::new(
        move |endpoint: OidcDiscoveryEndpoint, request: DiscoveryRequest| {
            let client = client.clone();
            let kc_server = kc_server.clone();
            let kc_realm = kc_realm.clone();
            Box::pin(async move {
                let span = tracing::span!(
                    tracing::Level::INFO,
                    "perform_oidc_discovery",
                    kc_instance_id = ?instance_id,
                    kc_server,
                    kc_realm,
                    oidc_discovery_endpoint = ?endpoint.0.to_string(),
                    discovery_attempt = request.attempt,
                    discovery_kind = ?request.kind,
                );
                perform_oidc_discovery(client, endpoint, retry.0, Duration::from_secs(retry.1))
                    .instrument(span)
                    .await
                    .map(Arc::new)
            })
        },
    )
}

async fn perform_oidc_discovery(
    client: reqwest::Client,
    oidc_discovery_endpoint: OidcDiscoveryEndpoint,
    num_retries: usize,
    fixed_delay: StdDuration,
) -> Result<DiscoveredData, AuthError> {
    tracing::info!("Starting OIDC discovery.");

    // Load the OIDC configuration, deserialized as the full canonical discovery document.
    let oidc_config_client = client.clone();
    let oidc_config = retry_async(async move || {
        retrieve_oidc_config(&oidc_config_client, oidc_discovery_endpoint.0.clone())
            .await
            .context(OidcDiscoverySnafu {})
    })
    .delayed_by(delay::Fixed::of(fixed_delay).take(num_retries))
    .await?;

    // Parse JWK endpoint if the OIDC configuration is available.
    let jwk_set_endpoint =
        Url::parse(&oidc_config.standard_claims.jwks_uri).context(JwkEndpointSnafu {})?;

    // Load JWK set if endpoint was parsable.
    let jwk_set = retry_async(async move || {
        retrieve_jwk_set(&client, jwk_set_endpoint.clone())
            .await
            .context(JwkSetDiscoverySnafu {})
    })
    .delayed_by(delay::Fixed::of(fixed_delay).take(num_retries))
    .await?;

    let num_keys = jwk_set.keys.len();
    tracing::info!(
        "Received new jwk_set containing {num_keys} {}.",
        match num_keys {
            1 => "key",
            _ => "keys",
        }
    );

    Ok(DiscoveredData::new(oidc_config, &jwk_set))
}

/// Retrieves the provider's OIDC discovery document.
async fn retrieve_oidc_config(
    client: &reqwest::Client,
    discovery_endpoint: impl IntoUrl,
) -> Result<OidcConfig, RequestError> {
    retrieve_json::<OidcConfig>(client, discovery_endpoint).await
}

/// Retrieves the provider's JWKS, skipping entries that cannot be deserialized as JWKs.
async fn retrieve_jwk_set(
    client: &reqwest::Client,
    jwk_set_endpoint: impl IntoUrl,
) -> Result<jsonwebtoken::jwk::JwkSet, RequestError> {
    #[derive(Deserialize)]
    struct RawJwkSet {
        keys: Vec<serde_json::Value>,
    }

    let raw_set = retrieve_json::<RawJwkSet>(client, jwk_set_endpoint).await?;
    let mut set = jsonwebtoken::jwk::JwkSet { keys: Vec::new() };
    for key in raw_set.keys {
        match serde_json::from_value::<jsonwebtoken::jwk::Jwk>(key) {
            Ok(parsed) => set.keys.push(parsed),
            Err(err) => tracing::warn!(?err, "Found non-decodable JWK"),
        }
    }
    Ok(set)
}
