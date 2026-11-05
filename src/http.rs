//! HTTP client for OIDC discovery and JWKS requests.

use std::sync::Arc;
use std::time::Duration;

use reqwest::IntoUrl;
use serde::de::DeserializeOwned;
use snafu::ResultExt;

use crate::error::{RequestError, request_error};

const DEFAULT_CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
const DEFAULT_REQUEST_TIMEOUT: Duration = Duration::from_secs(30);

/// Builds the shared provider HTTP client with connection pooling, a 10-second connect timeout,
/// and a 30-second total-request timeout.
pub(crate) fn default_http_client() -> reqwest::Client {
    reqwest::Client::builder()
        .connect_timeout(DEFAULT_CONNECT_TIMEOUT)
        .timeout(DEFAULT_REQUEST_TIMEOUT)
        .build()
        .expect("the default HTTP client must build (TLS backend initialization)")
}

/// Performs a GET request against `endpoint` and deserializes the JSON response body into `T`,
/// treating non-success HTTP statuses as errors.
pub(crate) async fn retrieve_json<T: DeserializeOwned>(
    client: &reqwest::Client,
    endpoint: impl IntoUrl,
) -> Result<T, RequestError> {
    client
        .get(endpoint)
        .send()
        .await
        .and_then(reqwest::Response::error_for_status)
        .map_err(Arc::new)
        .context(request_error::SendSnafu)?
        .json::<T>()
        .await
        .map_err(Arc::new)
        .context(request_error::DecodeSnafu)
}
