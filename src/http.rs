//! HTTP requests for OIDC discovery and JWKS documents.

use std::sync::Arc;

use reqwest::IntoUrl;
use serde::de::DeserializeOwned;
use snafu::ResultExt;

use crate::error::{RequestError, request_error};

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
