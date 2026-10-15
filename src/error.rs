//! Errors returned by connection, token validation, extraction, and policy construction.

use std::{borrow::Cow, sync::Arc};

use axum::{
    Json,
    http::{HeaderValue, StatusCode, header::WWW_AUTHENTICATE},
    response::{IntoResponse, Response},
};
use serde_json::json;
use snafu::Snafu;

use crate::http::RequestError;

/// Errors returned by [`crate::instance::KeycloakAuthInstance::connect`].
#[derive(Debug, Snafu)]
#[non_exhaustive]
pub enum ConnectError {
    /// The configured Keycloak server URL cannot be used as a base URL, so no realm endpoints can
    /// be derived from it.
    #[snafu(display("The Keycloak server URL cannot be used as a base URL."))]
    InvalidServerUrl,

    /// The initial OIDC discovery failed.
    #[snafu(display("The initial OIDC discovery failed."))]
    InitialDiscovery {
        /// The discovery or key-processing error.
        source: AuthError,
    },
}

/// Errors returned when a [`crate::validation::ValidationPolicy`] is built from inconsistent
/// requirements.
#[derive(Debug, Clone, PartialEq, Eq, Snafu)]
#[non_exhaustive]
pub enum ValidationPolicyError {
    /// The policy validates the token issuer, but no expected issuers were configured.
    #[snafu(display(
        "The policy validates the token issuer, but no expected issuers were configured."
    ))]
    MissingExpectedIssuers,

    /// The policy requires a matching audience, but the configured expected audiences are empty.
    #[snafu(display(
        "The policy requires a matching audience, but the configured expected audiences are empty."
    ))]
    MissingExpectedAudiences,

    /// An empty algorithm allowlist was configured, which would reject every token.
    #[snafu(display(
        "An empty algorithm allowlist was configured, which would reject every token."
    ))]
    MissingAllowedAlgorithms,

    /// An empty set of accepted token types was configured, which would reject every token.
    #[snafu(display(
        "An empty set of accepted token types was configured, which would reject every token."
    ))]
    MissingAcceptedTokenTypes,

    /// An empty set of allowed authorized parties was configured, which would reject every token.
    #[snafu(display(
        "An empty set of allowed authorized parties was configured, which would reject every token."
    ))]
    MissingAllowedAuthorizedParties,
}

/// Errors surfaced by the authentication and middleware API.
///
/// The extraction-related variants are part of [`crate::extract::TokenExtractor::extract`]'s
/// contract. [`Self::MissingAuthorizationHeader`], [`Self::MissingQueryParams`],
/// [`Self::MissingTokenQueryParam`], and [`Self::MissingToken`] mean that an extractor's
/// credential source was absent. Other extraction errors mean that a source was present but
/// unusable.
///
/// The error retains underlying sources and validation reasons for direct validation and
/// [`crate::PassthroughMode::Pass`] consumers. Its [`IntoResponse`] implementation returns:
///
/// - `401 Unauthorized` for token-extraction errors and unavailable decoding keys.
/// - `401 Unauthorized` with the OAuth `invalid_token` code for JWT decoding and validation errors.
/// - `403 Forbidden` for role failures.
/// - `500 Internal Server Error` for OIDC or JWKS request, endpoint, and key-conversion failures.
///
/// [`crate::layer::KeycloakAuthLayer::dangerously_log_authentication_errors`] controls detailed
/// logging of the final middleware error, while
/// [`crate::layer::KeycloakAuthLayer::dangerously_log_token_extraction_errors`] independently
/// controls per-extractor error logging. Neither setting changes these responses.
#[derive(Debug, Clone, Snafu)]
#[snafu(visibility(pub(crate)))]
pub enum AuthError {
    /// No OIDC discovery document is available.
    #[snafu(display("Never discovered an OIDC configuration."))]
    NoOidcDiscovery,

    /// The OIDC discovery request failed.
    #[snafu(display("Could not discover OIDC configuration."))]
    OidcDiscovery {
        #[snafu(backtrace)]
        /// The provider request error.
        source: RequestError,
    },

    /// No JWKS is available.
    ///
    /// Retained for compatibility. Current discovery reports [`Self::NoDecodingKeys`] when a
    /// provider response contains no usable keys.
    #[snafu(display("Never discovered a JWK set."))]
    NoJwkSetDiscovery,

    /// The JWKS endpoint was not a valid URL.
    #[snafu(display("Could not parse the JWK endpoint."))]
    JwkEndpoint {
        /// The URL parsing error.
        source: url::ParseError,
    },

    /// The JWKS request failed.
    #[snafu(display("Could not discover the JWK set."))]
    JwkSetDiscovery {
        /// The provider request error.
        source: RequestError,
    },

    /// The `Authorization` header was absent.
    #[snafu(display("The 'Authorization' header was not present on a request."))]
    MissingAuthorizationHeader,

    /// The `Authorization` header was present but could not be represented as a string.
    #[snafu(display(
        "The 'Authorization' header was present on a request but its value could not be parsed. Reason: {reason}"
    ))]
    InvalidAuthorizationHeader {
        /// Why the header value could not be parsed.
        reason: String,
    },

    /// The `Authorization` header did not contain a non-blank `Bearer <token>` value.
    #[snafu(display(
        "The 'Authorization' header did not contain the expected 'Bearer ...token' format."
    ))]
    MissingBearerToken,

    /// The request URI had no query string.
    #[snafu(display("No query parameters were found on the request."))]
    MissingQueryParams,

    /// The query string did not contain the configured token parameter.
    #[snafu(display(
        "Query parameters were found on the request, but the expected token parameter wasn't."
    ))]
    MissingTokenQueryParam,

    /// The configured token parameter was present but blank.
    #[snafu(display(
        "Query parameters were found on the request, and the expected token parameter was found, but it had no value assigned (\"?token=\")."
    ))]
    EmptyTokenQueryParam,

    /// No JWT could be extracted from the request.
    #[snafu(display("No JWT could be extracted from the request."))]
    MissingToken,

    /// A provider JWK could not be converted into a decoding key.
    ///
    /// Retained for compatibility. Current discovery skips unusable individual JWKs and reports
    /// [`Self::NoDecodingKeys`] if none remain.
    #[snafu(display(
        "The DecodingKey, required for decoding tokens, could not be created. Source: {source}"
    ))]
    CreateDecodingKey {
        /// The key-conversion error.
        source: jsonwebtoken::errors::Error,
    },

    /// The JWT header could not be decoded.
    #[snafu(display("The JWT header could not be decoded. Source: {source}"))]
    DecodeHeader {
        /// The header decoding error.
        source: jsonwebtoken::errors::Error,
    },

    /// No usable decoding keys are currently available.
    #[snafu(display("There were no decoding keys available."))]
    NoDecodingKeys,

    /// The JWT could not be decoded.
    #[snafu(display("The JWT could not be decoded. Source: {source}"))]
    Decode {
        /// The signature or JWT decoding error.
        source: jsonwebtoken::errors::Error,
    },

    /// The verified claims could not be deserialized into the configured token model.
    #[snafu(display("Parts of the JWT could not be parsed. Source: {source}"))]
    JsonParse {
        /// The claims deserialization error.
        source: Arc<serde_json::Error>,
    },

    /// The token has expired.
    #[snafu(display("The tokens lifetime is expired."))]
    TokenExpired,

    /// The token or credential value is invalid and no more specific variant applies.
    #[snafu(display(
        "For a not further known reason, the token was deemed invalid: Reason: {reason}"
    ))]
    InvalidToken {
        /// Why validation failed.
        reason: String,
    },

    /// A required role was absent. HTTP responses omit the role name.
    #[snafu(display("An expected role (omitted for security reasons) was missing."))]
    MissingExpectedRole {
        /// The missing role's display name.
        role: String,
    },

    /// An unexpected role was present.
    #[snafu(display("An unexpected role was present."))]
    UnexpectedRole,
}

impl IntoResponse for AuthError {
    fn into_response(self) -> Response {
        let (status, error_message) = match self {
            AuthError::DecodeHeader { .. }
            | AuthError::Decode { .. }
            | AuthError::JsonParse { .. }
            | AuthError::TokenExpired
            | AuthError::InvalidToken { .. } => return invalid_token_response(),
            err @ (AuthError::NoOidcDiscovery
            | AuthError::OidcDiscovery { source: _ }
            | AuthError::NoJwkSetDiscovery
            | AuthError::JwkEndpoint { source: _ }
            | AuthError::JwkSetDiscovery { source: _ }
            | AuthError::CreateDecodingKey { source: _ }) => (
                StatusCode::INTERNAL_SERVER_ERROR,
                Cow::Owned(err.to_string()),
            ),
            err @ (AuthError::MissingAuthorizationHeader
            | AuthError::InvalidAuthorizationHeader { reason: _ }
            | AuthError::MissingBearerToken
            | AuthError::MissingQueryParams
            | AuthError::MissingTokenQueryParam
            | AuthError::EmptyTokenQueryParam
            | AuthError::MissingToken
            | AuthError::NoDecodingKeys) => (StatusCode::UNAUTHORIZED, Cow::Owned(err.to_string())),
            AuthError::MissingExpectedRole { .. } => (
                StatusCode::FORBIDDEN,
                Cow::Borrowed("Missing expected role"),
            ),
            err @ AuthError::UnexpectedRole => (StatusCode::FORBIDDEN, Cow::Owned(err.to_string())),
        };
        let body = Json(json!({
            "error": error_message,
        }));
        (status, body).into_response()
    }
}

fn invalid_token_response() -> Response {
    let body = Json(json!({
        "error": "invalid_token",
    }));
    (
        StatusCode::UNAUTHORIZED,
        [(
            WWW_AUTHENTICATE,
            HeaderValue::from_static("Bearer error=\"invalid_token\""),
        )],
        body,
    )
        .into_response()
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use assertr::prelude::*;
    use axum::{
        body::to_bytes,
        http::{StatusCode, header::WWW_AUTHENTICATE},
        response::IntoResponse,
    };

    use super::AuthError;

    #[tokio::test]
    async fn malformed_claim_parse_errors_are_sanitized_as_invalid_token() {
        let source = serde_json::from_value::<i64>(serde_json::json!({ "malformed": true }))
            .expect_err("an object cannot be parsed as an integer claim");
        let error = AuthError::JsonParse {
            source: Arc::new(source),
        };
        assert_that!(error.to_string()).contains("invalid type: map, expected i64");

        assert_invalid_token_response(error).await;
    }

    #[tokio::test]
    async fn token_validation_errors_share_one_invalid_token_response() {
        use jsonwebtoken::errors::{Error, ErrorKind};

        for error in [
            AuthError::DecodeHeader {
                source: Error::from(ErrorKind::InvalidToken),
            },
            AuthError::Decode {
                source: Error::from(ErrorKind::InvalidSignature),
            },
            AuthError::TokenExpired,
            AuthError::InvalidToken {
                reason: String::from("application-specific validation detail"),
            },
        ] {
            assert_invalid_token_response(error).await;
        }
    }

    #[tokio::test]
    async fn missing_expected_role_response_omits_role_name() {
        let response = AuthError::MissingExpectedRole {
            role: String::from("sensitive-administrator-role"),
        }
        .into_response();

        assert_that!(response.status()).is_equal_to(StatusCode::FORBIDDEN);
        let body = to_bytes(response.into_body(), 1024)
            .await
            .expect("the JSON response body must be readable");
        let body = std::str::from_utf8(&body).expect("the JSON response body must be UTF-8");
        assert_that!(body)
            .is_equal_to(r#"{"error":"Missing expected role"}"#)
            .does_not_contain("sensitive-administrator-role");
    }

    async fn assert_invalid_token_response(error: AuthError) {
        let response = error.into_response();

        assert_that!(response.status()).is_equal_to(StatusCode::UNAUTHORIZED);
        assert_that!(response.headers().get(WWW_AUTHENTICATE).cloned())
            .some()
            .ascii()
            .is_equal_to("Bearer error=\"invalid_token\"");
        let body = to_bytes(response.into_body(), 1024)
            .await
            .expect("the JSON response body must be readable");
        let body = std::str::from_utf8(&body).expect("the JSON response body must be UTF-8");
        assert_that!(body)
            .is_equal_to(r#"{"error":"invalid_token"}"#)
            .does_not_contain("expected i64");
    }
}
