//! Errors returned by instance construction, token validation, extraction, and policy
//! construction.

use std::{borrow::Cow, sync::Arc};

use axum::{
    Json,
    http::{HeaderValue, StatusCode, header::WWW_AUTHENTICATE},
    response::{IntoResponse, Response},
};
use serde_json::json;
use snafu::Snafu;
use url::Url;

/// Errors returned while retrieving an OIDC discovery document or JWKS.
#[derive(Debug, Clone, Snafu)]
#[snafu(module(request_error), visibility(pub(crate)))]
#[non_exhaustive]
pub enum RequestError {
    /// The request could not produce a successful HTTP response.
    #[snafu(display("RequestError: Request failed or returned a non-success status"))]
    Send {
        /// The transport, timeout, redirect, or HTTP status error.
        source: Arc<reqwest::Error>,
    },

    /// A successful response body could not be read or decoded as the expected JSON type.
    #[snafu(display("RequestError: Could not decode payload"))]
    Decode {
        /// The body-reading or JSON-decoding error.
        source: Arc<reqwest::Error>,
    },
}

/// A Keycloak server URL rejected while creating a [`ServerUrl`](crate::instance::ServerUrl).
#[derive(Debug, Clone, PartialEq, Eq, Snafu)]
#[snafu(module(invalid_server_url_error), visibility(pub(crate)))]
#[non_exhaustive]
pub enum InvalidServerUrlError {
    /// The input is not a valid URL.
    #[snafu(display(
        "'{input}' cannot be used as a Keycloak server URL because it is not a valid URL \
         ({source}). Use the server's 'http' or 'https' URL, such as 'https://keycloak.example/'."
    ))]
    Parse {
        /// The rejected input.
        input: String,
        /// Why the input could not be parsed.
        source: url::ParseError,
    },

    /// The URL cannot serve as a base URL, such as a `mailto:` URL, so no realm URLs can be
    /// derived from it.
    #[snafu(display(
        "'{url}' cannot be used as a Keycloak server URL because it cannot serve as a base URL. \
         Use the server's 'http' or 'https' URL, such as 'https://keycloak.example/'."
    ))]
    CannotBeABase {
        /// The rejected URL.
        url: Url,
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
    EmptyExpectedAudiences,

    /// An empty algorithm allowlist was configured, which would reject every token.
    #[snafu(display(
        "An empty algorithm allowlist was configured, which would reject every token."
    ))]
    EmptyAllowedAlgorithms,

    /// An empty set of accepted token types was configured, which would reject every token.
    #[snafu(display(
        "An empty set of accepted token types was configured, which would reject every token."
    ))]
    EmptyAcceptedTokenTypes,

    /// An empty set of allowed authorized parties was configured, which would reject every token.
    #[snafu(display(
        "An empty set of allowed authorized parties was configured, which would reject every token."
    ))]
    EmptyAllowedAuthorizedParties,
}

/// Errors surfaced by the authentication and middleware API.
///
/// [`Self::MissingToken`] means that no configured extractor found a credential source.
/// [`Self::TokenExtraction`] means that a source was present but unusable.
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
#[non_exhaustive]
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

    /// A credential source was present but unusable, and
    /// [`TokenExtractionErrorPolicy::Reject`](crate::extract::TokenExtractionErrorPolicy::Reject)
    /// rejected the request.
    ///
    /// The message is generic, so it can be returned in HTTP responses. The source is the
    /// extractor's error, which may contain request data. Downcast it to inspect it, for example
    /// to an [`AuthHeaderExtractError`](crate::extract::AuthHeaderExtractError) or a
    /// [`QueryParamExtractError`](crate::extract::QueryParamExtractError) for the built-in
    /// extractors.
    #[snafu(display("The request carried an unusable credential."))]
    TokenExtraction {
        /// The extractor's error.
        source: Arc<dyn std::error::Error + Send + Sync>,
    },

    /// No JWT could be extracted from the request.
    #[snafu(display("No JWT could be extracted from the request."))]
    MissingToken,

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
            | AuthError::JwkEndpoint { source: _ }
            | AuthError::JwkSetDiscovery { source: _ }) => (
                StatusCode::INTERNAL_SERVER_ERROR,
                Cow::Owned(err.to_string()),
            ),
            err @ (AuthError::TokenExtraction { source: _ }
            | AuthError::MissingToken
            | AuthError::NoDecodingKeys) => {
                // RFC 6750 section 3: a request without usable credentials gets a challenge
                // without an error code.
                return (
                    StatusCode::UNAUTHORIZED,
                    [(WWW_AUTHENTICATE, HeaderValue::from_static("Bearer"))],
                    Json(json!({ "error": err.to_string() })),
                )
                    .into_response();
            }
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
        http::{StatusCode, header::WWW_AUTHENTICATE},
        response::IntoResponse,
    };

    use crate::{extract::BoxError, test_support::response_text};

    use super::{AuthError, RequestError};

    const SENSITIVE_PROVIDER_ADDRESS: &str = "sensitive-provider.internal";

    /// An error whose response describes it, rather than the generic `invalid_token` response.
    struct DescriptiveResponseCase {
        error: AuthError,
        status: StatusCode,
        challenge: Option<&'static str>,
        body: &'static str,
    }

    fn descriptive_response_cases() -> Vec<DescriptiveResponseCase> {
        // RFC 6750 section 3: a request without usable credentials gets a challenge without an
        // error code.
        let missing_credentials = |error, body| DescriptiveResponseCase {
            error,
            status: StatusCode::UNAUTHORIZED,
            challenge: Some("Bearer"),
            body,
        };
        let internal_error = |error, body| DescriptiveResponseCase {
            error,
            status: StatusCode::INTERNAL_SERVER_ERROR,
            challenge: None,
            body,
        };
        vec![
            // The extractor's error never reaches the body.
            missing_credentials(
                AuthError::TokenExtraction {
                    source: Arc::from(BoxError::from("attacker-controlled extractor detail")),
                },
                r#"{"error":"The request carried an unusable credential."}"#,
            ),
            missing_credentials(
                AuthError::MissingToken,
                r#"{"error":"No JWT could be extracted from the request."}"#,
            ),
            missing_credentials(
                AuthError::NoDecodingKeys,
                r#"{"error":"There were no decoding keys available."}"#,
            ),
            DescriptiveResponseCase {
                error: AuthError::UnexpectedRole,
                status: StatusCode::FORBIDDEN,
                challenge: None,
                body: r#"{"error":"An unexpected role was present."}"#,
            },
            internal_error(
                AuthError::NoOidcDiscovery,
                r#"{"error":"Never discovered an OIDC configuration."}"#,
            ),
            internal_error(
                AuthError::OidcDiscovery {
                    source: provider_request_error(),
                },
                r#"{"error":"Could not discover OIDC configuration."}"#,
            ),
            internal_error(
                AuthError::JwkEndpoint {
                    source: url::Url::parse(SENSITIVE_PROVIDER_ADDRESS)
                        .expect_err("a host without a URL scheme must be rejected"),
                },
                r#"{"error":"Could not parse the JWK endpoint."}"#,
            ),
            internal_error(
                AuthError::JwkSetDiscovery {
                    source: provider_request_error(),
                },
                r#"{"error":"Could not discover the JWK set."}"#,
            ),
        ]
    }

    fn provider_request_error() -> RequestError {
        let source = reqwest::Client::new()
            .get(format!("https://{SENSITIVE_PROVIDER_ADDRESS}:invalid/jwks"))
            .build()
            .expect_err("an invalid provider port must fail request construction");
        RequestError::Send {
            source: Arc::new(source),
        }
    }

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
    async fn descriptive_responses_have_their_documented_status_challenge_and_body() {
        for case in descriptive_response_cases() {
            let name = format!("{:?}", case.error);
            let response = case.error.into_response();

            assert_that!(response.status())
                .with_subject_name(format!("{name}: status"))
                .is_equal_to(case.status);
            assert_that!(
                response
                    .headers()
                    .get(WWW_AUTHENTICATE)
                    .map(|challenge| challenge.to_str().expect("the challenge must be ASCII"))
            )
            .with_subject_name(format!("{name}: challenge"))
            .is_equal_to(case.challenge);
            assert_that!(response_text(response).await)
                .with_subject_name(format!("{name}: body"))
                .is_equal_to(case.body)
                .does_not_contain(SENSITIVE_PROVIDER_ADDRESS);
        }
    }

    #[tokio::test]
    async fn missing_expected_role_response_omits_role_name() {
        let response = AuthError::MissingExpectedRole {
            role: String::from("sensitive-administrator-role"),
        }
        .into_response();

        assert_that!(response.status()).is_equal_to(StatusCode::FORBIDDEN);
        assert_that!(response_text(response).await)
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
        assert_that!(response_text(response).await)
            .is_equal_to(r#"{"error":"invalid_token"}"#)
            .does_not_contain("expected i64");
    }
}
