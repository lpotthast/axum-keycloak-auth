use std::{borrow::Cow, sync::Arc};

use axum::{
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use serde_json::json;
use snafu::Snafu;

use crate::oidc_discovery;

#[derive(Debug, Clone, Snafu)]
#[snafu(visibility(pub(crate)))]
pub enum AuthError {
    /// OIDC discovery never happened.
    #[snafu(display("Never discovered a OIDC configuration."))]
    NoOidcDiscovery,

    /// OIDC discovery failed.
    #[snafu(display("Could not discover OIDC configuration."))]
    OidcDiscovery {
        #[snafu(backtrace)]
        source: oidc_discovery::RequestError,
    },

    /// JWK set discovery never happened.
    #[snafu(display("Never discovered a JWK set."))]
    NoJwkSetDiscovery,

    /// JWK endpoint was not a valid URL.
    #[snafu(display("Could not parse the JWK endpoint."))]
    JwkEndpoint { source: url::ParseError },

    /// JWK set discovery failed.
    #[snafu(display("Could not discover the JWK set."))]
    JwkSetDiscovery {
        source: oidc_discovery::RequestError,
    },

    /// The 'Authorization' header was not present on a request.
    #[snafu(display("The 'Authorization' header was not present on a request."))]
    MissingAuthorizationHeader,

    /// The 'Authorization' header was present on a request but its value could not be parsed.
    /// This can occur if the header value did not solely contain visible ASCII characters.
    #[snafu(display("The 'Authorization' header was present on a request but its value could not be parsed. Reason: {reason}"))]
    InvalidAuthorizationHeader { reason: String },

    /// The 'Authorization' header was present  and could be parsed, but it did not contain the expected "Bearer {token}" format.
    #[snafu(display(
        "The 'Authorization' header did not contain the expected 'Bearer ...token' format."
    ))]
    MissingBearerToken,

    /// No query parameters were found on the request.
    #[snafu(display("No query parameters were found on the request."))]
    MissingQueryParams,

    /// Query parameters were found on the request, but the expected token parameter wasn't.
    #[snafu(display(
        "Query parameters were found on the request, but the expected token parameter wasn't."
    ))]
    MissingTokenQueryParam,

    /// Query parameters were found on the request, and the expected token parameter was found, but it had no value assigned ("?token=").
    #[snafu(display("Query parameters were found on the request, and the expected token parameter was found, but it had no value assigned (\"?token=\")."))]
    EmptyTokenQueryParam,

    /// No JWT could be extracted from the request.
    #[snafu(display("No JWT could be extracted from the request."))]
    MissingToken,

    /// The DecodingKey, required for decoding tokens, could not be created.
    #[snafu(display(
        "The DecodingKey, required for decoding tokens, could not be created. Source: {source}"
    ))]
    CreateDecodingKey { source: jsonwebtoken::errors::Error },

    /// The JWT header could not be decoded.
    #[snafu(display("The JWT header could not be decoded. Source: {source}"))]
    DecodeHeader { source: jsonwebtoken::errors::Error },

    /// No decoding keys were fetched jet.
    #[snafu(display("There were no decoding keys available."))]
    NoDecodingKeys,

    /// The JWT could not be decoded.
    #[snafu(display("The JWT could not be decoded. Source: {source}"))]
    Decode { source: jsonwebtoken::errors::Error },

    /// Parts of the JWT could not be parsed.
    #[snafu(display("Parts of the JWT could not be parsed. Source: {source}"))]
    JsonParse { source: Arc<serde_json::Error> },

    /// The tokens lifetime is expired.
    #[snafu(display("The tokens lifetime is expired."))]
    TokenExpired,

    /// For a not further known reason, the token was deemed invalid
    #[snafu(display(
        "For a not further known reason, the token was deemed invalid: Reason: {reason}"
    ))]
    InvalidToken { reason: String },

    /// Note: The `IntoResponse` implementation will only show the provided role in a debug build!
    #[snafu(display("An expected role (omitted for security reasons) was missing."))]
    MissingExpectedRole { role: String },

    /// An unexpected role was present.
    #[snafu(display("An unexpected role was present."))]
    UnexpectedRole,
}

impl IntoResponse for AuthError {
    fn into_response(self) -> Response {
        let (status, error_message) = match self {
            err @ AuthError::NoOidcDiscovery => (
                StatusCode::INTERNAL_SERVER_ERROR,
                Cow::Owned(err.to_string()),
            ),
            err @ AuthError::OidcDiscovery { source: _ } => (
                StatusCode::INTERNAL_SERVER_ERROR,
                Cow::Owned(err.to_string()),
            ),
            err @ AuthError::NoJwkSetDiscovery => (
                StatusCode::INTERNAL_SERVER_ERROR,
                Cow::Owned(err.to_string()),
            ),
            err @ AuthError::JwkEndpoint { source: _ } => (
                StatusCode::INTERNAL_SERVER_ERROR,
                Cow::Owned(err.to_string()),
            ),
            err @ AuthError::JwkSetDiscovery { source: _ } => (
                StatusCode::INTERNAL_SERVER_ERROR,
                Cow::Owned(err.to_string()),
            ),
            err @ AuthError::MissingAuthorizationHeader => {
                (StatusCode::UNAUTHORIZED, Cow::Owned(err.to_string()))
            }
            err @ AuthError::InvalidAuthorizationHeader { reason: _ } => {
                (StatusCode::UNAUTHORIZED, Cow::Owned(err.to_string()))
            }
            err @ AuthError::MissingBearerToken => {
                (StatusCode::UNAUTHORIZED, Cow::Owned(err.to_string()))
            }
            err @ AuthError::MissingQueryParams => {
                (StatusCode::UNAUTHORIZED, Cow::Owned(err.to_string()))
            }
            err @ AuthError::MissingTokenQueryParam => {
                (StatusCode::UNAUTHORIZED, Cow::Owned(err.to_string()))
            }
            err @ AuthError::EmptyTokenQueryParam => {
                (StatusCode::UNAUTHORIZED, Cow::Owned(err.to_string()))
            }
            err @ AuthError::MissingToken => {
                (StatusCode::UNAUTHORIZED, Cow::Owned(err.to_string()))
            }
            err @ AuthError::CreateDecodingKey { source: _ } => (
                StatusCode::INTERNAL_SERVER_ERROR,
                Cow::Owned(err.to_string()),
            ),
            err @ AuthError::DecodeHeader { source: _ } => {
                (StatusCode::BAD_REQUEST, Cow::Owned(err.to_string()))
            }
            err @ AuthError::NoDecodingKeys => {
                (StatusCode::UNAUTHORIZED, Cow::Owned(err.to_string()))
            }
            err @ AuthError::Decode { source: _ } => {
                (StatusCode::UNAUTHORIZED, Cow::Owned(err.to_string()))
            }
            err @ AuthError::JsonParse { source: _ } => (
                StatusCode::INTERNAL_SERVER_ERROR,
                Cow::Owned(err.to_string()),
            ),
            err @ AuthError::TokenExpired => {
                (StatusCode::UNAUTHORIZED, Cow::Owned(err.to_string()))
            }
            err @ AuthError::InvalidToken { reason: _ } => {
                (StatusCode::UNAUTHORIZED, Cow::Owned(err.to_string()))
            }
            AuthError::MissingExpectedRole { role } => (
                StatusCode::FORBIDDEN,
                match cfg!(debug_assertions) {
                    true => Cow::Owned(format!("Missing expected role: {role}")),
                    false => Cow::Borrowed("Missing expected role"),
                },
            ),
            err @ AuthError::UnexpectedRole => (StatusCode::FORBIDDEN, Cow::Owned(err.to_string())),
        };
        let body = Json(json!({
            "error": error_message,
        }));
        (status, body).into_response()
    }
}
