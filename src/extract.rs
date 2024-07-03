use std::{borrow::Cow, sync::Arc};

use axum::extract::Request;
use nonempty::NonEmpty;

use crate::error::AuthError;

/// A raw (unprocessed) token (string) taken from a request.
/// This being `Cow` allows the `TokenExtractor` implementations to borrow from the request if possible.
pub type ExtractedToken<'a> = Cow<'a, str>;

/// Allows for customized strategies on how to retrieve the auth token from an axum request.
/// This crate implements two default strategies:
///   - `AuthHeaderTokenExtractor`: Extracts the token from the `http::header::AUTHORIZATION` header.
///   - `QueryParamTokenExtractor`: Extracts the token from a query parameter (for example named "token").
///
/// Note: The current return type and caller impl does not allow to return multiple tokens from a request.
/// We may implement this feature in the future. This could allow the QueryParamTokenExtractor to extract all tokens found.
pub trait TokenExtractor: Send + Sync + std::fmt::Debug {
    fn extract<'a>(&self, request: &'a Request) -> Result<ExtractedToken<'a>, AuthError>;
}

/// Searches the auth token in the authorization header. (Authorization: `Bearer <token>`)
#[derive(Debug, Clone, Default)]
pub struct AuthHeaderTokenExtractor {}

impl TokenExtractor for AuthHeaderTokenExtractor {
    fn extract<'a>(&self, request: &'a Request) -> Result<ExtractedToken<'a>, AuthError> {
        request
            .headers()
            .get(http::header::AUTHORIZATION)
            .ok_or(AuthError::MissingAuthorizationHeader)?
            .to_str()
            .map_err(|err| AuthError::InvalidAuthorizationHeader {
                reason: err.to_string(),
            })?
            .strip_prefix("Bearer ")
            .ok_or(AuthError::MissingBearerToken)
            .map(Cow::Borrowed)
    }
}

/// Searches the auth token in the query parameters, eg. returns `<token>` when looking at a request with URL `https://<url>/<path>?token=<token>`.
/// The key to be searched for is configurable. Default is: "token".
///
/// SECURITY: This extractor should be used with caution!
/// Only use it if you are informed about the security implication of providing tokens through query parameters.
#[derive(Debug, Clone)]
pub struct QueryParamTokenExtractor {
    pub key: String,
}

impl QueryParamTokenExtractor {
    pub fn extracting_key(key: impl Into<String>) -> Self {
        Self { key: key.into() }
    }
}

impl Default for QueryParamTokenExtractor {
    fn default() -> Self {
        Self::extracting_key("token")
    }
}

impl TokenExtractor for QueryParamTokenExtractor {
    fn extract<'a>(&self, request: &'a Request) -> Result<ExtractedToken<'a>, AuthError> {
        let query = request.uri().query().ok_or(AuthError::MissingQueryParams)?;

        let mut tokens = serde_querystring::DuplicateQS::parse(query.as_bytes())
            .values(self.key.as_bytes())
            .unwrap_or_default()
            .into_iter();

        let first_token = tokens
            .next()
            .ok_or(AuthError::MissingTokenQueryParam)?
            .ok_or(AuthError::EmptyTokenQueryParam)?;

        let first_token = std::str::from_utf8(first_token.as_ref()).expect("Valid UTF-8");

        Ok(ExtractedToken::Owned(first_token.to_owned()))
    }
}

pub(crate) fn extract_jwt<'a>(
    request: &'a Request<axum::body::Body>,
    extractors: &NonEmpty<Arc<dyn TokenExtractor>>,
) -> Option<ExtractedToken<'a>> {
    for extractor in extractors {
        match extractor.extract(request) {
            Ok(jwt) => return Some(jwt),
            Err(err) => {
                tracing::debug!(?extractor, ?err, "Extractor failed");
            }
        }
    }
    None
}
