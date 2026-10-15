use std::borrow::Cow;

use axum::extract::Request;
use snafu::Snafu;

use crate::error::AuthError;

use super::{ExtractedToken, TokenExtractor};

/// Errors specific to a present `Authorization` header.
#[derive(Debug, Clone, Snafu)]
pub(crate) enum AuthHeaderExtractError {
    /// The `Authorization` header was present, but did not use the expected "Bearer ..." format.
    #[snafu(display("The 'Authorization' header did not contain a \"Bearer ...\" token."))]
    MissingBearerToken,

    /// The `Authorization` header was present and used the "Bearer ..." format, but carried a blank
    /// token after the scheme, meaning it was empty or consisted only of whitespace.
    #[snafu(display("The 'Authorization' header carried a blank \"Bearer \" token."))]
    EmptyBearerToken,

    /// The `Authorization` header was present and used the "Bearer ..." format, but its value
    /// could not be parsed.
    #[snafu(display("The 'Authorization' header could not be parsed. Reason: {reason}"))]
    InvalidHeaderValue { reason: String },
}

/// Extracts a token from an `Authorization: Bearer <token>` header.
///
/// The `Bearer ` prefix is case-sensitive. Empty and whitespace-only token values are rejected.
#[derive(Debug, Clone, Default)]
pub struct AuthHeaderTokenExtractor {}

impl AuthHeaderTokenExtractor {
    /// Extracts a bearer token, reporting an absent header as `Ok(None)`.
    pub(crate) fn try_extract(
        request: &Request,
    ) -> Result<Option<ExtractedToken<'_>>, AuthHeaderExtractError> {
        let Some(header) = request.headers().get(http::header::AUTHORIZATION) else {
            return Ok(None);
        };

        let token = header
            .to_str()
            .map_err(|err| AuthHeaderExtractError::InvalidHeaderValue {
                reason: err.to_string(),
            })?
            .strip_prefix("Bearer ")
            .ok_or(AuthHeaderExtractError::MissingBearerToken)?;

        // A blank value can never be a JWT, and reporting it as an extracted token would stop
        // extraction and shadow a valid token in a lower-priority source.
        if token.trim().is_empty() {
            return Err(AuthHeaderExtractError::EmptyBearerToken);
        }

        Ok(Some(Cow::Borrowed(token)))
    }
}

impl TokenExtractor for AuthHeaderTokenExtractor {
    fn extract<'a>(&self, request: &'a Request) -> Result<ExtractedToken<'a>, AuthError> {
        match Self::try_extract(request) {
            Ok(Some(token)) => Ok(token),
            Ok(None) => Err(AuthError::MissingAuthorizationHeader),
            Err(AuthHeaderExtractError::InvalidHeaderValue { reason }) => {
                Err(AuthError::InvalidAuthorizationHeader { reason })
            }
            Err(
                AuthHeaderExtractError::MissingBearerToken
                | AuthHeaderExtractError::EmptyBearerToken,
            ) => Err(AuthError::MissingBearerToken),
        }
    }
}

#[cfg(test)]
mod tests {
    use assertr::prelude::*;
    use axum::{body::Body, extract::Request};
    use http::HeaderValue;

    use super::{AuthHeaderExtractError, AuthHeaderTokenExtractor};

    fn request_with_authorization(value: &str) -> Request {
        Request::builder()
            .header(http::header::AUTHORIZATION, value)
            .body(Body::empty())
            .expect("test request must build")
    }

    #[test]
    fn no_authorization_header_yields_ok_none() {
        assert_that!(AuthHeaderTokenExtractor::try_extract(&Request::new(
            Body::empty()
        )))
        .ok()
        .is_none();
    }

    #[test]
    fn empty_bearer_token_yields_an_error() {
        assert_that!(AuthHeaderTokenExtractor::try_extract(
            &request_with_authorization("Bearer ")
        ))
        .is_matching(pattern!(Err(AuthHeaderExtractError::EmptyBearerToken)));
    }

    #[test]
    fn whitespace_only_bearer_token_yields_an_error() {
        for blank in ["Bearer  ", "Bearer \t", "Bearer   \t "] {
            assert_that!(AuthHeaderTokenExtractor::try_extract(
                &request_with_authorization(blank)
            ))
            .is_matching(pattern!(Err(AuthHeaderExtractError::EmptyBearerToken)));
        }
    }

    #[test]
    fn valid_bearer_token_is_returned() {
        assert_that!(AuthHeaderTokenExtractor::try_extract(
            &request_with_authorization("Bearer abc.def.ghi")
        ))
        .ok()
        .some()
        .is_equal_to("abc.def.ghi");
    }

    #[test]
    fn unexpected_authorization_header_shapes_yield_typed_errors() {
        assert_that!(AuthHeaderTokenExtractor::try_extract(
            &request_with_authorization("Basic abc.def.ghi")
        ))
        .is_matching(pattern!(Err(AuthHeaderExtractError::MissingBearerToken)));
        assert_that!(AuthHeaderTokenExtractor::try_extract(
            &request_with_authorization("bearer abc.def.ghi")
        ))
        .is_matching(pattern!(Err(AuthHeaderExtractError::MissingBearerToken)));

        let request = Request::builder()
            .header(
                http::header::AUTHORIZATION,
                HeaderValue::from_bytes(&[0xff]).expect("test header value must build"),
            )
            .body(Body::empty())
            .expect("test request must build");
        assert_that!(AuthHeaderTokenExtractor::try_extract(&request)).is_matching(pattern!(Err(
            AuthHeaderExtractError::InvalidHeaderValue { .. }
        )));
    }
}
