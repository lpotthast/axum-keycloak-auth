use std::borrow::Cow;

use axum::extract::Request;
use http::header::ToStrError;
use snafu::{OptionExt, ResultExt, Snafu, ensure};

use super::{BoxError, ExtractedToken, TokenExtractor};

/// Why [`AuthHeaderTokenExtractor`] could not extract a token from a present `Authorization`
/// header.
#[derive(Debug, Snafu)]
#[non_exhaustive]
pub enum AuthHeaderExtractError {
    /// The header value contained characters other than visible ASCII and could not be read as a
    /// string.
    #[snafu(display("The 'Authorization' header could not be read as a string."))]
    InvalidHeaderValue {
        /// The conversion error.
        source: ToStrError,
    },

    /// The header did not use the `Bearer` scheme.
    #[snafu(display("The 'Authorization' header did not use the 'Bearer' scheme."))]
    MissingBearerScheme,

    /// The header used the `Bearer` scheme, but the token after it was empty or consisted only of
    /// whitespace.
    #[snafu(display("The 'Authorization' header carried a blank 'Bearer' token."))]
    EmptyBearerToken,
}

/// Extracts a token from an `Authorization: Bearer <token>` header.
///
/// The `Bearer ` prefix is case-sensitive. Whitespace around the token is ignored. A missing header
/// is an absent source. Any other header that does not carry a non-blank bearer token is rejected
/// with an [`AuthHeaderExtractError`].
#[derive(Debug, Clone, Default)]
pub struct AuthHeaderTokenExtractor {}

impl TokenExtractor for AuthHeaderTokenExtractor {
    fn extract<'a>(&self, request: &'a Request) -> Result<Option<ExtractedToken<'a>>, BoxError> {
        let Some(header) = request.headers().get(http::header::AUTHORIZATION) else {
            return Ok(None);
        };

        let token = header
            .to_str()
            .context(InvalidHeaderValueSnafu)?
            .strip_prefix("Bearer ")
            .context(MissingBearerSchemeSnafu)?
            // The scheme may be followed by several spaces, and a JWT never contains whitespace.
            .trim();

        // A blank value can never be a JWT, and reporting it as an extracted token would stop
        // extraction and shadow a valid token in a lower-priority source.
        ensure!(!token.is_empty(), EmptyBearerTokenSnafu);

        Ok(Some(Cow::Borrowed(token)))
    }
}

#[cfg(test)]
mod tests {
    use assertr::prelude::*;
    use axum::{body::Body, extract::Request};
    use http::HeaderValue;

    use super::{AuthHeaderExtractError, AuthHeaderTokenExtractor, TokenExtractor};

    fn request_with_authorization(
        value: impl TryInto<HeaderValue, Error: std::fmt::Debug>,
    ) -> Request {
        Request::builder()
            .header(
                http::header::AUTHORIZATION,
                value.try_into().expect("test header value must build"),
            )
            .body(Body::empty())
            .expect("test request must build")
    }

    /// Extracts with the default extractor, downcasting an error to [`AuthHeaderExtractError`].
    fn extract(request: &Request) -> Result<Option<String>, AuthHeaderExtractError> {
        AuthHeaderTokenExtractor::default()
            .extract(request)
            .map(|token| token.map(String::from))
            .map_err(|error| {
                *error
                    .downcast::<AuthHeaderExtractError>()
                    .expect("the extractor must report an `AuthHeaderExtractError`")
            })
    }

    #[test]
    fn no_authorization_header_yields_ok_none() {
        assert_that!(extract(&Request::new(Body::empty())))
            .ok()
            .is_none();
    }

    #[test]
    fn blank_bearer_tokens_yield_an_error() {
        for blank in ["Bearer ", "Bearer  ", "Bearer \t", "Bearer   \t "] {
            assert_that!(extract(&request_with_authorization(blank)))
                .with_subject_name(format!("{blank:?}"))
                .is_matching(pattern!(Err(AuthHeaderExtractError::EmptyBearerToken)));
        }
    }

    #[test]
    fn valid_bearer_token_is_returned() {
        assert_that!(extract(&request_with_authorization("Bearer abc.def.ghi")))
            .ok()
            .some()
            .is_equal_to("abc.def.ghi");
    }

    #[test]
    fn whitespace_around_the_bearer_token_is_ignored() {
        for authorization in [
            "Bearer  abc.def.ghi",
            "Bearer abc.def.ghi ",
            "Bearer \t abc.def.ghi \t",
        ] {
            assert_that!(extract(&request_with_authorization(authorization)))
                .with_subject_name(format!("{authorization:?}"))
                .ok()
                .some()
                .is_equal_to("abc.def.ghi");
        }
    }

    #[test]
    fn other_schemes_yield_an_error() {
        // The scheme comparison is case-sensitive.
        for authorization in ["Basic abc.def.ghi", "bearer abc.def.ghi"] {
            assert_that!(extract(&request_with_authorization(authorization)))
                .with_subject_name(format!("{authorization:?}"))
                .is_matching(pattern!(Err(AuthHeaderExtractError::MissingBearerScheme)));
        }
    }

    #[test]
    fn a_header_value_that_is_not_visible_ascii_yields_an_error() {
        let request = request_with_authorization(
            HeaderValue::from_bytes(&[0xff]).expect("test header value must build"),
        );

        assert_that!(extract(&request)).is_matching(pattern!(Err(
            AuthHeaderExtractError::InvalidHeaderValue { .. }
        )));
    }
}
