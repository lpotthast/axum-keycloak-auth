use std::borrow::Cow;

use axum::extract::Request;
use http::header::ToStrError;
use snafu::{ResultExt, Snafu, ensure};

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

    /// The header used the `Bearer` scheme, but the token after it was empty or consisted only of
    /// whitespace.
    #[snafu(display("The 'Authorization' header carried a blank 'Bearer' token."))]
    EmptyBearerToken,
}

/// Extracts a token from an `Authorization: Bearer <token>` header.
///
/// The `Bearer` scheme is matched case-insensitively, as RFC 7235 requires. Whitespace around the
/// token is ignored. A missing header, or one using another scheme such as `Basic`, is an absent
/// source. A `Bearer` header that does not carry a non-blank token is rejected with an
/// [`AuthHeaderExtractError`].
#[derive(Debug, Clone, Default)]
pub struct AuthHeaderTokenExtractor {}

impl TokenExtractor for AuthHeaderTokenExtractor {
    fn extract<'a>(&self, request: &'a Request) -> Result<Option<ExtractedToken<'a>>, BoxError> {
        let Some(header_value) = request.headers().get(http::header::AUTHORIZATION) else {
            return Ok(None);
        };

        // The scheme ends at the first space. Determine it from the raw bytes, so that a header for
        // another scheme is skipped even if it is not visible ASCII.
        let bytes = header_value.as_bytes();
        let scheme_len = bytes
            .iter()
            .position(|byte| *byte == b' ')
            .unwrap_or(bytes.len());
        if !bytes[..scheme_len].eq_ignore_ascii_case(b"Bearer") {
            return Ok(None);
        }

        // Bearer tokens are visible ASCII (RFC 6750). Slicing at `scheme_len` is safe because the
        // scheme matched the ASCII `Bearer`. The scheme may be followed by several spaces, and a
        // JWT never contains whitespace.
        let token = header_value.to_str().context(InvalidHeaderValueSnafu)?[scheme_len..].trim();

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
    fn the_scheme_is_matched_case_insensitively() {
        for authorization in [
            "bearer abc.def.ghi",
            "BEARER abc.def.ghi",
            "bEaReR abc.def.ghi",
        ] {
            assert_that!(extract(&request_with_authorization(authorization)))
                .with_subject_name(format!("{authorization:?}"))
                .ok()
                .some()
                .is_equal_to("abc.def.ghi");
        }
    }

    #[test]
    fn other_schemes_are_an_absent_source() {
        for authorization in [
            "Basic dXNlcjpwYXNz",
            "DPoP abc.def.ghi",
            "Bearerabc.def.ghi",
            "Basic \u{e4}",
        ] {
            assert_that!(extract(&request_with_authorization(
                HeaderValue::from_bytes(authorization.as_bytes())
                    .expect("test header value must build")
            )))
            .with_subject_name(format!("{authorization:?}"))
            .ok()
            .is_none();
        }
    }

    #[test]
    fn a_bearer_scheme_without_a_token_yields_an_error() {
        assert_that!(extract(&request_with_authorization("Bearer")))
            .is_matching(pattern!(Err(AuthHeaderExtractError::EmptyBearerToken)));
    }

    #[test]
    fn a_bearer_header_value_that_is_not_visible_ascii_yields_an_error() {
        // Invalid UTF-8, and valid UTF-8 that is still no bearer token, which is ASCII-only.
        for value in [&b"Bearer \xff"[..], "Bearer t\u{f6}k\u{e9}n".as_bytes()] {
            let request = request_with_authorization(
                HeaderValue::from_bytes(value).expect("test header value must build"),
            );

            assert_that!(extract(&request))
                .with_subject_name(format!("{value:?}"))
                .is_matching(pattern!(Err(
                    AuthHeaderExtractError::InvalidHeaderValue { .. }
                )));
        }
    }
}
