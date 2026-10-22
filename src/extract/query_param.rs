use axum::extract::Request;
use snafu::Snafu;

use crate::error::AuthError;

use super::{ExtractedToken, TokenExtractor};

/// Errors specific to a present token query parameter.
#[derive(Debug, Clone, Snafu)]
pub(crate) enum QueryParamExtractError {
    /// The configured token query parameter was present, but had a blank value, meaning it was
    /// value-less (`?token`), empty (`?token=`), or consisted only of whitespace.
    #[snafu(display("The token query parameter had a blank value."))]
    EmptyToken,

    /// The configured token query parameter was present, but was not valid UTF-8.
    #[snafu(display("The token query parameter was not valid UTF-8."))]
    InvalidUtf8,
}

/// Extracts a token from a query parameter.
///
/// The parameter name defaults to `token`. If the parameter occurs more than once, only the first
/// value is considered. Whitespace around the token is ignored, and empty and whitespace-only
/// token values are rejected.
///
/// # Security
///
/// URL tokens can be retained in browser history, referrer headers, proxy and server logs, and
/// monitoring tools. Prefer header extraction whenever possible.
#[derive(Debug, Clone)]
pub struct QueryParamTokenExtractor {
    /// Query parameter name to extract.
    pub key: String,
}

impl QueryParamTokenExtractor {
    /// Creates an extractor for `key`.
    pub fn extracting_key(key: impl Into<String>) -> Self {
        Self { key: key.into() }
    }

    /// Extracts a query-parameter token, reporting a missing query string or parameter as
    /// `Ok(None)`.
    pub(crate) fn try_extract<'a>(
        &self,
        request: &'a Request,
    ) -> Result<Option<ExtractedToken<'a>>, QueryParamExtractError> {
        let Some(query) = request.uri().query() else {
            return Ok(None);
        };

        let mut tokens = serde_querystring::DuplicateQS::parse(query.as_bytes())
            .values(self.key.as_bytes())
            .unwrap_or_default()
            .into_iter();

        let Some(first_token) = tokens.next() else {
            return Ok(None);
        };
        let first_token = first_token.ok_or(QueryParamExtractError::EmptyToken)?;

        // One allocation at most: a percent-decoded value is taken over as-is, a plain one is
        // copied once. Returning a borrowed token is not possible here because
        // `DuplicateQS::values` ties the lifetime of its key argument to the query string.
        let mut first_token = String::from_utf8(first_token.into_owned())
            .map_err(|_err| QueryParamExtractError::InvalidUtf8)?;

        // A JWT never contains whitespace. Trim in place, keeping the single allocation.
        first_token.truncate(first_token.trim_end().len());
        first_token.drain(..first_token.len() - first_token.trim_start().len());

        // A blank value can never be a JWT, and reporting it as an extracted token would stop
        // extraction and shadow a valid token in a lower-priority source.
        if first_token.is_empty() {
            return Err(QueryParamExtractError::EmptyToken);
        }

        Ok(Some(ExtractedToken::Owned(first_token)))
    }
}

impl Default for QueryParamTokenExtractor {
    fn default() -> Self {
        Self::extracting_key("token")
    }
}

impl TokenExtractor for QueryParamTokenExtractor {
    fn extract<'a>(&self, request: &'a Request) -> Result<ExtractedToken<'a>, AuthError> {
        match self.try_extract(request) {
            Ok(Some(token)) => Ok(token),
            // `try_extract` collapses "no query string" and "no such parameter" into `None`. The
            // legacy contract distinguishes them, so the absent case is resolved here.
            Ok(None) if request.uri().query().is_some() => Err(AuthError::MissingTokenQueryParam),
            Ok(None) => Err(AuthError::MissingQueryParams),
            Err(QueryParamExtractError::EmptyToken) => Err(AuthError::EmptyTokenQueryParam),
            Err(error @ QueryParamExtractError::InvalidUtf8) => Err(AuthError::InvalidToken {
                reason: error.to_string(),
            }),
        }
    }
}

#[cfg(test)]
mod tests {
    use assertr::prelude::*;
    use axum::{body::Body, extract::Request};

    use super::{AuthError, QueryParamExtractError, QueryParamTokenExtractor, TokenExtractor};

    fn request_with_uri(uri: &str) -> Request {
        Request::builder()
            .uri(uri)
            .body(Body::empty())
            .expect("test request must build")
    }

    #[test]
    fn no_token_yields_ok_none() {
        let extractor = QueryParamTokenExtractor::default();
        assert_that!(extractor.try_extract(&request_with_uri("/")))
            .ok()
            .is_none();
        assert_that!(extractor.try_extract(&request_with_uri("/?other=1")))
            .ok()
            .is_none();
    }

    #[test]
    fn empty_token_value_yields_an_error() {
        let extractor = QueryParamTokenExtractor::default();
        assert_that!(extractor.try_extract(&request_with_uri("/?token")))
            .is_matching(pattern!(Err(QueryParamExtractError::EmptyToken)));
        assert_that!(extractor.try_extract(&request_with_uri("/?token=")))
            .is_matching(pattern!(Err(QueryParamExtractError::EmptyToken)));
        assert_that!(extractor.try_extract(&request_with_uri("/?token=&token=second")))
            .is_matching(pattern!(Err(QueryParamExtractError::EmptyToken)));
    }

    #[test]
    fn whitespace_only_token_value_yields_an_error() {
        let extractor = QueryParamTokenExtractor::default();
        for blank in ["/?token=%20", "/?token=%09", "/?token=%20%09%20"] {
            assert_that!(extractor.try_extract(&request_with_uri(blank)))
                .is_matching(pattern!(Err(QueryParamExtractError::EmptyToken)));
        }
    }

    #[test]
    fn whitespace_around_the_token_is_ignored() {
        let extractor = QueryParamTokenExtractor::default();
        for uri in [
            "/?token=%20abc.def.ghi",
            "/?token=abc.def.ghi%20",
            "/?token=%09%20abc.def.ghi%20%09",
        ] {
            assert_that!(extractor.try_extract(&request_with_uri(uri)))
                .with_subject_name(uri)
                .ok()
                .some()
                .is_equal_to("abc.def.ghi");
        }
    }

    #[test]
    fn single_valid_token_is_returned() {
        let extractor = QueryParamTokenExtractor::default();
        assert_that!(extractor.try_extract(&request_with_uri("/?token=value")))
            .ok()
            .some()
            .is_equal_to("value");
    }

    #[test]
    fn multiple_tokens_first_one_is_returned() {
        let extractor = QueryParamTokenExtractor::default();
        assert_that!(extractor.try_extract(&request_with_uri("/?token=first&token=second")))
            .ok()
            .some()
            .is_equal_to("first");
    }

    #[test]
    fn extraction_is_panic_free_across_unexpected_parameter_shapes() {
        let extractor = QueryParamTokenExtractor::default();
        assert_that!(extractor.try_extract(&request_with_uri("/?token=%FF"))) // Invalid percent-decoded UTF-8.
            .is_matching(pattern!(Err(QueryParamExtractError::InvalidUtf8)));
        assert_that!(extractor.try_extract(&request_with_uri("/?token=abc.def.ghi")))
            .ok()
            .some()
            .is_equal_to("abc.def.ghi");
    }

    #[test]
    fn extracts_custom_parameter() {
        let extractor = QueryParamTokenExtractor::extracting_key("foo");
        assert_that!(extractor.try_extract(&request_with_uri("/?foo=value")))
            .ok()
            .some()
            .is_equal_to("value");
    }

    // ----- The public `TokenExtractor` contract ------------------------------------------------

    #[test]
    fn extract_returns_the_token() {
        assert_that!(
            QueryParamTokenExtractor::default().extract(&request_with_uri("/?token=abc.def.ghi"))
        )
        .ok()
        .is_equal_to("abc.def.ghi");
    }

    #[test]
    fn extract_distinguishes_an_absent_query_string_from_an_absent_parameter() {
        let extractor = QueryParamTokenExtractor::default();
        assert_that!(extractor.extract(&request_with_uri("/")))
            .is_matching(pattern!(Err(AuthError::MissingQueryParams)));
        assert_that!(extractor.extract(&request_with_uri("/?other=value")))
            .is_matching(pattern!(Err(AuthError::MissingTokenQueryParam)));
    }

    #[test]
    fn extract_reports_a_blank_token() {
        for uri in ["/?token", "/?token=", "/?token=%20"] {
            assert_that!(QueryParamTokenExtractor::default().extract(&request_with_uri(uri)))
                .with_subject_name(uri)
                .is_matching(pattern!(Err(AuthError::EmptyTokenQueryParam)));
        }
    }

    #[test]
    fn extract_reports_invalid_utf8_as_an_invalid_token() {
        let expected_reason = QueryParamExtractError::InvalidUtf8.to_string();

        assert_that!(QueryParamTokenExtractor::default().extract(&request_with_uri("/?token=%FF")))
            .is_matching(pattern!(
                Err(AuthError::InvalidToken { reason }) if reason == &expected_reason
            ));
    }
}
