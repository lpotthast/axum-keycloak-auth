use axum::extract::Request;
use snafu::{OptionExt, Snafu, ensure};

use super::{BoxError, ExtractedToken, TokenExtractor};

/// Why [`QueryParamTokenExtractor`] could not extract a token from a present query parameter.
#[derive(Debug, Snafu)]
#[non_exhaustive]
pub enum QueryParamExtractError {
    /// The parameter had a blank value, meaning it was value-less (`?token`), empty (`?token=`),
    /// or consisted only of whitespace.
    #[snafu(display("The token query parameter had a blank value."))]
    EmptyToken,

    /// The percent-decoded parameter value was not valid UTF-8.
    #[snafu(display("The token query parameter was not valid UTF-8."))]
    InvalidUtf8,
}

/// Extracts a token from a query parameter.
///
/// The parameter name defaults to `token`. If the parameter occurs more than once, only the first
/// value is considered. Whitespace around the token is ignored. A missing query string or
/// parameter is an absent source. Empty and whitespace-only values are rejected with a
/// [`QueryParamExtractError`].
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
}

impl Default for QueryParamTokenExtractor {
    fn default() -> Self {
        Self::extracting_key("token")
    }
}

impl TokenExtractor for QueryParamTokenExtractor {
    fn extract<'a>(&self, request: &'a Request) -> Result<Option<ExtractedToken<'a>>, BoxError> {
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
        let first_token = first_token.context(EmptyTokenSnafu)?;

        // One allocation at most: a percent-decoded value is taken over as-is, a plain one is
        // copied once. Returning a borrowed token is not possible here because
        // `DuplicateQS::values` ties the lifetime of its key argument to the query string.
        // The decoding error is dropped because it would carry the token's bytes.
        let mut first_token = String::from_utf8(first_token.into_owned())
            .ok()
            .context(InvalidUtf8Snafu)?;

        // A JWT never contains whitespace. Trim in place, keeping the single allocation.
        first_token.truncate(first_token.trim_end().len());
        first_token.drain(..first_token.len() - first_token.trim_start().len());

        // A blank value can never be a JWT, and reporting it as an extracted token would stop
        // extraction and shadow a valid token in a lower-priority source.
        ensure!(!first_token.is_empty(), EmptyTokenSnafu);

        Ok(Some(ExtractedToken::Owned(first_token)))
    }
}

#[cfg(test)]
mod tests {
    use assertr::prelude::*;
    use axum::{body::Body, extract::Request};

    use super::{QueryParamExtractError, QueryParamTokenExtractor, TokenExtractor};

    fn request_with_uri(uri: &str) -> Request {
        Request::builder()
            .uri(uri)
            .body(Body::empty())
            .expect("test request must build")
    }

    /// Extracts with `extractor`, downcasting an error to [`QueryParamExtractError`].
    fn extract(
        extractor: &QueryParamTokenExtractor,
        uri: &str,
    ) -> Result<Option<String>, QueryParamExtractError> {
        extractor
            .extract(&request_with_uri(uri))
            .map(|token| token.map(String::from))
            .map_err(|error| {
                *error
                    .downcast::<QueryParamExtractError>()
                    .expect("the extractor must report a `QueryParamExtractError`")
            })
    }

    #[test]
    fn no_token_yields_ok_none() {
        let extractor = QueryParamTokenExtractor::default();
        assert_that!(extract(&extractor, "/")).ok().is_none();
        assert_that!(extract(&extractor, "/?other=1"))
            .ok()
            .is_none();
    }

    #[test]
    fn empty_token_value_yields_an_error() {
        let extractor = QueryParamTokenExtractor::default();
        assert_that!(extract(&extractor, "/?token"))
            .is_matching(pattern!(Err(QueryParamExtractError::EmptyToken)));
        assert_that!(extract(&extractor, "/?token="))
            .is_matching(pattern!(Err(QueryParamExtractError::EmptyToken)));
        assert_that!(extract(&extractor, "/?token=&token=second"))
            .is_matching(pattern!(Err(QueryParamExtractError::EmptyToken)));
    }

    #[test]
    fn whitespace_only_token_value_yields_an_error() {
        let extractor = QueryParamTokenExtractor::default();
        for blank in ["/?token=%20", "/?token=%09", "/?token=%20%09%20"] {
            assert_that!(extract(&extractor, blank))
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
            assert_that!(extract(&extractor, uri))
                .with_subject_name(uri)
                .ok()
                .some()
                .is_equal_to("abc.def.ghi");
        }
    }

    #[test]
    fn single_valid_token_is_returned() {
        let extractor = QueryParamTokenExtractor::default();
        assert_that!(extract(&extractor, "/?token=value"))
            .ok()
            .some()
            .is_equal_to("value");
    }

    #[test]
    fn multiple_tokens_first_one_is_returned() {
        let extractor = QueryParamTokenExtractor::default();
        assert_that!(extract(&extractor, "/?token=first&token=second"))
            .ok()
            .some()
            .is_equal_to("first");
    }

    #[test]
    fn extraction_is_panic_free_across_unexpected_parameter_shapes() {
        let extractor = QueryParamTokenExtractor::default();
        assert_that!(extract(&extractor, "/?token=%FF")) // Invalid percent-decoded UTF-8.
            .is_matching(pattern!(Err(QueryParamExtractError::InvalidUtf8)));
        assert_that!(extract(&extractor, "/?token=abc.def.ghi"))
            .ok()
            .some()
            .is_equal_to("abc.def.ghi");
    }

    #[test]
    fn extracts_custom_parameter() {
        let extractor = QueryParamTokenExtractor::extracting_key("foo");
        assert_that!(extract(&extractor, "/?foo=value"))
            .ok()
            .some()
            .is_equal_to("value");
    }
}
