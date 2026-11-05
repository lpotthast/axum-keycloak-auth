//! Extract compact JWTs from incoming requests.
//!
//! [`TokenExtractor`] defines *where* a token is looked for. This crate ships two implementations:
//! [`AuthHeaderTokenExtractor`] reads the `Authorization: Bearer <token>` header, and
//! [`QueryParamTokenExtractor`] reads a configurable query parameter.
//!
//! A layer may use several extractors, and each one is asked for its credential source. RFC 6750
//! forbids clients to send a token by more than one method in a request. The outcome therefore
//! depends on how many sources are present:
//!
//! - None: authentication fails with [`AuthError::MissingToken`].
//! - One, carrying a token: that token is validated.
//! - One, but unusable: authentication fails with [`AuthError::TokenExtraction`].
//! - More than one, usable or not: authentication fails with
//!   [`AuthError::MultipleCredentialSources`]. A malformed `Authorization` header next to a valid
//!   query token is therefore rejected rather than authenticated with the query token.
//!
//! The built-in extractors treat a blank token value, meaning one that is empty or consists only of
//! whitespace, as an unusable source rather than as an absent one. `Authorization: Bearer ` and
//! `?token=` are therefore errors. Custom extractors should likewise return an error instead of a
//! blank token.

mod auth_header;
mod query_param;

use std::{borrow::Cow, sync::Arc};

use axum::extract::Request;
use nonempty::NonEmpty;

use crate::{error::AuthError, logging::event_at_level};

pub use auth_header::{AuthHeaderExtractError, AuthHeaderTokenExtractor};
pub use query_param::{QueryParamExtractError, QueryParamTokenExtractor};

/// An unprocessed compact JWT extracted from a request.
///
/// The value may borrow from the request or own decoded data.
pub type ExtractedToken<'a> = Cow<'a, str>;

/// A type-erased error returned by a [`TokenExtractor`].
pub type BoxError = Box<dyn std::error::Error + Send + Sync>;

/// Extracts a compact JWT from one credential source in an Axum request.
///
/// The crate provides [`AuthHeaderTokenExtractor`] and [`QueryParamTokenExtractor`].
pub trait TokenExtractor: Send + Sync + std::fmt::Debug {
    /// Extracts a token from the request.
    ///
    /// Returns `Ok(Some(token))` if the credential source carries a token, and `Ok(None)` only if
    /// the source is absent. Any other result counts as a present source, see the
    /// [module documentation](self).
    ///
    /// # Errors
    ///
    /// Returns an error if the credential source is present but unusable, for example if malformed
    /// or blank. Any specific error type must be converted into [`BoxError`]. Using `?` works.
    /// Callers can downcast it from the source of [`AuthError::TokenExtraction`]. The built-in
    /// extractors report an [`AuthHeaderExtractError`] or a [`QueryParamExtractError`].
    ///
    /// The error never reaches the HTTP response. It may contain request data, which is only
    /// logged if explicitly enabled through
    /// [`KeycloakAuthLayer::dangerously_log_token_extraction_errors`](crate::layer::KeycloakAuthLayer::dangerously_log_token_extraction_errors)
    /// or
    /// [`KeycloakAuthLayer::dangerously_log_authentication_errors`](crate::layer::KeycloakAuthLayer::dangerously_log_authentication_errors).
    fn extract<'a>(&self, request: &'a Request) -> Result<Option<ExtractedToken<'a>>, BoxError>;
}

fn log_extraction_error(level: tracing::Level, extractor: &dyn TokenExtractor, error: &BoxError) {
    event_at_level!(level, ?extractor, %error, "Token extractor failed.");
}

/// Extract a JWT from `request` using `extractors`.
///
/// Applies the rules of the [module documentation](self), asking the extractors in their configured
/// order and stopping at the second present credential source. `Ok(None)` means that no source was
/// present.
///
/// When `token_extraction_error_log_level` is set, every extractor error is logged at that level,
/// including the extractor's [`Debug`](std::fmt::Debug) output and the detailed error. `None`
/// disables these events.
pub(crate) fn extract_jwt<'a>(
    request: &'a Request<axum::body::Body>,
    extractors: &NonEmpty<Arc<dyn TokenExtractor>>,
    token_extraction_error_log_level: Option<tracing::Level>,
) -> Result<Option<ExtractedToken<'a>>, AuthError> {
    let mut present: Option<Result<ExtractedToken<'a>, BoxError>> = None;
    for extractor in extractors {
        let outcome = match extractor.extract(request) {
            Ok(None) => continue,
            Ok(Some(jwt)) => Ok(jwt),
            Err(error) => {
                if let Some(level) = token_extraction_error_log_level {
                    log_extraction_error(level, extractor.as_ref(), &error);
                }
                Err(error)
            }
        };
        if present.is_some() {
            return Err(AuthError::MultipleCredentialSources);
        }
        present = Some(outcome);
    }
    present
        .transpose()
        .map_err(|error| AuthError::TokenExtraction {
            source: Arc::from(error),
        })
}

#[cfg(test)]
mod tests {
    use std::{
        fmt,
        sync::{
            Arc,
            atomic::{AtomicUsize, Ordering},
        },
    };

    use assertr::prelude::*;
    use axum::{body::Body, extract::Request};
    use nonempty::NonEmpty;

    use super::{
        AuthError, AuthHeaderExtractError, AuthHeaderTokenExtractor, BoxError, ExtractedToken,
        QueryParamTokenExtractor, TokenExtractor, extract_jwt,
    };
    use crate::test_support::CapturedLogs;

    const DEBUG_SECRET: &str = "debug-secret-bearer-token";
    const ERROR_SECRET: &str = "error-secret-bearer-token";

    fn request(uri: &str, authorization: Option<&str>) -> Request {
        let mut builder = Request::builder().uri(uri);
        if let Some(authorization) = authorization {
            builder = builder.header(http::header::AUTHORIZATION, authorization);
        }
        builder
            .body(Body::empty())
            .expect("test request must build")
    }

    fn header_then_query() -> NonEmpty<Arc<dyn TokenExtractor>> {
        NonEmpty::<Arc<dyn TokenExtractor>> {
            head: Arc::new(AuthHeaderTokenExtractor::default()),
            tail: vec![Arc::new(QueryParamTokenExtractor::default())],
        }
    }

    /// A custom extractor whose credential source is always absent.
    #[derive(Debug)]
    struct AbsentTokenExtractor;

    impl TokenExtractor for AbsentTokenExtractor {
        fn extract<'a>(
            &self,
            _request: &'a Request,
        ) -> Result<Option<ExtractedToken<'a>>, BoxError> {
            Ok(None)
        }
    }

    /// An extractor that always reports `token`, or an absent source if `None`, counting how often
    /// it was asked.
    #[derive(Debug)]
    struct CountingTokenExtractor {
        token: Option<&'static str>,
        calls: Arc<AtomicUsize>,
    }

    impl CountingTokenExtractor {
        fn new(token: Option<&'static str>) -> (Arc<Self>, Arc<AtomicUsize>) {
            let calls = Arc::new(AtomicUsize::new(0));
            let extractor = Arc::new(Self {
                token,
                calls: Arc::clone(&calls),
            });
            (extractor, calls)
        }
    }

    impl TokenExtractor for CountingTokenExtractor {
        fn extract<'a>(
            &self,
            _request: &'a Request,
        ) -> Result<Option<ExtractedToken<'a>>, BoxError> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            Ok(self.token.map(ExtractedToken::Borrowed))
        }
    }

    struct SecretLeakingTokenExtractor;

    impl fmt::Debug for SecretLeakingTokenExtractor {
        fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            formatter
                .debug_tuple("SecretLeakingTokenExtractor")
                .field(&DEBUG_SECRET)
                .finish()
        }
    }

    impl TokenExtractor for SecretLeakingTokenExtractor {
        fn extract<'a>(
            &self,
            _request: &'a Request,
        ) -> Result<Option<ExtractedToken<'a>>, BoxError> {
            Err(ERROR_SECRET.into())
        }
    }

    #[test]
    fn a_single_token_is_returned_after_asking_every_extractor() {
        let (first, first_calls) = CountingTokenExtractor::new(Some("first"));
        let (later, later_calls) = CountingTokenExtractor::new(None);
        let extractors = NonEmpty::<Arc<dyn TokenExtractor>> {
            head: first,
            tail: vec![later],
        };

        assert_that!(extract_jwt(&request("/", None), &extractors, None))
            .ok()
            .some()
            .is_equal_to("first");
        assert_that!(first_calls.load(Ordering::SeqCst))
            .with_subject_name("first extractor calls")
            .is_equal_to(1);
        assert_that!(later_calls.load(Ordering::SeqCst))
            .with_subject_name("later extractor calls")
            .is_equal_to(1);
    }

    #[test]
    fn a_token_behind_absent_credential_sources_is_found() {
        let request = request("/?token=abc.def.ghi", None);
        let extractors = NonEmpty::<Arc<dyn TokenExtractor>> {
            head: Arc::new(AbsentTokenExtractor),
            tail: vec![
                Arc::new(AuthHeaderTokenExtractor::default()),
                Arc::new(QueryParamTokenExtractor::default()),
            ],
        };

        assert_that!(extract_jwt(&request, &extractors, None))
            .ok()
            .some()
            .is_equal_to("abc.def.ghi");
    }

    #[test]
    fn another_authorization_scheme_is_no_credential_source() {
        let request = request("/?token=abc.def.ghi", Some("Basic dXNlcjpwYXNz"));

        assert_that!(extract_jwt(&request, &header_then_query(), None))
            .ok()
            .some()
            .is_equal_to("abc.def.ghi");
    }

    #[test]
    fn a_single_unusable_credential_source_is_rejected_with_its_error() {
        let request = request("/", Some("Bearer "));

        let error = extract_jwt(&request, &header_then_query(), None)
            .expect_err("the blank header must reject extraction");

        let AuthError::TokenExtraction { source } = error else {
            panic!("expected a token extraction error, got {error:?}");
        };
        assert!(
            matches!(
                source.downcast_ref::<AuthHeaderExtractError>(),
                Some(AuthHeaderExtractError::EmptyBearerToken)
            ),
            "expected the header extractor's error, got {source:?}"
        );
    }

    #[test]
    fn more_than_one_present_credential_source_is_rejected_whether_usable_or_not() {
        for (uri, authorization) in [
            ("/?token=abc.def.ghi", "Bearer abc.def.ghi"),
            ("/?token=abc.def.ghi", "Bearer jkl.mno.pqr"),
            ("/?token=abc.def.ghi", "Bearer "),
            ("/?token=", "Bearer abc.def.ghi"),
            ("/?token=", "Bearer "),
        ] {
            assert_that!(extract_jwt(
                &request(uri, Some(authorization)),
                &header_then_query(),
                None,
            ))
            .with_subject_name(format!("{uri} with {authorization:?}"))
            .is_matching(pattern!(Err(AuthError::MultipleCredentialSources)));
        }
    }

    #[test]
    fn extraction_stops_at_the_second_present_credential_source() {
        let (first, _) = CountingTokenExtractor::new(Some("first"));
        let (second, _) = CountingTokenExtractor::new(Some("second"));
        let (third, third_calls) = CountingTokenExtractor::new(Some("third"));
        let extractors = NonEmpty::<Arc<dyn TokenExtractor>> {
            head: first,
            tail: vec![second, third],
        };

        assert_that!(extract_jwt(&request("/", None), &extractors, None))
            .is_matching(pattern!(Err(AuthError::MultipleCredentialSources)));
        assert_that!(third_calls.load(Ordering::SeqCst))
            .with_subject_name("third extractor calls")
            .is_equal_to(0);
    }

    #[test]
    fn extraction_logging_does_not_expose_custom_extractor_or_error_details_by_default() {
        let request = request("/", None);
        let extractors = NonEmpty::<Arc<dyn TokenExtractor>> {
            head: Arc::new(SecretLeakingTokenExtractor),
            tail: vec![Arc::new(QueryParamTokenExtractor::default())],
        };
        let logs = CapturedLogs::default();
        let extracted = {
            let _capture = logs.capture();
            extract_jwt(&request, &extractors, None)
        };

        assert_that!(extracted).is_matching(pattern!(Err(AuthError::TokenExtraction { .. })));
        assert_that!(logs.contents())
            .does_not_contain(DEBUG_SECRET)
            .does_not_contain(ERROR_SECRET);
    }

    #[test]
    fn enabled_extraction_error_logging_records_every_extractor_error_but_no_absent_source() {
        let request = request("/", Some("Bearer "));
        let extractors = NonEmpty::<Arc<dyn TokenExtractor>> {
            head: Arc::new(SecretLeakingTokenExtractor),
            tail: vec![
                Arc::new(AbsentTokenExtractor),
                Arc::new(AuthHeaderTokenExtractor::default()),
                Arc::new(QueryParamTokenExtractor::default()),
            ],
        };
        let logs = CapturedLogs::default();
        let extracted = {
            let _capture = logs.capture();
            extract_jwt(&request, &extractors, Some(tracing::Level::INFO))
        };

        assert_that!(extracted).is_matching(pattern!(Err(AuthError::MultipleCredentialSources)));
        assert_that!(logs.contents())
            .contains_occurrences("Token extractor failed.", 2)
            .contains(" INFO ")
            .contains("SecretLeakingTokenExtractor")
            .contains(DEBUG_SECRET)
            .contains(ERROR_SECRET)
            .contains("AuthHeaderTokenExtractor")
            .does_not_contain("AbsentTokenExtractor");
    }

    #[test]
    fn no_source_at_all_yields_ok_none() {
        assert_that!(extract_jwt(&request("/", None), &header_then_query(), None))
            .ok()
            .is_none();
    }
}
