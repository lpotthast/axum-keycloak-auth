//! Extract compact JWTs from incoming requests.
//!
//! [`TokenExtractor`] defines *where* a token is looked for. This crate ships two implementations:
//! [`AuthHeaderTokenExtractor`] reads the `Authorization: Bearer <token>` header, and
//! [`QueryParamTokenExtractor`] reads a configurable query parameter.
//!
//! A layer may use several extractors. They run in order until one returns a token. An absent
//! credential source always continues to the next extractor. [`TokenExtractionErrorPolicy`]
//! controls whether a present but unusable source continues or rejects authentication.
//!
//! The built-in extractors treat a blank token value, meaning one that is empty or consists only of
//! whitespace, as an unusable source rather than as an extracted token. `Authorization: Bearer `
//! and `?token=` are therefore errors, and extraction still continues past them under
//! [`TokenExtractionErrorPolicy::Fallback`]. Custom extractors should likewise return an error
//! instead of a blank token, because any returned token ends extraction.

mod auth_header;
mod policy;
mod query_param;

use std::{borrow::Cow, sync::Arc};

use axum::extract::Request;
use nonempty::NonEmpty;

use crate::{error::AuthError, logging::event_at_level};

pub use auth_header::{AuthHeaderExtractError, AuthHeaderTokenExtractor};
pub use policy::TokenExtractionErrorPolicy;
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
    /// Returns `Ok(Some(token))` if the credential source carries a valid token, and `Ok(None)` if
    /// the token is absent, which lets extraction continue with the next extractor.
    ///
    /// # Errors
    ///
    /// Returns an error if the credential source is present but unusable, for example if malformed
    /// or blank. Any specific error type must be converted into [`BoxError`]. Using `?` works.
    /// Errors are handled according to [`TokenExtractionErrorPolicy`]. A rejecting policy reports
    /// the first error as the source of [`AuthError::TokenExtraction`], where callers can downcast it. The built-in
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
/// Extractors are tried in their configured order. An absent source (`Ok(None)`) lets extraction
/// continue with the next extractor. The first token is returned. `Ok(None)` means no extractor
/// found its source.
///
/// When `token_extraction_error_log_level` is set, every extractor error is logged at that level,
/// including the extractor's [`Debug`](std::fmt::Debug) output and the detailed error. `None`
/// disables these events. An error means that the current source was present but malformed. The
/// default [`TokenExtractionErrorPolicy::Fallback`] policy tries the next extractor.
/// [`TokenExtractionErrorPolicy::Reject`] propagates the first error instead, preventing a request
/// containing, for example, a malformed `Authorization` header and a valid query token from
/// authenticating with the query token.
pub(crate) fn extract_jwt<'a>(
    request: &'a Request<axum::body::Body>,
    extractors: &NonEmpty<Arc<dyn TokenExtractor>>,
    error_policy: TokenExtractionErrorPolicy,
    token_extraction_error_log_level: Option<tracing::Level>,
) -> Result<Option<ExtractedToken<'a>>, AuthError> {
    for extractor in extractors {
        match extractor.extract(request) {
            Ok(Some(jwt)) => return Ok(Some(jwt)),
            Ok(None) => {}
            Err(error) => {
                if let Some(level) = token_extraction_error_log_level {
                    log_extraction_error(level, extractor.as_ref(), &error);
                }

                // Matched exhaustively on purpose: a future policy variant must be decided here
                // rather than silently defaulting to one of the existing behaviors.
                match error_policy {
                    TokenExtractionErrorPolicy::Fallback => {}
                    TokenExtractionErrorPolicy::Reject => {
                        return Err(AuthError::TokenExtraction {
                            source: Arc::from(error),
                        });
                    }
                }
            }
        }
    }
    Ok(None)
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
        QueryParamTokenExtractor, TokenExtractionErrorPolicy, TokenExtractor, extract_jwt,
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

    /// An extractor that always finds `token`, counting how often it was asked.
    #[derive(Debug)]
    struct CountingTokenExtractor {
        token: &'static str,
        calls: Arc<AtomicUsize>,
    }

    impl TokenExtractor for CountingTokenExtractor {
        fn extract<'a>(
            &self,
            _request: &'a Request,
        ) -> Result<Option<ExtractedToken<'a>>, BoxError> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            Ok(Some(ExtractedToken::Borrowed(self.token)))
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
    fn the_first_extracted_token_wins_and_later_extractors_are_not_asked() {
        let first_calls = Arc::new(AtomicUsize::new(0));
        let later_calls = Arc::new(AtomicUsize::new(0));
        let extractors = NonEmpty::<Arc<dyn TokenExtractor>> {
            head: Arc::new(CountingTokenExtractor {
                token: "first",
                calls: first_calls.clone(),
            }),
            tail: vec![Arc::new(CountingTokenExtractor {
                token: "later",
                calls: later_calls.clone(),
            })],
        };

        assert_that!(extract_jwt(
            &request("/", None),
            &extractors,
            TokenExtractionErrorPolicy::Fallback,
            None,
        ))
        .ok()
        .some()
        .is_equal_to("first");
        assert_that!(first_calls.load(Ordering::SeqCst))
            .with_subject_name("first extractor calls")
            .is_equal_to(1);
        assert_that!(later_calls.load(Ordering::SeqCst))
            .with_subject_name("later extractor calls")
            .is_equal_to(0);
    }

    #[test]
    fn extraction_continues_after_an_absent_credential_source_under_both_policies() {
        let request = request("/?token=abc.def.ghi", None);
        let extractors = NonEmpty::<Arc<dyn TokenExtractor>> {
            head: Arc::new(AbsentTokenExtractor),
            tail: vec![
                Arc::new(AuthHeaderTokenExtractor::default()),
                Arc::new(QueryParamTokenExtractor::default()),
            ],
        };

        for policy in [
            TokenExtractionErrorPolicy::Fallback,
            TokenExtractionErrorPolicy::Reject,
        ] {
            assert_that!(extract_jwt(&request, &extractors, policy, None))
                .ok()
                .some()
                .is_equal_to("abc.def.ghi");
        }
    }

    #[test]
    fn fallback_policy_continues_after_a_malformed_credential_source() {
        let request = request("/?token=abc.def.ghi", Some("Basic credentials"));

        assert_that!(extract_jwt(
            &request,
            &header_then_query(),
            TokenExtractionErrorPolicy::Fallback,
            None,
        ))
        .ok()
        .some()
        .is_equal_to("abc.def.ghi");
    }

    #[test]
    fn fallback_logging_does_not_expose_custom_extractor_or_error_details_by_default() {
        let request = request("/?token=abc.def.ghi", None);
        let extractors = NonEmpty::<Arc<dyn TokenExtractor>> {
            head: Arc::new(SecretLeakingTokenExtractor),
            tail: vec![Arc::new(QueryParamTokenExtractor::default())],
        };
        let logs = CapturedLogs::default();
        let extracted = {
            let _capture = logs.capture();
            extract_jwt(
                &request,
                &extractors,
                TokenExtractionErrorPolicy::Fallback,
                None,
            )
        };

        assert_that!(extracted)
            .ok()
            .some()
            .is_equal_to("abc.def.ghi");
        assert_that!(logs.contents())
            .does_not_contain(DEBUG_SECRET)
            .does_not_contain(ERROR_SECRET);
    }

    #[test]
    fn enabled_extraction_error_logging_records_every_extractor_error_but_no_absent_source() {
        let request = request("/?token=abc.def.ghi", Some("Basic credentials"));
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
            extract_jwt(
                &request,
                &extractors,
                TokenExtractionErrorPolicy::Fallback,
                Some(tracing::Level::INFO),
            )
        };

        assert_that!(extracted)
            .ok()
            .some()
            .is_equal_to("abc.def.ghi");
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
    fn an_empty_token_value_does_not_shadow_a_lower_priority_source() {
        let request = request("/?token=abc.def.ghi", Some("Bearer "));

        assert_that!(extract_jwt(
            &request,
            &header_then_query(),
            TokenExtractionErrorPolicy::Fallback,
            None,
        ))
        .ok()
        .some()
        .is_equal_to("abc.def.ghi");
    }

    #[test]
    fn reject_policy_stops_at_a_malformed_credential_source_and_keeps_its_error() {
        let request = request("/?token=abc.def.ghi", Some("Basic credentials"));

        let error = extract_jwt(
            &request,
            &header_then_query(),
            TokenExtractionErrorPolicy::Reject,
            None,
        )
        .expect_err("the malformed header must reject extraction");

        let AuthError::TokenExtraction { source } = error else {
            panic!("expected a token extraction error, got {error:?}");
        };
        assert!(
            matches!(
                source.downcast_ref::<AuthHeaderExtractError>(),
                Some(AuthHeaderExtractError::MissingBearerScheme)
            ),
            "expected the header extractor's error, got {source:?}"
        );
    }

    #[test]
    fn no_source_at_all_yields_ok_none() {
        let request = request("/", None);

        for policy in [
            TokenExtractionErrorPolicy::Fallback,
            TokenExtractionErrorPolicy::Reject,
        ] {
            assert_that!(extract_jwt(&request, &header_then_query(), policy, None,))
                .ok()
                .is_none();
        }
    }
}
