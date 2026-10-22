//! Tower service produced by [`KeycloakAuthLayer`].

use std::{
    sync::Arc,
    task::{Context, Poll},
};

use axum::{body::Body, response::IntoResponse};
use futures::future::BoxFuture;
use http::Request;
use nonempty::NonEmpty;
use serde::de::DeserializeOwned;

use crate::{
    KeycloakAuthStatus, PassthroughMode,
    error::AuthError,
    extract::{self, TokenExtractionErrorPolicy, TokenExtractor},
    layer::KeycloakAuthLayer,
    logging::event_at_level,
    role::Role,
    validation::Validator,
};

fn log_authentication_error(level: tracing::Level, error: &AuthError) {
    match error {
        AuthError::MissingExpectedRole { role } => event_at_level!(
            level,
            error = %error,
            missing_role = %role,
            "Authentication failed"
        ),
        _ => event_at_level!(level, error = %error, "Authentication failed"),
    }
}

/// Tower service that extracts and validates a token before calling an inner service.
///
/// Applications normally construct this through [`tower::Layer::layer`] on a
/// [`KeycloakAuthLayer`].
#[derive(Clone)]
pub struct KeycloakAuthService<S, R, Extra>
where
    R: Role,
    Extra: DeserializeOwned + Clone,
{
    inner: S,
    validator: Arc<Validator<R, Extra>>,
    token_extractors: Arc<NonEmpty<Arc<dyn TokenExtractor>>>,
    token_extraction_error_policy: TokenExtractionErrorPolicy,
    passthrough_mode: PassthroughMode,
    authentication_error_log_level: Option<tracing::Level>,
    token_extraction_error_log_level: Option<tracing::Level>,
}

impl<S, R, Extra> KeycloakAuthService<S, R, Extra>
where
    R: Role,
    Extra: DeserializeOwned + Clone,
{
    /// Wraps `inner` using a snapshot of `layer`'s current configuration.
    pub fn new(inner: S, layer: &KeycloakAuthLayer<R, Extra>) -> Self {
        Self {
            inner,
            validator: Arc::new(layer.validator()),
            token_extractors: Arc::new(layer.token_extractors.clone()),
            token_extraction_error_policy: layer.token_extraction_error_policy,
            passthrough_mode: layer.passthrough_mode,
            authentication_error_log_level: layer.dangerously_log_authentication_errors,
            token_extraction_error_log_level: layer.dangerously_log_token_extraction_errors,
        }
    }
}

impl<S, R, Extra> tower::Service<Request<Body>> for KeycloakAuthService<S, R, Extra>
where
    S: tower::Service<Request<Body>, Response = axum::response::Response> + Clone + Send + 'static,
    S::Future: Send + 'static,
    R: Role + 'static,
    Extra: DeserializeOwned + Clone + Sync + Send + 'static,
{
    type Response = S::Response;
    type Error = S::Error;
    type Future = BoxFuture<'static, Result<Self::Response, Self::Error>>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        // Readiness deliberately does not wait for OIDC discovery: requests that need decoding
        // keys wait inside `call`, for at most the refresh policy's `max_refresh_wait`, for the
        // initial or a shared on-demand discovery (see `Discovery::refresh_if_needed`). Requests
        // that are rejected without keys (for example on a missing token) do not need discovery.
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, mut request: Request<Body>) -> Self::Future {
        tracing::debug!("Validating request...");

        let clone = self.inner.clone();

        // Take the service that was ready!
        let mut inner = std::mem::replace(&mut self.inner, clone);

        let validator = self.validator.clone();
        let token_extractors = self.token_extractors.clone();
        let token_extraction_error_policy = self.token_extraction_error_policy;
        let passthrough_mode = self.passthrough_mode;
        let authentication_error_log_level = self.authentication_error_log_level;
        let token_extraction_error_log_level = self.token_extraction_error_log_level;

        Box::pin(async move {
            // Process the request.
            let result = match extract::extract_jwt(
                &request,
                &token_extractors,
                token_extraction_error_policy,
                token_extraction_error_log_level,
            ) {
                Ok(Some(token)) => validator.validate(&token).await,
                Ok(None) => Err(AuthError::MissingToken),
                Err(error) => Err(error),
            };

            match result {
                Ok(validated) => {
                    if let Some(raw_claims) = validated.raw_claims {
                        request.extensions_mut().insert(raw_claims);
                    }
                    match passthrough_mode {
                        PassthroughMode::Block => {
                            request.extensions_mut().insert(validated.token);
                        }
                        PassthroughMode::Pass => {
                            request
                                .extensions_mut()
                                .insert(KeycloakAuthStatus::<R, Extra>::Success(validated.token));
                        }
                    }
                    inner.call(request).await
                }
                Err(err) => {
                    if let Some(level) = authentication_error_log_level {
                        log_authentication_error(level, &err);
                    }

                    match passthrough_mode {
                        PassthroughMode::Block => Ok(err.into_response()),
                        PassthroughMode::Pass => {
                            request
                                .extensions_mut()
                                .insert(KeycloakAuthStatus::<R, Extra>::Failure(Arc::new(err)));
                            inner.call(request).await
                        }
                    }
                }
            }
        })
    }
}

#[cfg(test)]
mod tests {
    use std::{
        convert::Infallible,
        sync::{Arc, Mutex},
    };

    use assertr::prelude::*;
    use axum::{
        body::Body,
        http::{Request, StatusCode, header::WWW_AUTHENTICATE},
        response::{IntoResponse, Response},
    };
    use jsonwebtoken::Algorithm;
    use serde_json::{Value, json};
    use tower::Service;

    use crate::{
        KeycloakAuthStatus, PassthroughMode,
        test_support::{
            CapturedLogs, RSA_KEY_A, TEST_KID, anonymous_request, assert_logged_iff,
            bearer_request, keycloak_claims, offline_layer, response_text, signed_token,
            validation_time,
        },
        token::{KeycloakToken, RawClaims},
    };

    use super::KeycloakAuthService;

    /// An inner service accepting every request that reaches it.
    async fn no_content(_request: Request<Body>) -> Result<Response, Infallible> {
        Ok(StatusCode::NO_CONTENT.into_response())
    }

    #[tokio::test]
    async fn authentication_error_logging_is_opt_in_and_uses_the_configured_level() {
        for (authentication_error_log_level, passthrough_mode) in [
            (None, PassthroughMode::Block),
            (Some(tracing::Level::WARN), PassthroughMode::Block),
            (Some(tracing::Level::INFO), PassthroughMode::Block),
            (Some(tracing::Level::WARN), PassthroughMode::Pass),
        ] {
            let mut layer = offline_layer();
            layer.passthrough_mode = passthrough_mode;
            layer.dangerously_log_authentication_errors = authentication_error_log_level;
            let mut service = KeycloakAuthService::new(tower::service_fn(no_content), &layer);

            let now = validation_time();
            let mut claims = keycloak_claims(now);
            claims.insert(String::from("exp"), json!(now.unix_timestamp() - 60));
            claims.insert(String::from("iat"), json!({ "malformed": true }));
            let token = RSA_KEY_A
                .sign(&claims, Algorithm::RS256, Some(TEST_KID))
                .expect("the malformed-claims test token must sign");

            let logs = CapturedLogs::default();
            let response = {
                let _capture = logs.capture();
                service
                    .call(bearer_request(&token))
                    .await
                    .expect("authentication middleware must not fail as a service")
            };

            match passthrough_mode {
                PassthroughMode::Block => {
                    assert_that!(response.status()).is_equal_to(StatusCode::UNAUTHORIZED);
                    assert_that!(response.headers().get(WWW_AUTHENTICATE).cloned())
                        .with_subject_name("the Bearer challenge of an invalid token response")
                        .some()
                        .ascii()
                        .is_equal_to("Bearer error=\"invalid_token\"");
                    assert_that!(response_text(response).await)
                        .is_equal_to(r#"{"error":"invalid_token"}"#);
                }
                PassthroughMode::Pass => {
                    assert_that!(response.status()).is_equal_to(StatusCode::NO_CONTENT);
                }
            }

            let contents = logs.contents();
            let enabled = authentication_error_log_level.is_some();
            assert_logged_iff(
                &contents,
                "Authentication failed",
                enabled,
                format!(
                    "authentication error logging enabled = {enabled}, mode = {passthrough_mode:?}"
                ),
            );
            assert_logged_iff(
                &contents,
                "invalid type: map, expected i64",
                enabled,
                format!("detailed error logging enabled = {enabled}"),
            );
            if let Some(level) = authentication_error_log_level {
                assert_that!(logs.event_containing("Authentication failed").level())
                    .with_subject_name("configured authentication error log level")
                    .is_equal_to(level);
            }
            assert_that!(contents)
                .with_subject_name("the raw token is never logged")
                .does_not_contain(&token);
            assert_that!(contents)
                .with_subject_name("unrelated claims are never logged")
                .does_not_contain("test@example.com");
        }
    }

    /// The authentication extensions an inner service observed on its request.
    #[derive(Debug, PartialEq)]
    struct ObservedExtensions {
        raw_claims_subject: Option<String>,
        token_subject: Option<String>,
        status: Option<String>,
    }

    impl ObservedExtensions {
        fn of(request: &Request<Body>) -> Self {
            let extensions = request.extensions();
            Self {
                raw_claims_subject: extensions
                    .get::<RawClaims>()
                    .and_then(|claims| claims["sub"].as_str().map(String::from)),
                token_subject: extensions
                    .get::<KeycloakToken<String, Value>>()
                    .map(|token| token.subject.clone()),
                status: extensions
                    .get::<KeycloakAuthStatus<String, Value>>()
                    .map(|status| match status {
                        KeycloakAuthStatus::Success(token) => format!("Success({})", token.subject),
                        KeycloakAuthStatus::Failure(error) => format!("Failure({error:?})"),
                    }),
            }
        }
    }

    #[tokio::test]
    async fn extensions_and_inner_service_calls_follow_the_passthrough_mode() {
        for (passthrough_mode, authenticated, expected_status, expected_observation) in [
            (
                PassthroughMode::Block,
                true,
                StatusCode::NO_CONTENT,
                Some(ObservedExtensions {
                    raw_claims_subject: Some(String::from("test-subject")),
                    token_subject: Some(String::from("test-subject")),
                    status: None,
                }),
            ),
            (
                PassthroughMode::Block,
                false,
                StatusCode::UNAUTHORIZED,
                None,
            ),
            (
                PassthroughMode::Pass,
                true,
                StatusCode::NO_CONTENT,
                Some(ObservedExtensions {
                    raw_claims_subject: Some(String::from("test-subject")),
                    token_subject: None,
                    status: Some(String::from("Success(test-subject)")),
                }),
            ),
            (
                PassthroughMode::Pass,
                false,
                StatusCode::NO_CONTENT,
                Some(ObservedExtensions {
                    raw_claims_subject: None,
                    token_subject: None,
                    status: Some(String::from("Failure(MissingToken)")),
                }),
            ),
        ] {
            let case_name = format!("{passthrough_mode:?} mode, authenticated = {authenticated}");
            let mut layer = offline_layer();
            layer.passthrough_mode = passthrough_mode;
            layer.persist_raw_claims = true;
            let observations = Arc::new(Mutex::new(Vec::new()));
            let inner_observations = Arc::clone(&observations);
            let inner = tower::service_fn(move |request: Request<Body>| {
                inner_observations
                    .lock()
                    .expect("the observation lock must not be poisoned")
                    .push(ObservedExtensions::of(&request));
                no_content(request)
            });
            let mut service = KeycloakAuthService::new(inner, &layer);

            let request = if authenticated {
                bearer_request(&signed_token(&RSA_KEY_A, Some(TEST_KID)))
            } else {
                anonymous_request()
            };
            let response = service
                .call(request)
                .await
                .expect("authentication middleware must not fail as a service");

            assert_that!(response.status())
                .with_subject_name(format!("{case_name}: response status"))
                .is_equal_to(expected_status);
            let observations = std::mem::take(
                &mut *observations
                    .lock()
                    .expect("the observation lock must not be poisoned"),
            );
            assert_that!(observations)
                .with_subject_name(format!("{case_name}: inner-service calls"))
                .is_equal_to(Vec::from_iter(expected_observation));
        }
    }

    #[tokio::test]
    async fn authentication_error_logging_hints_at_the_missing_role_only_when_enabled() {
        const MISSING_ROLE: &str = "sensitive-administrator-role";

        for authentication_error_log_level in [None, Some(tracing::Level::DEBUG)] {
            let mut layer = offline_layer();
            layer.required_roles = vec![String::from(MISSING_ROLE)];
            layer.dangerously_log_authentication_errors = authentication_error_log_level;
            let mut service = KeycloakAuthService::new(tower::service_fn(no_content), &layer);
            let token = signed_token(&RSA_KEY_A, Some(TEST_KID));

            let logs = CapturedLogs::default();
            let response = {
                let _capture = logs.capture();
                service
                    .call(bearer_request(&token))
                    .await
                    .expect("authentication middleware must not fail as a service")
            };

            assert_that!(response.status()).is_equal_to(StatusCode::FORBIDDEN);
            assert_that!(response_text(response).await)
                .is_equal_to(r#"{"error":"Missing expected role"}"#)
                .does_not_contain(MISSING_ROLE);

            let contents = logs.contents();
            let enabled = authentication_error_log_level.is_some();
            assert_logged_iff(
                &contents,
                "Authentication failed",
                enabled,
                "missing-role authentication error event",
            );
            assert_logged_iff(
                &contents,
                &format!("missing_role={MISSING_ROLE}"),
                enabled,
                "structured missing-role hint",
            );
            if let Some(level) = authentication_error_log_level {
                let event = logs.event_containing("Authentication failed");
                assert_that!(event.level())
                    .with_subject_name("configured authentication error log level")
                    .is_equal_to(level);
                assert_that!(event.field("missing_role"))
                    .with_subject_name("structured missing-role field")
                    .is_equal_to(Some(MISSING_ROLE));
            }
            assert_that!(contents)
                .with_subject_name("the raw token is never logged")
                .does_not_contain(&token);
        }
    }

    #[tokio::test]
    async fn token_extraction_and_final_authentication_error_logging_are_independent() {
        for (token_extraction_error_log_level, authentication_error_log_level) in [
            (None, None),
            (Some(tracing::Level::INFO), None),
            (None, Some(tracing::Level::WARN)),
            (Some(tracing::Level::INFO), Some(tracing::Level::WARN)),
        ] {
            let mut layer = offline_layer();
            layer.dangerously_log_token_extraction_errors = token_extraction_error_log_level;
            layer.dangerously_log_authentication_errors = authentication_error_log_level;
            let mut service = KeycloakAuthService::new(tower::service_fn(no_content), &layer);

            let logs = CapturedLogs::default();
            let response = {
                let _capture = logs.capture();
                service
                    .call(anonymous_request())
                    .await
                    .expect("authentication middleware must not fail as a service")
            };

            assert_that!(response.status()).is_equal_to(StatusCode::UNAUTHORIZED);
            let contents = logs.contents();
            let extraction_logging_enabled = token_extraction_error_log_level.is_some();
            let authentication_logging_enabled = authentication_error_log_level.is_some();
            assert_logged_iff(
                &contents,
                "Token extractor failed.",
                extraction_logging_enabled,
                "per-extractor error event",
            );
            assert_logged_iff(
                &contents,
                "The 'Authorization' header was not present on a request.",
                extraction_logging_enabled,
                "per-extractor error details",
            );
            assert_logged_iff(
                &contents,
                "Authentication failed",
                authentication_logging_enabled,
                "final authentication error event",
            );
            assert_logged_iff(
                &contents,
                "No JWT could be extracted from the request.",
                authentication_logging_enabled,
                "final authentication error details",
            );

            if let Some(level) = token_extraction_error_log_level {
                assert_that!(logs.event_containing("Token extractor failed.").level())
                    .with_subject_name("configured token-extraction error log level")
                    .is_equal_to(level);
            }
            if let Some(level) = authentication_error_log_level {
                assert_that!(logs.event_containing("Authentication failed").level())
                    .with_subject_name("configured authentication error log level")
                    .is_equal_to(level);
            }
        }
    }
}
