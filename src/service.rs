//! Tower service produced by [`crate::layer::KeycloakAuthLayer`].

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
    role::Role,
    validation::Validator,
};

fn log_authentication_error(level: tracing::Level, error: &AuthError) {
    macro_rules! log_at_configured_level {
        ($level:ident) => {
            match error {
                AuthError::MissingExpectedRole { role } => {
                    tracing::event!(
                        tracing::Level::$level,
                        error = %error,
                        missing_role = %role,
                        "Authentication failed"
                    );
                }
                _ => tracing::event!(
                    tracing::Level::$level,
                    error = %error,
                    "Authentication failed"
                ),
            }
        };
    }

    match level {
        tracing::Level::ERROR => log_at_configured_level!(ERROR),
        tracing::Level::WARN => log_at_configured_level!(WARN),
        tracing::Level::INFO => log_at_configured_level!(INFO),
        tracing::Level::DEBUG => log_at_configured_level!(DEBUG),
        tracing::Level::TRACE => log_at_configured_level!(TRACE),
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
    use std::{convert::Infallible, sync::Arc};

    use assertr::prelude::*;
    use axum::{
        body::{Body, to_bytes},
        http::{
            Request, StatusCode,
            header::{AUTHORIZATION, WWW_AUTHENTICATE},
        },
        response::IntoResponse,
    };
    use jsonwebtoken::Algorithm;
    use serde_json::{Value, json};
    use tower::Service;

    use crate::{
        KeycloakAuthStatus, PassthroughMode,
        layer::KeycloakAuthLayer,
        test_support::{
            CapturedLogs, ManualClock, RSA_KEY_A, assert_logged_iff, keycloak_claims,
            offline_instance, validation_time,
        },
        token::{KeycloakToken, RawClaims},
    };

    use super::KeycloakAuthService;

    #[tokio::test]
    async fn authentication_error_logging_is_opt_in_and_uses_the_configured_level() {
        for (authentication_error_log_level, passthrough_mode) in [
            (None, PassthroughMode::Block),
            (Some(tracing::Level::WARN), PassthroughMode::Block),
            (Some(tracing::Level::INFO), PassthroughMode::Block),
            (Some(tracing::Level::WARN), PassthroughMode::Pass),
        ] {
            let now = validation_time();
            let mut layer = KeycloakAuthLayer::<String, Value>::builder()
                .instance(offline_instance(
                    url::Url::parse("https://issuer.example/")
                        .expect("the test issuer URL must parse"),
                    String::from("test-realm"),
                ))
                .passthrough_mode(passthrough_mode)
                .expected_audiences(vec![String::from("account")])
                .build()
                .with_clock(Arc::new(ManualClock::new(now)));
            layer.dangerously_log_authentication_errors = authentication_error_log_level;
            let inner = tower::service_fn(|_request: Request<Body>| async {
                Ok::<_, Infallible>(StatusCode::NO_CONTENT.into_response())
            });
            let mut service = KeycloakAuthService::new(inner, &layer);

            let mut claims = keycloak_claims(now);
            claims.insert(String::from("exp"), json!(now.unix_timestamp() - 60));
            claims.insert(String::from("iat"), json!({ "malformed": true }));
            let token = RSA_KEY_A
                .sign(&claims, Algorithm::RS256, Some("key-a"))
                .expect("the malformed-claims test token must sign");
            let request = Request::builder()
                .header(AUTHORIZATION, format!("Bearer {token}"))
                .body(Body::empty())
                .expect("the test request must build");

            let logs = CapturedLogs::default();
            let subscriber = tracing_subscriber::fmt()
                .without_time()
                .with_ansi(false)
                .with_max_level(tracing::Level::TRACE)
                .with_writer(logs.clone())
                .finish();
            let response = {
                let _default = tracing::subscriber::set_default(subscriber);
                service
                    .call(request)
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
                    let body = to_bytes(response.into_body(), 1024)
                        .await
                        .expect("the JSON response body must be readable");
                    let body =
                        std::str::from_utf8(&body).expect("the JSON response body must be UTF-8");
                    assert_that!(body).is_equal_to(r#"{"error":"invalid_token"}"#);
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
                assert_that!(contents)
                    .with_subject_name("configured authentication error log level")
                    .contains(level.as_str());
            }
            assert_that!(contents)
                .with_subject_name("the raw token is never logged")
                .does_not_contain(&token);
            assert_that!(contents)
                .with_subject_name("unrelated claims are never logged")
                .does_not_contain("test@example.com");
        }
    }

    #[tokio::test]
    async fn successful_authentication_inserts_the_mode_specific_extensions() {
        for passthrough_mode in [PassthroughMode::Block, PassthroughMode::Pass] {
            let now = validation_time();
            let layer = KeycloakAuthLayer::<String, Value>::builder()
                .instance(offline_instance(
                    url::Url::parse("https://issuer.example/")
                        .expect("the test issuer URL must parse"),
                    String::from("test-realm"),
                ))
                .passthrough_mode(passthrough_mode)
                .expected_audiences(vec![String::from("account")])
                .persist_raw_claims(true)
                .build()
                .with_clock(Arc::new(ManualClock::new(now)));
            let inner = tower::service_fn(move |request: Request<Body>| async move {
                let extensions = request.extensions();
                let token_present = match passthrough_mode {
                    PassthroughMode::Block => {
                        extensions.get::<KeycloakToken<String, Value>>().is_some()
                    }
                    PassthroughMode::Pass => matches!(
                        extensions.get::<KeycloakAuthStatus<String, Value>>(),
                        Some(KeycloakAuthStatus::Success(_))
                    ),
                };
                let status = if token_present && extensions.get::<RawClaims>().is_some() {
                    StatusCode::NO_CONTENT
                } else {
                    StatusCode::INTERNAL_SERVER_ERROR
                };
                Ok::<_, Infallible>(status.into_response())
            });
            let mut service = KeycloakAuthService::new(inner, &layer);
            let token = RSA_KEY_A
                .sign(&keycloak_claims(now), Algorithm::RS256, Some("key-a"))
                .expect("the valid test token must sign");
            let request = Request::builder()
                .header(AUTHORIZATION, format!("Bearer {token}"))
                .body(Body::empty())
                .expect("the test request must build");

            let response = service
                .call(request)
                .await
                .expect("authentication middleware must not fail as a service");

            assert_that!(response.status())
                .with_subject_name(format!("response in {passthrough_mode:?} mode"))
                .is_equal_to(StatusCode::NO_CONTENT);
        }
    }

    #[tokio::test]
    async fn authentication_error_logging_hints_at_the_missing_role_only_when_enabled() {
        const MISSING_ROLE: &str = "sensitive-administrator-role";

        for authentication_error_log_level in [None, Some(tracing::Level::DEBUG)] {
            let now = validation_time();
            let mut layer = KeycloakAuthLayer::<String, Value>::builder()
                .instance(offline_instance(
                    url::Url::parse("https://issuer.example/")
                        .expect("the test issuer URL must parse"),
                    String::from("test-realm"),
                ))
                .expected_audiences(vec![String::from("account")])
                .required_roles(vec![String::from(MISSING_ROLE)])
                .build()
                .with_clock(Arc::new(ManualClock::new(now)));
            layer.dangerously_log_authentication_errors = authentication_error_log_level;
            let inner = tower::service_fn(|_request: Request<Body>| async {
                Ok::<_, Infallible>(StatusCode::NO_CONTENT.into_response())
            });
            let mut service = KeycloakAuthService::new(inner, &layer);
            let token = RSA_KEY_A
                .sign(&keycloak_claims(now), Algorithm::RS256, Some("key-a"))
                .expect("the missing-role test token must sign");
            let request = Request::builder()
                .header(AUTHORIZATION, format!("Bearer {token}"))
                .body(Body::empty())
                .expect("the test request must build");
            let logs = CapturedLogs::default();
            let subscriber = tracing_subscriber::fmt()
                .without_time()
                .with_ansi(false)
                .with_max_level(tracing::Level::TRACE)
                .with_writer(logs.clone())
                .finish();

            let response = {
                let _default = tracing::subscriber::set_default(subscriber);
                service
                    .call(request)
                    .await
                    .expect("authentication middleware must not fail as a service")
            };

            assert_that!(response.status()).is_equal_to(StatusCode::FORBIDDEN);
            let body = to_bytes(response.into_body(), 1024)
                .await
                .expect("the JSON response body must be readable");
            let body = std::str::from_utf8(&body).expect("the JSON response body must be UTF-8");
            assert_that!(body)
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
            let mut layer = KeycloakAuthLayer::<String, Value>::builder()
                .instance(offline_instance(
                    url::Url::parse("https://issuer.example/")
                        .expect("the test issuer URL must parse"),
                    String::from("test-realm"),
                ))
                .expected_audiences(vec![String::from("account")])
                .build();
            layer.dangerously_log_token_extraction_errors = token_extraction_error_log_level;
            layer.dangerously_log_authentication_errors = authentication_error_log_level;
            let inner = tower::service_fn(|_request: Request<Body>| async {
                Ok::<_, Infallible>(StatusCode::NO_CONTENT.into_response())
            });
            let mut service = KeycloakAuthService::new(inner, &layer);
            let request = Request::builder()
                .body(Body::empty())
                .expect("the test request must build");
            let logs = CapturedLogs::default();
            let subscriber = tracing_subscriber::fmt()
                .without_time()
                .with_ansi(false)
                .with_max_level(tracing::Level::TRACE)
                .with_writer(logs.clone())
                .finish();

            let response = {
                let _default = tracing::subscriber::set_default(subscriber);
                service
                    .call(request)
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

            if extraction_logging_enabled {
                let event = contents
                    .lines()
                    .find(|line| line.contains("Token extractor failed."))
                    .expect("enabled extraction-error logging must emit its event");
                assert_that!(event)
                    .with_subject_name("configured token-extraction error log level")
                    .contains(tracing::Level::INFO.as_str());
            }
            if authentication_logging_enabled {
                let event = contents
                    .lines()
                    .find(|line| line.contains("Authentication failed"))
                    .expect("enabled authentication-error logging must emit its event");
                assert_that!(event)
                    .with_subject_name("configured authentication error log level")
                    .contains(tracing::Level::WARN.as_str());
            }
        }
    }
}
